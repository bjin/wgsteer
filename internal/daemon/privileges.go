package daemon

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var capNames = [...]string{
	"chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid",
	"setpcap", "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw",
	"ipc_lock", "ipc_owner", "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
	"sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time", "sys_tty_config", "mknod",
	"lease", "audit_write", "audit_control", "setfcap", "mac_override", "mac_admin", "syslog",
	"wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore",
}

// effectiveCaps returns the effective capability set of the calling thread.
// Go starts every thread with the process's capabilities, and the daemon
// never changes them.
func effectiveCaps() (uint64, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return 0, fmt.Errorf("capget: %w", err)
	}
	return uint64(data[1].Effective)<<32 | uint64(data[0].Effective), nil
}

// lastCap is the highest capability the kernel knows, or -1 if unknown.
func lastCap() int {
	b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return -1
	}
	return n
}

// formatCaps renders a capability set: "all" when it holds every capability
// up to last (as root usually does), "none", or a comma list.
func formatCaps(set uint64, last int) string {
	if last >= 0 && last < 64 {
		if all := uint64(1)<<(last+1) - 1; set&all == all {
			return "all"
		}
	}
	var names []string
	for bit := range 64 {
		if set&(1<<bit) == 0 {
			continue
		}
		if bit < len(capNames) {
			names = append(names, "cap_"+capNames[bit])
		} else {
			names = append(names, "cap_"+strconv.Itoa(bit))
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}

// checkCaps fails unless CAP_NET_ADMIN is effective. It is the only
// capability the daemon needs (docs/design.md, Privileges): WireGuard
// genetlink (reads too), nftables, and SO_MARK on the probe's sockets.
func checkCaps(set uint64) error {
	if set&(1<<unix.CAP_NET_ADMIN) != 0 {
		return nil
	}
	return errors.New("CAP_NET_ADMIN is not in the effective capability set; it is needed for " +
		"WireGuard netlink (also in --dry-run), nftables and the probe's fwmark. Run as root, or " +
		"grant only CAP_NET_ADMIN to the service user (systemd AmbientCapabilities=CAP_NET_ADMIN; " +
		"OpenWrt procd capabilities via ujail, or setcap cap_net_admin=ep on the binary)")
}

// reportPrivileges logs who the daemon runs as and fails fast without
// CAP_NET_ADMIN, instead of a bare "operation not permitted" later.
func (d *daemon) reportPrivileges() error {
	set, err := effectiveCaps()
	if err != nil {
		return d.fail("privileges", err)
	}
	d.log.Info("privileges", "uid", os.Getuid(), "euid", os.Geteuid(), "gid", os.Getgid(),
		"capabilities", formatCaps(set, lastCap()))
	if err := checkCaps(set); err != nil {
		return d.fail("privileges", err)
	}
	return nil
}

// privilegeHint explains permission errors that remain with CAP_NET_ADMIN
// effective.
func privilegeHint(err error) error {
	switch {
	case errors.Is(err, syscall.EPERM):
		return fmt.Errorf("%w (CAP_NET_ADMIN is effective but not honoured: it must be held in the "+
			"user namespace that owns the device's network namespace)", err)
	case errors.Is(err, syscall.EACCES):
		return fmt.Errorf("%w (a userspace device's UAPI socket is accessible only to the uid that "+
			"runs wireguard-go; run wgsteer as that user)", err)
	}
	return err
}
