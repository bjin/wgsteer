package daemon

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestFormatCaps(t *testing.T) {
	const last = 40 // cap_checkpoint_restore
	for _, c := range []struct {
		set  uint64
		want string
	}{
		{1<<(last+1) - 1, "all"},
		{1<<last - 1, "cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill," +
			"cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast," +
			"cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot," +
			"cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time," +
			"cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap," +
			"cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read," +
			"cap_perfmon,cap_bpf"}, // one short of all
		{1 << unix.CAP_NET_ADMIN, "cap_net_admin"},
		{1<<unix.CAP_NET_ADMIN | 1<<unix.CAP_PERFMON | 1<<45, "cap_net_admin,cap_perfmon,cap_45"},
		{0, "none"},
	} {
		if got := formatCaps(c.set, last); got != c.want {
			t.Errorf("formatCaps(%#x) = %q, want %q", c.set, got, c.want)
		}
	}
	if got := formatCaps(1<<unix.CAP_NET_ADMIN, -1); got != "cap_net_admin" {
		t.Errorf("unknown cap_last_cap: %q", got)
	}
}

func TestCheckCaps(t *testing.T) {
	if err := checkCaps(1 << unix.CAP_NET_ADMIN); err != nil {
		t.Errorf("CAP_NET_ADMIN only: %v", err)
	}
	if err := checkCaps(1<<unix.CAP_NET_RAW | 1<<unix.CAP_DAC_OVERRIDE | 1<<unix.CAP_SYS_ADMIN); err == nil {
		t.Error("set without CAP_NET_ADMIN accepted")
	}
}
