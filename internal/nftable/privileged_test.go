package nftable

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Privileged tests need CAP_NET_ADMIN in a disposable network namespace.
// They refuse to run in the initial user namespace so they can never touch
// a host ruleset; `make integration` runs them under `unshare -rn`.
func requirePrivileged(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("privileged test: needs CAP_NET_ADMIN in a user+network namespace; run under `unshare -rn` (make integration)")
	}
	b, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		t.Skipf("privileged test: cannot read uid_map: %v", err)
	}
	if f := strings.Fields(string(b)); len(f) == 3 && f[0] == "0" && f[1] == "0" && f[2] == "4294967295" {
		t.Skip("privileged test: refusing to run in the initial user namespace; run under `unshare -rn` (make integration)")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("privileged test: nft binary not found")
	}
}

const helperEnv = "WGSTEER_NFTABLE_HELPER_TABLE"

func openT(t *testing.T, name string) *Manager {
	t.Helper()
	m, err := Open(name)
	if err != nil {
		t.Fatalf("Open(%q): %v", name, err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func nft(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("nft %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func tableExists(t *testing.T, name string) bool {
	t.Helper()
	c, err := nftables.New() // transient: one socket per call
	if err != nil {
		t.Fatal(err)
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	for _, tb := range tables {
		if tb.Name == name {
			return true
		}
	}
	return false
}

func comm(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// assertOwnedByUs checks the `nft list` view of ownership: flags owner and
// the comm of this test binary.
func assertOwnedByUs(t *testing.T, name string) string {
	t.Helper()
	out := nft(t, "list", "table", "inet", name)
	if !strings.Contains(out, "\tflags owner\n") {
		t.Errorf("table not shown with flags owner:\n%s", out)
	}
	if want := "# progname " + comm(t); !strings.Contains(out, want) {
		t.Errorf("table listing lacks %q:\n%s", want, out)
	}
	return out
}

func assertVerify(t *testing.T, m *Manager, rs Ruleset) {
	t.Helper()
	ok, err := m.Verify(rs)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatalf("Verify(%v) = false; table:\n%s", rs, nft(t, "list", "table", "inet", m.table.Name))
	}
}

func loUp(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("ip link set lo up: %v\n%s", err, out)
	}
}

func TestPrivRuleEncodingAndDrops(t *testing.T) {
	requirePrivileged(t)
	loUp(t)
	m := openT(t, "wgsteer_encoding")
	info := m.Info()
	if !info.OwnerFlag || info.Owner == 0 || info.ReplacedStale || info.Name != "wgsteer_encoding" || info.Chain != "input" {
		t.Fatalf("Info = %+v", info)
	}

	rs := Ruleset{ListenPort: 51820, Denied: aps("127.0.0.1:4000", "192.0.2.7:443", "[2001:db8::1]:51820", "[::1]:5000")}
	if _, err := m.Apply(rs); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	out := assertOwnedByUs(t, m.table.Name)
	t.Logf("nft list table inet %s:\n%s", m.table.Name, out)
	for _, want := range []string{
		"type filter hook input priority filter - 5; policy accept;",
		"\t\tudp dport 51820 ip saddr 127.0.0.1 udp sport 4000 counter packets 0 bytes 0 drop\n",
		"\t\tudp dport 51820 ip saddr 192.0.2.7 udp sport 443 counter packets 0 bytes 0 drop\n",
		"\t\tudp dport 51820 ip6 saddr 2001:db8::1 udp sport 51820 counter packets 0 bytes 0 drop\n",
		"\t\tudp dport 51820 ip6 saddr ::1 udp sport 5000 counter packets 0 bytes 0 drop\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("listing lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "comment") {
		t.Errorf("rule identification leaked into the listing:\n%s", out)
	}
	assertVerify(t, m, rs)
	if !m.Committed().Equal(rs) {
		t.Errorf("Committed = %v, want %v", m.Committed(), rs)
	}
	if ok, err := m.Verify(Ruleset{ListenPort: 51821, Denied: rs.Denied}); err != nil || ok {
		t.Errorf("Verify with another port = %v, %v; want false", ok, err)
	}

	// Denied tuple is dropped, another source port of the same address is
	// not. Loopback delivery is synchronous and ordered, so the first
	// datagram the listener sees must be the allowed one.
	ln, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:51820")))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	send := func(src string) {
		c, err := net.DialUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(src)), ln.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write([]byte(src)); err != nil {
			t.Fatal(err)
		}
	}
	send("127.0.0.1:4000")
	send("127.0.0.1:4001")
	buf := make([]byte, 64)
	_ = ln.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := ln.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	if from.Port() != 4001 || string(buf[:n]) != "127.0.0.1:4001" {
		t.Fatalf("first datagram from %v (%q), want the allowed 127.0.0.1:4001", from, buf[:n])
	}

	counters, err := m.Counters()
	if err != nil {
		t.Fatal(err)
	}
	want := netip.MustParseAddrPort("127.0.0.1:4000")
	var hit bool
	for _, c := range counters {
		if c.Addr == want {
			hit = c.Packets == 1 && c.Bytes > 0
		} else if c.Packets != 0 {
			t.Errorf("unexpected drops on %v: %+v", c.Addr, c)
		}
	}
	if !hit || len(counters) != 4 {
		t.Fatalf("counters = %+v, want one drop on %v", counters, want)
	}

	// Apply returns the counters from before its flush.
	before, err := m.Apply(Ruleset{ListenPort: 51820, Denied: aps("192.0.2.7:443")})
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 4 || before[0].Addr != want || before[0].Packets != 1 {
		t.Fatalf("before = %+v", before)
	}
	after, err := m.Counters()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].Packets != 0 {
		t.Fatalf("counters after rebuild = %+v", after)
	}
}

func TestPrivForeignConnection(t *testing.T) {
	requirePrivileged(t)
	m := openT(t, "wgsteer_foreign")
	rs := Ruleset{ListenPort: 1000, Denied: aps("192.0.2.1:1")}
	if _, err := m.Apply(rs); err != nil {
		t.Fatal(err)
	}

	other, err := nftables.New(nftables.AsLasting())
	if err != nil {
		t.Fatal(err)
	}
	defer other.CloseLasting()
	other.FlushChain(m.chain)
	if err := other.Flush(); !errors.Is(err, unix.EPERM) {
		t.Errorf("second connection flushing the chain: %v, want EPERM", err)
	}
	other.DelTable(m.table)
	if err := other.Flush(); !errors.Is(err, unix.EPERM) {
		t.Errorf("second connection deleting the table: %v, want EPERM", err)
	}
	if out, err := exec.Command("nft", "delete", "table", "inet", m.table.Name).CombinedOutput(); err == nil {
		t.Errorf("nft delete table succeeded on an owned table: %s", out)
	}

	if m2, err := Open(m.table.Name); !errors.Is(err, ErrOwnedElsewhere) {
		if m2 != nil {
			_ = m2.Close()
		}
		t.Fatalf("second Open = %v, want ErrOwnedElsewhere", err)
	}
	assertVerify(t, m, rs)
	assertOwnedByUs(t, m.table.Name)
}

func TestPrivFailedTransaction(t *testing.T) {
	requirePrivileged(t)
	m := openT(t, "wgsteer_failed")
	rs1 := Ruleset{ListenPort: 2000, Denied: aps("192.0.2.1:1", "[2001:db8::1]:1")}
	rs2 := Ruleset{ListenPort: 2000, Denied: aps("192.0.2.9:9")}
	if _, err := m.Apply(rs1); err != nil {
		t.Fatal(err)
	}
	conn := m.conn

	// The batch carries the valid rebuild to rs2 plus a rule for a
	// nonexistent chain on the manager's own connection.
	m.flush = func(c *nftables.Conn) error {
		c.AddRule(&nftables.Rule{
			Table: m.table,
			Chain: &nftables.Chain{Name: "nonexistent", Table: m.table},
			Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
		})
		return c.Flush()
	}
	_, err := m.Apply(rs2)
	if !errors.Is(err, ErrRejected) || !errors.Is(err, unix.ENOENT) {
		t.Fatalf("Apply with invalid message = %v, want ErrRejected wrapping ENOENT", err)
	}
	m.flush = nil
	if !tableExists(t, m.table.Name) {
		t.Fatal("table vanished after a failed transaction")
	}
	assertOwnedByUs(t, m.table.Name)
	assertVerify(t, m, rs1)
	if !m.Committed().Equal(rs1) {
		t.Errorf("Committed = %v, want previous %v", m.Committed(), rs1)
	}

	if _, err := m.Apply(rs2); err != nil {
		t.Fatalf("next Apply on the same connection: %v", err)
	}
	if m.conn != conn {
		t.Fatal("connection replaced")
	}
	assertVerify(t, m, rs2)
	assertOwnedByUs(t, m.table.Name)
}

// enobufs is what a lost ACK looks like: a socket error without a sequence.
var enobufs = fmt.Errorf("receive: %w", &netlink.OpError{Op: "receive", Err: os.NewSyscallError("recvmsg", unix.ENOBUFS)})

func TestPrivUnknownOutcome(t *testing.T) {
	requirePrivileged(t)
	m := openT(t, "wgsteer_unknown")
	rs1 := Ruleset{ListenPort: 3000, Denied: aps("192.0.2.1:1")}
	rs2 := Ruleset{ListenPort: 3000, Denied: aps("192.0.2.2:2")}
	rs3 := Ruleset{ListenPort: 3000, Denied: aps("192.0.2.3:3")}
	if _, err := m.Apply(rs1); err != nil {
		t.Fatal(err)
	}

	// Committed, but the reply is lost: read-back matches -> success.
	m.flush = func(c *nftables.Conn) error {
		if err := c.Flush(); err != nil {
			t.Errorf("underlying flush: %v", err)
		}
		return enobufs
	}
	if _, err := m.Apply(rs2); err != nil {
		t.Fatalf("Apply with lost ACK of a committed batch: %v", err)
	}
	if !m.Committed().Equal(rs2) {
		t.Errorf("Committed = %v, want %v", m.Committed(), rs2)
	}

	// Rejected, and the error reply is lost: read-back mismatch -> rejected.
	m.flush = func(c *nftables.Conn) error {
		c.AddRule(&nftables.Rule{
			Table: m.table,
			Chain: &nftables.Chain{Name: "nonexistent", Table: m.table},
			Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
		})
		if err := c.Flush(); err == nil {
			t.Error("invalid batch accepted")
		}
		return enobufs
	}
	if _, err := m.Apply(rs3); !errors.Is(err, ErrRejected) {
		t.Fatalf("Apply with lost error reply = %v, want ErrRejected", err)
	}
	m.flush = nil
	if !m.Committed().Equal(rs2) {
		t.Errorf("Committed = %v, want %v", m.Committed(), rs2)
	}
	assertVerify(t, m, rs2)
}

func TestPrivReplacement(t *testing.T) {
	requirePrivileged(t)
	m := openT(t, "wgsteer_replace")
	rs := Ruleset{ListenPort: 4000, Denied: aps("192.0.2.1:1", "[2001:db8::5]:5")}
	if _, err := m.Apply(rs); err != nil {
		t.Fatal(err)
	}

	// CloseLasting alone destroys the owned table.
	if err := m.conn.CloseLasting(); err != nil {
		t.Fatal(err)
	}
	if tableExists(t, m.table.Name) {
		t.Fatal("table still exists after CloseLasting")
	}
	if err := m.Reconnect(rs); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	assertOwnedByUs(t, m.table.Name)
	assertVerify(t, m, rs)
	if info := m.Info(); !info.OwnerFlag || info.ReplacedStale {
		t.Errorf("Info after Reconnect = %+v", info)
	}

	// Reconnect from a live connection closes it first, so the new socket
	// does not find the table owned by the old one.
	rs2 := Ruleset{ListenPort: 4001, Denied: aps("192.0.2.2:2")}
	if err := m.Reconnect(rs2); err != nil {
		t.Fatalf("Reconnect on a live connection: %v", err)
	}
	assertVerify(t, m, rs2)
	if !m.Committed().Equal(rs2) {
		t.Errorf("Committed = %v, want %v", m.Committed(), rs2)
	}
	assertOwnedByUs(t, m.table.Name)
}

func genID(t *testing.T) uint32 {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	g, err := c.GetGen()
	if err != nil {
		t.Fatalf("GetGen: %v", err)
	}
	return g.ID
}

func TestPrivStaleTable(t *testing.T) {
	requirePrivileged(t)
	const name = "wgsteer_stale"
	// Generation step of one transaction on this kernel.
	g0 := genID(t)
	nft(t, "add", "table", "inet", "wgsteer_genprobe")
	step := genID(t) - g0
	nft(t, "delete", "table", "inet", "wgsteer_genprobe")

	path := filepath.Join(t.TempDir(), "stale.nft")
	stale := "table inet " + name + " {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\tudp dport 1 drop\n\t}\n}\n"
	if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	nft(t, "-f", path)

	before := genID(t)
	m := openT(t, name)
	if got := genID(t) - before; got != step {
		t.Errorf("Open took %d generation steps, want %d (one transaction)", got, step)
	}
	if !m.Info().ReplacedStale || !m.Info().OwnerFlag {
		t.Errorf("Info = %+v, want ReplacedStale and OwnerFlag", m.Info())
	}
	out := assertOwnedByUs(t, name)
	if strings.Contains(out, "udp dport 1 drop") {
		t.Errorf("stale rule survived:\n%s", out)
	}
	assertVerify(t, m, Ruleset{})
}

func TestPrivFlushRulesetSkipsOwnedTable(t *testing.T) {
	requirePrivileged(t)
	m := openT(t, "wgsteer_flush")
	rs := Ruleset{ListenPort: 5000, Denied: aps("127.0.0.1:1", "[::1]:2")}
	if _, err := m.Apply(rs); err != nil {
		t.Fatal(err)
	}

	nft(t, "flush", "ruleset")
	assertVerify(t, m, rs)

	path := filepath.Join(t.TempDir(), "reload.nft")
	conf := "flush ruleset\ntable inet wgsteer_other {\n\tchain c {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	nft(t, "-f", path)
	assertVerify(t, m, rs)
	assertOwnedByUs(t, m.table.Name)
	if !tableExists(t, "wgsteer_other") {
		t.Error("reload file was not applied")
	}
	nft(t, "delete", "table", "inet", "wgsteer_other")

	// Close deletes the table explicitly and is idempotent.
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if tableExists(t, m.table.Name) {
		t.Error("table exists after Close")
	}
	if err := m.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if _, err := m.Apply(rs); !errors.Is(err, ErrClosed) {
		t.Errorf("Apply after Close = %v, want ErrClosed", err)
	}
}

// TestPrivHelperOwner is the child process of TestPrivProcessDeath: it opens
// the table, reports readiness and blocks until killed.
func TestPrivHelperOwner(t *testing.T) {
	name := os.Getenv(helperEnv)
	if name == "" {
		t.Skip("helper process for TestPrivProcessDeath")
	}
	m, err := Open(name)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	if _, err := m.Apply(Ruleset{ListenPort: 6000, Denied: aps("192.0.2.1:1")}); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Println("ready")
	select {}
}

func TestPrivProcessDeath(t *testing.T) {
	requirePrivileged(t)
	const name = "wgsteer_death"
	cmd := exec.Command(os.Args[0], "-test.run=^TestPrivHelperOwner$")
	cmd.Env = append(os.Environ(), helperEnv+"="+name)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	sc := bufio.NewScanner(stdout)
	for {
		if !sc.Scan() {
			t.Fatalf("helper exited before ready: %v", sc.Err())
		}
		line := sc.Text()
		if line == "ready" {
			break
		}
		if strings.HasPrefix(line, "error:") {
			t.Fatalf("helper: %s", line)
		}
	}

	out := nft(t, "list", "table", "inet", name)
	if !strings.Contains(out, "flags owner") || !strings.Contains(out, "udp dport 6000") {
		t.Fatalf("helper's table:\n%s", out)
	}
	if m, err := Open(name); !errors.Is(err, ErrOwnedElsewhere) {
		if m != nil {
			_ = m.Close()
		}
		t.Fatalf("Open while another process owns the table = %v, want ErrOwnedElsewhere", err)
	}

	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	// The kernel releases the table when the socket is closed during exit,
	// before the parent can reap the child; poll only as a safety margin.
	deadline := time.Now().Add(5 * time.Second)
	for tableExists(t, name) {
		if time.Now().After(deadline) {
			t.Fatal("table survived the owner's SIGKILL")
		}
		time.Sleep(10 * time.Millisecond)
	}
	m := openT(t, name)
	assertVerify(t, m, Ruleset{})
}
