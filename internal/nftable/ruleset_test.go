package nftable

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func aps(ss ...string) []netip.AddrPort {
	out := make([]netip.AddrPort, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddrPort(s)
	}
	return out
}

func TestDesired(t *testing.T) {
	listed := aps("203.0.113.5:443", "127.0.0.1:4000", "[2001:db8::1]:51820", "198.51.100.9:443")
	tests := []struct {
		name     string
		selected string
		aliases  []netip.AddrPort
		want     []netip.AddrPort
	}{
		{
			name:     "selection allowed, rest denied in both families",
			selected: "127.0.0.1:4000",
			want:     aps("127.0.0.1:4000", "198.51.100.9:443", "203.0.113.5:443", "[2001:db8::1]:51820")[1:],
		},
		{
			name: "no selection denies every listed endpoint",
			want: aps("127.0.0.1:4000", "198.51.100.9:443", "203.0.113.5:443", "[2001:db8::1]:51820"),
		},
		{
			name:     "aliases of the endpoint left are denied too",
			selected: "[2001:db8::1]:51820",
			aliases:  aps("192.0.2.77:443", "[2001:db8::99]:443"),
			want:     aps("127.0.0.1:4000", "192.0.2.77:443", "198.51.100.9:443", "203.0.113.5:443", "[2001:db8::99]:443"),
		},
		{
			name:     "duplicates and mapped forms collapse",
			selected: "203.0.113.5:443",
			aliases:  aps("[::ffff:198.51.100.9]:443", "127.0.0.1:4000", "192.0.2.77:443", "192.0.2.77:443"),
			want:     aps("127.0.0.1:4000", "192.0.2.77:443", "198.51.100.9:443", "[2001:db8::1]:51820"),
		},
		{
			name:     "selected never denied even if listed as alias",
			selected: "203.0.113.5:443",
			aliases:  aps("[::ffff:203.0.113.5]:443"),
			want:     aps("127.0.0.1:4000", "198.51.100.9:443", "[2001:db8::1]:51820"),
		},
		{
			name:     "same address, other port is a different tuple",
			selected: "203.0.113.5:443",
			aliases:  aps("203.0.113.5:444"),
			want:     aps("127.0.0.1:4000", "198.51.100.9:443", "203.0.113.5:444", "[2001:db8::1]:51820"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sel netip.AddrPort
			if tt.selected != "" {
				sel = netip.MustParseAddrPort(tt.selected)
			}
			got := Desired(listed, sel, tt.aliases, 51820)
			if got.ListenPort != 51820 {
				t.Errorf("ListenPort = %d, want 51820", got.ListenPort)
			}
			if !slices.Equal(got.Denied, tt.want) {
				t.Errorf("Denied = %v, want %v", got.Denied, tt.want)
			}
			// Input order must not matter.
			rev := slices.Clone(listed)
			slices.Reverse(rev)
			if again := Desired(rev, sel, tt.aliases, 51820); !slices.Equal(again.Denied, got.Denied) {
				t.Errorf("order-dependent result: %v vs %v", again.Denied, got.Denied)
			}
		})
	}
}

func TestDesiredSingleSelected(t *testing.T) {
	got := Desired(aps("192.0.2.1:1"), netip.MustParseAddrPort("192.0.2.1:1"), nil, 7)
	if len(got.Denied) != 0 {
		t.Fatalf("Denied = %v, want empty", got.Denied)
	}
}

func TestRulesetEqual(t *testing.T) {
	a := Ruleset{ListenPort: 51820, Denied: aps("192.0.2.1:443", "[2001:db8::1]:443")}
	tests := []struct {
		name string
		b    Ruleset
		want bool
	}{
		{"identical", Ruleset{ListenPort: 51820, Denied: aps("192.0.2.1:443", "[2001:db8::1]:443")}, true},
		{"other order, duplicates, mapped", Ruleset{ListenPort: 51820, Denied: aps("[2001:db8::1]:443", "[::ffff:192.0.2.1]:443", "192.0.2.1:443")}, true},
		{"other port", Ruleset{ListenPort: 51821, Denied: a.Denied}, false},
		{"missing tuple", Ruleset{ListenPort: 51820, Denied: aps("192.0.2.1:443")}, false},
		{"extra tuple", Ruleset{ListenPort: 51820, Denied: aps("192.0.2.1:443", "192.0.2.2:443", "[2001:db8::1]:443")}, false},
		{"other source port", Ruleset{ListenPort: 51820, Denied: aps("192.0.2.1:444", "[2001:db8::1]:443")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.Equal(tt.b); got != tt.want {
				t.Errorf("Equal = %v, want %v", got, tt.want)
			}
			if got := tt.b.Equal(a); got != tt.want {
				t.Errorf("reverse Equal = %v, want %v", got, tt.want)
			}
		})
	}
	if !(Ruleset{ListenPort: 1}).Equal(Ruleset{ListenPort: 2, Denied: []netip.AddrPort{}}) {
		t.Error("empty rulesets with different ports should be equal (both mean an empty chain)")
	}
}

func TestUserDataRoundTrip(t *testing.T) {
	for _, ap := range aps("127.0.0.1:4000", "[2001:db8::1]:51820") {
		port, got, ok := parseUserData(ruleUserData(51820, ap))
		if !ok || port != 51820 || got != ap {
			t.Errorf("round trip of %v: got %d %v %v", ap, port, got, ok)
		}
	}
	if _, _, ok := parseUserData([]byte("foreign")); ok {
		t.Error("foreign userdata parsed as ours")
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want outcome
	}{
		{"kernel error reply", fmt.Errorf("receive: %w", fmt.Errorf("NFT_MSG_NEWRULE: %w", &netlink.OpError{Op: "receive", Err: unix.ENOENT, Sequence: 42})), outcomeRejected},
		{"socket receive error", fmt.Errorf("receive: %w", &netlink.OpError{Op: "receive", Err: os.NewSyscallError("recvmsg", unix.ENOBUFS)}), outcomeUnknown},
		{"send failure", fmt.Errorf("SendMessages: %w", &netlink.OpError{Op: "send-messages", Err: unix.EBADF}), outcomeBroken},
		{"other", errors.New("pselect6: interrupted"), outcomeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classify(tt.err); got != tt.want {
				t.Errorf("classify = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestReadFailureThreshold uses a fake netlink socket whose every request
// fails, so it needs no privileges.
func TestReadFailureThreshold(t *testing.T) {
	conn, err := nftables.New(nftables.AsLasting(), nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if req == nil {
			return nil, io.EOF
		}
		return nltest.Error(int(unix.EIO), req)
	}))
	if err != nil {
		t.Fatal(err)
	}
	tbl := &nftables.Table{Name: "t", Family: nftables.TableFamilyINet}
	m := &Manager{table: tbl, chain: &nftables.Chain{Name: chainName, Table: tbl}, conn: conn}
	for i := 1; i <= maxReadFailures; i++ {
		_, err := m.Counters()
		if err == nil {
			t.Fatalf("read %d: no error", i)
		}
		if broken := errors.Is(err, ErrConnBroken); broken != (i == maxReadFailures) {
			t.Fatalf("read %d: err = %v, ErrConnBroken = %v", i, err, broken)
		}
	}
	if _, err := m.Verify(Ruleset{}); !errors.Is(err, ErrConnBroken) {
		t.Fatalf("Verify after threshold: %v, want ErrConnBroken", err)
	}
}
