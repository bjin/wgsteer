package probe

import (
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/bjin/wgsteer/internal/probecfg"
)

func TestParseState(t *testing.T) {
	raw := strings.Join([]string{
		"private_key=0000000000000000000000000000000000000000000000000000000000000001",
		"listen_port=40000",
		"fwmark=51820",
		"public_key=0000000000000000000000000000000000000000000000000000000000000002",
		"preshared_key=0000000000000000000000000000000000000000000000000000000000000000",
		"protocol_version=1",
		"endpoint=[::ffff:127.0.0.1]:51820",
		"last_handshake_time_sec=1700000000",
		"last_handshake_time_nsec=5",
		"tx_bytes=100",
		"rx_bytes=200",
		"persistent_keepalive_interval=0",
		"allowed_ip=192.0.2.1/32",
		"",
	}, "\n")
	st, err := parseState(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := State{
		Endpoint:      netip.MustParseAddrPort("127.0.0.1:51820"),
		LastHandshake: time.Unix(1700000000, 5),
		ListenPort:    40000,
		Fwmark:        51820,
		RxBytes:       200,
		TxBytes:       100,
	}
	if st != want {
		t.Errorf("state %+v, want %+v", st, want)
	}

	never, err := parseState("listen_port=1\npublic_key=00\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n")
	if err != nil {
		t.Fatal(err)
	}
	if !never.LastHandshake.IsZero() || never.Endpoint.IsValid() {
		t.Errorf("no handshake/endpoint parsed as %+v", never)
	}

	if _, err := parseState("rx_bytes=x\n"); err == nil {
		t.Error("malformed counter accepted")
	}
}

func TestNewRejectsConfig(t *testing.T) {
	id := &probecfg.Config{}
	ep := netip.MustParseAddrPort("127.0.0.1:51820")
	base := Config{Identity: id, ProbeAddr: v4Probe, Target: v4Target, PayloadSize: 56, Endpoint: ep}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"no identity", func(c *Config) { c.Identity = nil }},
		{"no target", func(c *Config) { c.Target = netip.Addr{} }},
		{"mixed families", func(c *Config) { c.Target = v6Target }},
		{"payload below header fields", func(c *Config) { c.PayloadSize = MinPayloadSize - 1 }},
		{"payload above default MTU", func(c *Config) { c.PayloadSize = DefaultMTU - ipv4HeaderLen - icmpHeaderLen + 1 }},
		{"v6 payload above default MTU", func(c *Config) {
			c.ProbeAddr, c.Target, c.PayloadSize = v6Probe, v6Target, DefaultMTU-ipv6HeaderLen-icmpHeaderLen+1
		}},
		{"payload above configured MTU", func(c *Config) { c.MTU, c.PayloadSize = 1280, 1280-ipv4HeaderLen-icmpHeaderLen+1 }},
		{"MTU below the IPv4 minimum", func(c *Config) { c.MTU = 575 }},
		{"MTU below the IPv6 minimum", func(c *Config) { c.ProbeAddr, c.Target, c.MTU = v6Probe, v6Target, 1279 }},
		{"MTU above the maximum", func(c *Config) { c.MTU = MaxMTU + 1 }},
		{"no endpoint", func(c *Config) { c.Endpoint = netip.AddrPort{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mutate(&c)
			if p, err := New(c); err == nil {
				p.Close()
				t.Error("accepted")
			}
		})
	}
	ok := base
	ok.MTU, ok.PayloadSize = 1280, MaxPayloadSize(1280, v4Probe)
	p, err := New(ok)
	if err != nil {
		t.Fatalf("payload at the configured MTU's limit rejected: %v", err)
	}
	if mtu, _ := p.tun.MTU(); mtu != 1280 {
		t.Errorf("device MTU %d, want 1280", mtu)
	}
	p.Close()
}

// markBind is the probe's own bind with a scripted SetMark that never
// touches the sockets (setting SO_MARK needs CAP_NET_ADMIN).
type markBind struct {
	conn.Bind
	fail  int      // SetMark calls left to fail
	marks []uint32 // marks that reached the bind successfully
}

func (b *markBind) SetMark(m uint32) error {
	if b.fail > 0 {
		b.fail--
		return syscall.EPERM
	}
	b.marks = append(b.marks, m)
	return nil
}

// wireguard-go records a new fwmark before applying it and skips a mark equal
// to the recorded one: a retry after a failed application must still reach
// the sockets.
func TestSetFwmarkRetryReachesBind(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	id := &probecfg.Config{PrivateKey: priv, PublicKey: priv.PublicKey(), PeerKey: peer.PublicKey()}
	if err := id.Validate(v4Probe, v4Target); err != nil {
		t.Fatal(err)
	}
	b := &markBind{Bind: newUDPBind(), fail: 1}
	p, err := New(Config{Identity: id, ProbeAddr: v4Probe, Target: v4Target, PayloadSize: 56,
		Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), Bind: b, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.SetFwmark(51820); err == nil {
		t.Fatal("failed SetMark not reported")
	}
	if err := p.SetFwmark(51820); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(b.marks, 51820) {
		t.Fatalf("marks applied after the retry: %v, want 51820", b.marks)
	}
}
