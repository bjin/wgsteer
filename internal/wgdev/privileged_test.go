package wgdev

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Privileged tests need CAP_NET_ADMIN in a disposable network namespace.
// They refuse to run in the initial user namespace so they can never touch
// host interfaces; `make integration` runs them under `unshare -rn`.
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
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("privileged test: ip binary not found")
	}
}

func ip(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func key(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func prefixes(t *testing.T, ss ...string) []net.IPNet {
	t.Helper()
	out := make([]net.IPNet, len(ss))
	for i, s := range ss {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = *n
	}
	return out
}

func rawPeer(t *testing.T, raw *wgctrl.Client, dev string, k wgtypes.Key) wgtypes.Peer {
	t.Helper()
	d, err := raw.Device(dev)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range d.Peers {
		if p.PublicKey == k {
			return p
		}
	}
	t.Fatalf("%s has no peer %v", dev, k)
	return wgtypes.Peer{}
}

func getPeer(t *testing.T, c *Client, dev string, k wgtypes.Key) Peer {
	t.Helper()
	d, err := c.Get(dev)
	if err != nil {
		t.Fatalf("Get(%s): %v", dev, err)
	}
	p, ok := d.Peer(k)
	if !ok {
		t.Fatalf("%s has no peer %v", dev, k)
	}
	return p
}

// samePeerConfig compares everything SetEndpoint must not touch.
func samePeerConfig(a, b wgtypes.Peer) bool {
	return a.PublicKey == b.PublicKey && a.PresharedKey == b.PresharedKey &&
		slices.EqualFunc(a.AllowedIPs, b.AllowedIPs, func(x, y net.IPNet) bool { return x.String() == y.String() })
}

// TestPrivKernelDevice runs two kernel WireGuard devices in one network
// namespace, wga (client side, managed peer = wgb) and wgb, talking over
// loopback.
func TestPrivKernelDevice(t *testing.T) {
	requirePrivileged(t)
	ip(t, "link", "set", "lo", "up")
	for _, dev := range []string{"wga", "wgb"} {
		ip(t, "link", "add", dev, "type", "wireguard")
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", dev).Run() })
		ip(t, "link", "set", dev, "up")
	}

	raw, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	privA, privB, psk := key(t), key(t), key(t)
	pubA, pubB := privA.PublicKey(), privB.PublicKey()
	other := key(t).PublicKey()

	if err := raw.ConfigureDevice("wgb", wgtypes.Config{
		PrivateKey: &privB,
		ListenPort: new(51002),
		Peers: []wgtypes.PeerConfig{{
			PublicKey:    pubA,
			PresharedKey: &psk,
			Endpoint:     net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:51001")),
			AllowedIPs:   prefixes(t, "10.99.0.1/32"),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	// Creating the peer with keepalive 25 on an up device sends a keepalive,
	// which starts the handshake.
	if err := raw.ConfigureDevice("wga", wgtypes.Config{
		PrivateKey:   &privA,
		ListenPort:   new(51001),
		FirewallMark: new(0x1234),
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:  other,
				Endpoint:   net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:59999")),
				AllowedIPs: prefixes(t, "10.99.0.3/32"),
			},
			{
				PublicKey:                   pubB,
				PresharedKey:                &psk,
				Endpoint:                    net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:51002")),
				AllowedIPs:                  prefixes(t, "10.99.0.2/32", "0.0.0.0/1", "::/0"),
				PersistentKeepaliveInterval: new(25 * time.Second),
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	c, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	deadline := time.Now().Add(5 * time.Second)
	for getPeer(t, c, "wga", pubB).LastHandshake.IsZero() {
		if time.Now().After(deadline) {
			t.Fatal("no handshake between wga and wgb")
		}
		time.Sleep(10 * time.Millisecond)
	}

	d, err := c.Get("wga")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "wga" || d.Type != "kernel" || d.PublicKey != pubA || d.ListenPort != 51001 || d.Fwmark != 0x1234 || len(d.Peers) != 2 {
		t.Fatalf("Get(wga) = %+v", d)
	}
	p, _ := d.Peer(pubB)
	if p.Endpoint != netip.MustParseAddrPort("127.0.0.1:51002") || p.Keepalive != 25*time.Second || p.TxBytes == 0 || p.RxBytes == 0 {
		t.Fatalf("managed peer = %+v", p)
	}
	handshake := p.LastHandshake
	baseB := rawPeer(t, raw, "wga", pubB)
	baseOther := rawPeer(t, raw, "wga", other)

	// assertUntouched checks keys, allowed IPs, the other peer and the
	// handshake (no re-handshake).
	assertUntouched := func(t *testing.T) {
		t.Helper()
		if got := rawPeer(t, raw, "wga", pubB); !samePeerConfig(got, baseB) {
			t.Errorf("managed peer config changed: %+v, was %+v", got, baseB)
		}
		got := rawPeer(t, raw, "wga", other)
		if !samePeerConfig(got, baseOther) || got.Endpoint.String() != baseOther.Endpoint.String() || got.PersistentKeepaliveInterval != 0 {
			t.Errorf("other peer changed: %+v, was %+v", got, baseOther)
		}
		dev, err := raw.Device("wga")
		if err != nil {
			t.Fatal(err)
		}
		if dev.PrivateKey != privA || dev.ListenPort != 51001 || dev.FirewallMark != 0x1234 {
			t.Errorf("device config changed: %+v", dev)
		}
		if lh := getPeer(t, c, "wga", pubB).LastHandshake; !lh.Equal(handshake) {
			t.Errorf("last handshake changed: %v, was %v", lh, handshake)
		}
	}

	// kickReceived waits for wgb to receive exactly one 32-byte keepalive
	// from wga after a kick.
	rxB := func() int64 { return getPeer(t, c, "wgb", pubA).RxBytes }
	txA := func() int64 { return getPeer(t, c, "wga", pubB).TxBytes }
	kickReceived := func(t *testing.T, rx0, tx0 int64) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for rxB() == rx0 {
			if time.Now().After(deadline) {
				t.Fatal("wgb received nothing after the kick")
			}
			time.Sleep(5 * time.Millisecond)
		}
		if rx, tx := rxB()-rx0, txA()-tx0; rx != 32 || tx != 32 {
			t.Errorf("after kick: wgb rx +%d, wga tx +%d; want one 32-byte keepalive", rx, tx)
		}
	}

	t.Run("missing device", func(t *testing.T) {
		if _, err := c.Get("wgnone"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get(missing) = %v, want ErrNotFound", err)
		}
		if err := c.SetEndpoint("wgnone", pubB, netip.MustParseAddrPort("127.0.0.1:1"), 0, false); !errors.Is(err, ErrNotFound) {
			t.Errorf("SetEndpoint(missing) = %v, want ErrNotFound", err)
		}
	})

	t.Run("endpoint only", func(t *testing.T) {
		ep := netip.MustParseAddrPort("[::1]:51002")
		if err := c.SetEndpoint("wga", pubB, ep, 25*time.Second, false); err != nil {
			t.Fatal(err)
		}
		p := getPeer(t, c, "wga", pubB)
		if p.Endpoint != ep || p.Keepalive != 25*time.Second {
			t.Errorf("peer after SetEndpoint = %+v", p)
		}
		assertUntouched(t)
	})

	t.Run("kick keepalive 25", func(t *testing.T) {
		rx0, tx0 := rxB(), txA()
		ep := netip.MustParseAddrPort("127.0.0.2:51002")
		if err := c.SetEndpoint("wga", pubB, ep, 25*time.Second, true); err != nil {
			t.Fatal(err)
		}
		p := getPeer(t, c, "wga", pubB)
		if p.Endpoint != ep || p.Keepalive != 25*time.Second {
			t.Errorf("peer after kick = %+v, want endpoint %v keepalive 25s", p, ep)
		}
		kickReceived(t, rx0, tx0)
		assertUntouched(t)
	})

	t.Run("kick keepalive 0", func(t *testing.T) {
		if err := raw.ConfigureDevice("wga", wgtypes.Config{Peers: []wgtypes.PeerConfig{{
			PublicKey: pubB, UpdateOnly: true, PersistentKeepaliveInterval: new(time.Duration(0)),
		}}}); err != nil {
			t.Fatal(err)
		}
		rx0, tx0 := rxB(), txA()
		// A 16-byte IPv4 form must be normalized like any other.
		ep := netip.AddrPortFrom(netip.MustParseAddr("::ffff:127.0.0.1"), 51002)
		if err := c.SetEndpoint("wga", pubB, ep, 0, true); err != nil {
			t.Fatal(err)
		}
		p := getPeer(t, c, "wga", pubB)
		if p.Endpoint != netip.MustParseAddrPort("127.0.0.1:51002") || p.Keepalive != 0 {
			t.Errorf("peer after kick = %+v, want endpoint 127.0.0.1:51002 keepalive 0", p)
		}
		kickReceived(t, rx0, tx0)
		assertUntouched(t)
	})

	// A failed earlier kick can leave keepalive 1s on the device while the
	// original is 0; the next kick must still send at once.
	t.Run("kick keepalive 0 from a stale 1s", func(t *testing.T) {
		if err := raw.ConfigureDevice("wga", wgtypes.Config{Peers: []wgtypes.PeerConfig{{
			PublicKey: pubB, UpdateOnly: true, PersistentKeepaliveInterval: new(time.Second),
		}}}); err != nil {
			t.Fatal(err)
		}
		// Align with the periodic keepalive: the next one is ~1s away.
		rx := rxB()
		deadline := time.Now().Add(5 * time.Second)
		for rxB() == rx {
			if time.Now().After(deadline) {
				t.Fatal("no periodic keepalive at 1s")
			}
			time.Sleep(5 * time.Millisecond)
		}
		rx0, tx0 := rxB(), txA()
		start := time.Now()
		if err := c.SetEndpoint("wga", pubB, netip.MustParseAddrPort("127.0.0.1:51002"), 0, true); err != nil {
			t.Fatal(err)
		}
		kickReceived(t, rx0, tx0)
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Errorf("keepalive arrived after %v: the periodic one, not the kick", d)
		}
		if p := getPeer(t, c, "wga", pubB); p.Keepalive != 0 {
			t.Errorf("keepalive after kick = %v, want 0", p.Keepalive)
		}
	})
}
