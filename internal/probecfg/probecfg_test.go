package probecfg

import (
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	privHex = "003ed5d73b55806c30de3f8a7bdab38af13539220533055e635690b8b87ad641"
	// Derived with `wg pubkey`.
	pubHex  = "c4c8e984c5322c8184c72265b92b250fdb63688705f504ba003c88f03393cf28"
	peerHex = "f928d4f6c1b86c12f2562c10b07c555c5c57fd00f59e90c8d8d88767271cbf7c"
	pskHex  = "1111111111111111111111111111111111111111111111111111111111111111"
)

func mustKey(t *testing.T, s string) wgtypes.Key {
	t.Helper()
	k, err := parseHexKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParse(t *testing.T) {
	in := "# probe identity\nprivate_key=" + privHex + "\nlisten_port=58120\n\n" +
		"public_key=" + peerHex + "\npreshared_key=" + pskHex + "\n" +
		"endpoint=198.51.100.55:51820\nallowed_ip=192.0.2.0/24\n"
	c, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicKey != mustKey(t, pubHex) {
		t.Errorf("derived public key = %s", HexKey(c.PublicKey))
	}
	if c.PeerKey != mustKey(t, peerHex) || c.PresharedKey == nil || *c.PresharedKey != mustKey(t, pskHex) {
		t.Errorf("peer keys not parsed")
	}
	if c.ListenPort != 58120 || c.Endpoint != netip.MustParseAddrPort("198.51.100.55:51820") {
		t.Errorf("listen port %d, endpoint %s", c.ListenPort, c.Endpoint)
	}
}

func TestParseRejects(t *testing.T) {
	base := "private_key=" + privHex + "\n"
	peer := "public_key=" + peerHex + "\n"
	for name, in := range map[string]string{
		"no peer":         base,
		"two peers":       base + peer + "public_key=" + pubHex + "\n",
		"base64 key":      "private_key=AD7V1ztVgGww3j+KfbqzivE1OSIFMwVeY1aQuLh61kE=\n" + peer,
		"short key":       "private_key=00\n" + peer,
		"no private key":  peer,
		"own key as peer": base + "public_key=" + pubHex + "\n",
		"fwmark":          base + "fwmark=1\n" + peer,
		"unknown key":     base + peer + "bogus=1\n",
		"hostname":        base + peer + "endpoint=example.com:1\n",
	} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestValidateAndUAPI(t *testing.T) {
	c, err := Parse(strings.NewReader("private_key=" + privHex + "\npublic_key=" + peerHex + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	target := netip.MustParseAddr("192.0.2.1")
	if err := c.Validate(netip.MustParseAddr("192.0.2.3"), target); err != nil {
		t.Fatal(err)
	}
	if len(c.AllowedIPs) != 1 || c.AllowedIPs[0] != netip.MustParsePrefix("192.0.2.1/32") {
		t.Fatalf("default allowed IPs = %v", c.AllowedIPs)
	}
	ep := netip.MustParseAddrPort("[2001:db8::1]:443")
	u := c.UAPI(ep, 51820)
	for _, want := range []string{"private_key=" + privHex + "\n", "fwmark=51820\n", "endpoint=[2001:db8::1]:443\n", "allowed_ip=192.0.2.1/32\n"} {
		if !strings.Contains(u, want) {
			t.Errorf("UAPI lacks %q:\n%s", want, u)
		}
	}
	if strings.Index(u, "public_key=") > strings.Index(u, "endpoint=") {
		t.Errorf("endpoint must follow public_key in the creating IpcSet:\n%s", u)
	}

	c.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if err := c.Validate(netip.MustParseAddr("192.0.2.3"), target); err == nil {
		t.Error("target outside allowed_ip: want error")
	}
	if err := c.Validate(netip.MustParseAddr("2001:db8::3"), target); err == nil {
		t.Error("mixed families: want error")
	}
}

func TestCheckDevice(t *testing.T) {
	c, err := Parse(strings.NewReader("private_key=" + privHex + "\npublic_key=" + peerHex + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	peer := mustKey(t, peerHex)
	other := mustKey(t, pskHex)
	if err := c.CheckDevice(other, []wgtypes.Key{peer}); err != nil {
		t.Errorf("valid device: %v", err)
	}
	if err := c.CheckDevice(c.PublicKey, []wgtypes.Key{peer}); err == nil {
		t.Error("device shares the probe identity: want error")
	}
	if err := c.CheckDevice(other, []wgtypes.Key{other}); err == nil {
		t.Error("peer missing on device: want error")
	}
}
