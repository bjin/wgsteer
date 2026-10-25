package endpoints

import (
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestParseList(t *testing.T) {
	in := `# relays
192.0.2.1:51820
  [2001:DB8:0::1]:443   # v6 relay

127.0.0.1:4000
198.51.100.7:51820
`
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:51820"),
		netip.MustParseAddrPort("[2001:db8::1]:443"),
		netip.MustParseAddrPort("127.0.0.1:4000"),
		netip.MustParseAddrPort("198.51.100.7:51820"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %v, want %v", i, got[i], want[i])
		}
	}
}

func TestParseOneRejects(t *testing.T) {
	for _, s := range []string{
		"relay.example.com:51820",
		"192.0.2.1",
		"192.0.2.1:0",
		"192.0.2.1:70000",
		"2001:db8::1:51820",
		"[fe80::1]:51820",
		"[fe80::1%eth0]:51820",
		"[ff02::1]:51820",
		"[::ffff:192.0.2.1]:51820",
		"0.0.0.0:51820",
		"[::]:51820",
		"224.0.0.1:51820",
		"01.2.3.4:51820",
	} {
		if ap, err := ParseOne(s); err == nil {
			t.Errorf("ParseOne(%q) = %v, want error", s, ap)
		}
	}
}

func TestParseDuplicateAfterNormalization(t *testing.T) {
	in := "[2001:db8::1]:443\n[2001:DB8:0:0::1]:443\n"
	_, err := Parse(strings.NewReader(in))
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("err = %v, want duplicate on line 2", err)
	}
}

func TestParseErrorNamesLine(t *testing.T) {
	_, err := Parse(strings.NewReader("192.0.2.1:1\n\nhost:2\n"))
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("err = %v, want error on line 3", err)
	}
}

func TestFromUDPAddrUnmaps(t *testing.T) {
	// wgctrl may report IPv4 endpoints as 16-byte addresses.
	a := &net.UDPAddr{IP: net.ParseIP("192.0.2.1").To16(), Port: 51820}
	if len(a.IP) != net.IPv6len {
		t.Fatal("test needs a 16-byte IPv4 address")
	}
	want := netip.MustParseAddrPort("192.0.2.1:51820")
	if got := FromUDPAddr(a); got != want {
		t.Fatalf("FromUDPAddr = %v, want %v", got, want)
	}
	if got := FromUDPAddr(nil); got.IsValid() {
		t.Fatalf("FromUDPAddr(nil) = %v, want invalid", got)
	}
}
