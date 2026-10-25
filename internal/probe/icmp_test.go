package probe

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

var (
	v4Probe  = netip.MustParseAddr("192.0.2.7")
	v4Target = netip.MustParseAddr("192.0.2.1")
	v6Probe  = netip.MustParseAddr("2001:db8::7")
	v6Target = netip.MustParseAddr("2001:db8::1")
)

// onesSum is an independent RFC 1071 ones' complement sum with end-around
// carry after every word. A range including a correct checksum sums to 0xffff.
func onesSum(b []byte) uint16 {
	var s uint16
	for i := 0; i < len(b); i += 2 {
		w := uint16(b[i]) << 8
		if i+1 < len(b) {
			w |= uint16(b[i+1])
		}
		t := uint32(s) + uint32(w)
		s = uint16(t) + uint16(t>>16)
	}
	return s
}

// verifyChecksums checks the IPv4 header checksum and the ICMP checksum
// (ICMPv6 with an explicitly built pseudo-header).
func verifyChecksums(t *testing.T, pkt []byte) {
	t.Helper()
	if pkt[0]>>4 == 4 {
		if got := onesSum(pkt[:20]); got != 0xffff {
			t.Errorf("IPv4 header sum = %#04x, want 0xffff", got)
		}
		if got := onesSum(pkt[20:]); got != 0xffff {
			t.Errorf("ICMP sum = %#04x, want 0xffff", got)
		}
		return
	}
	icmp := pkt[40:]
	var ph []byte
	ph = append(ph, pkt[8:40]...) // source and destination
	ph = binary.BigEndian.AppendUint32(ph, uint32(len(icmp)))
	ph = append(ph, 0, 0, 0, 58)
	if got := onesSum(append(ph, icmp...)); got != 0xffff {
		t.Errorf("ICMPv6 sum with pseudo-header = %#04x, want 0xffff", got)
	}
	if onesSum(icmp) == 0xffff {
		t.Errorf("ICMPv6 checksum ignores the pseudo-header")
	}
}

// echoReplyOf turns an echo request into the reply a server would send.
func echoReplyOf(t *testing.T, req []byte) []byte {
	t.Helper()
	pkt, ok := echoReply(req)
	if !ok {
		t.Fatalf("not an echo request: % x", req)
	}
	return pkt
}

func TestEchoChecksums(t *testing.T) {
	for _, tc := range []struct {
		name     string
		src, dst netip.Addr
		size     int
	}{
		{"v4", v4Probe, v4Target, 56},
		{"v4 odd payload", v4Probe, v4Target, 57},
		{"v6", v6Probe, v6Target, 56},
		{"v6 odd payload", v6Probe, v6Target, 21},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := echoFields{ID: 0xbeef, Seq: 0xfffe, Nonce: 0x0123456789abcdef, EndpointID: 0xdeadbeef}
			pkt := buildEcho(tc.src, tc.dst, f, tc.size)
			if want := ipHeaderLen(tc.src) + 8 + tc.size; len(pkt) != want {
				t.Fatalf("len = %d, want %d", len(pkt), want)
			}
			verifyChecksums(t, pkt)
			stampEcho(pkt, 1234567*time.Microsecond)
			verifyChecksums(t, pkt)

			reply := echoReplyOf(t, pkt)
			verifyChecksums(t, reply)
			got, ok := parseEchoReply(reply, tc.dst, f.ID)
			if !ok {
				t.Fatal("valid reply rejected")
			}
			f.SentAt = 1234567 * time.Microsecond
			if got != f {
				t.Errorf("parsed %+v, want %+v", got, f)
			}
		})
	}
}

func TestBuildEchoHeaders(t *testing.T) {
	v4 := buildEcho(v4Probe, v4Target, echoFields{ID: 1, Seq: 2}, 56)
	if v4[0] != 0x45 || v4[9] != 1 || v4[20] != 8 || binary.BigEndian.Uint16(v4[2:]) != 84 {
		t.Errorf("bad IPv4 echo request header: % x", v4[:28])
	}
	if netip.AddrFrom4([4]byte(v4[12:16])) != v4Probe || netip.AddrFrom4([4]byte(v4[16:20])) != v4Target {
		t.Errorf("bad IPv4 addresses")
	}
	v6 := buildEcho(v6Probe, v6Target, echoFields{ID: 1, Seq: 2}, 56)
	if v6[0]>>4 != 6 || v6[6] != 58 || v6[40] != 128 || binary.BigEndian.Uint16(v6[4:]) != 64 {
		t.Errorf("bad IPv6 echo request header: % x", v6[:48])
	}
	if netip.AddrFrom16([16]byte(v6[8:24])) != v6Probe || netip.AddrFrom16([16]byte(v6[24:40])) != v6Target {
		t.Errorf("bad IPv6 addresses")
	}
}

func TestParseEchoReplyRejects(t *testing.T) {
	const id = 0x4242
	f := echoFields{ID: id, Seq: 7, Nonce: 99, EndpointID: 5}
	type rejectCase struct {
		name   string
		pkt    func() []byte
		target netip.Addr
	}
	for _, fam := range []struct {
		name     string
		src, dst netip.Addr
		other    netip.Addr // same family, not the target
		otherFam netip.Addr // the target's counterpart in the other family
	}{
		{"v4", v4Probe, v4Target, netip.MustParseAddr("192.0.2.9"), v6Target},
		{"v6", v6Probe, v6Target, netip.MustParseAddr("2001:db8::9"), v4Target},
	} {
		v4 := fam.src.Is4()
		hl := ipHeaderLen(fam.src)
		good := func() []byte { return echoReplyOf(t, buildEcho(fam.src, fam.dst, f, 56)) }
		// refix restores valid checksums after a mutation.
		refix := func(p []byte) []byte {
			if v4 {
				p[10], p[11] = 0, 0
				binary.BigEndian.PutUint16(p[10:], fold(sum16(p[:20], 0)))
			}
			setICMPChecksum(p)
			return p
		}
		cases := []rejectCase{
			{"wrong identifier", func() []byte {
				p := good()
				binary.BigEndian.PutUint16(p[hl+4:], id+1)
				return refix(p)
			}, fam.dst},
			{"wrong source", func() []byte {
				p := good()
				if v4 {
					a := fam.other.As4()
					copy(p[12:16], a[:])
				} else {
					a := fam.other.As16()
					copy(p[8:24], a[:])
				}
				return refix(p)
			}, fam.dst},
			{"echo request instead of reply", func() []byte {
				return buildEcho(fam.dst, fam.src, f, 56)
			}, fam.dst},
			{"other ICMP type", func() []byte {
				p := good()
				p[hl] = 3 // v4 destination unreachable; v6 time exceeded
				return refix(p)
			}, fam.dst},
			{"nonzero code", func() []byte {
				p := good()
				p[hl+1] = 1
				return refix(p)
			}, fam.dst},
			{"bad ICMP checksum", func() []byte {
				p := good()
				p[len(p)-1] ^= 0xff
				return p
			}, fam.dst},
			{"truncated payload", func() []byte {
				p := echoReplyOf(t, buildEcho(fam.src, fam.dst, f, 56))
				short := p[:hl+8+MinPayloadSize-1]
				if v4 {
					binary.BigEndian.PutUint16(short[2:], uint16(len(short)))
				} else {
					binary.BigEndian.PutUint16(short[4:], uint16(len(short)-40))
				}
				return refix(short)
			}, fam.dst},
			{"length beyond buffer", func() []byte {
				p := good()
				return p[:len(p)-1]
			}, fam.dst},
			{"other protocol", func() []byte {
				p := good()
				if v4 {
					p[9] = 17
				} else {
					p[6] = 17
				}
				return refix(p)
			}, fam.dst},
			{"family mismatch", good, fam.otherFam},
			{"empty", func() []byte { return nil }, fam.dst},
		}
		if v4 {
			cases = append(cases,
				rejectCase{"fragment", func() []byte {
					p := good()
					p[6] |= 0x20 // more fragments
					return refix(p)
				}, fam.dst},
				rejectCase{"bad IPv4 header checksum", func() []byte {
					p := good()
					p[10] ^= 0xff
					return p
				}, fam.dst},
			)
		}
		for _, tc := range cases {
			t.Run(fam.name+"/"+tc.name, func(t *testing.T) {
				if _, ok := parseEchoReply(tc.pkt(), tc.target, id); ok {
					t.Error("accepted")
				}
			})
		}
		t.Run(fam.name+"/trailing bytes after the IP length are ignored", func(t *testing.T) {
			p := append(good(), 0xaa, 0xbb)
			if _, ok := parseEchoReply(p, fam.dst, id); !ok {
				t.Error("rejected")
			}
		})
	}
}
