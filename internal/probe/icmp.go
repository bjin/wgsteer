package probe

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// MinPayloadSize is the smallest ICMP payload that holds the probe fields:
// nonce (8 bytes), endpoint id (4 bytes) and send timestamp (8 bytes).
const MinPayloadSize = payloadSentAt + 8

const (
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
	icmpHeaderLen = 8

	protoICMP   = 1
	protoICMPv6 = 58

	icmpv4EchoReply   = 0
	icmpv4EchoRequest = 8
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129

	// Payload layout, offsets relative to the start of the ICMP payload.
	payloadNonce      = 0
	payloadEndpointID = 8
	payloadSentAt     = 12

	defaultTTL = 64
)

// echoFields are the probe fields carried by an echo request and its reply.
type echoFields struct {
	ID         uint16
	Seq        uint16
	Nonce      uint64
	EndpointID uint32
	SentAt     time.Duration // monotonic offset since probe start, stamped at TUN Read
}

// ipHeaderLen returns the IP header length of a packet built by buildEcho.
func ipHeaderLen(src netip.Addr) int {
	if src.Is4() {
		return ipv4HeaderLen
	}
	return ipv6HeaderLen
}

// buildEcho crafts an ICMP (IPv4) or ICMPv6 (IPv6) echo request from src to
// dst with payloadSize payload bytes. src and dst must be the same family and
// payloadSize at least MinPayloadSize. SentAt is written as given; stampEcho
// overwrites it at send time.
func buildEcho(src, dst netip.Addr, f echoFields, payloadSize int) []byte {
	hl := ipHeaderLen(src)
	pkt := make([]byte, hl+icmpHeaderLen+payloadSize)
	icmp := pkt[hl:]
	if src.Is4() {
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
		binary.BigEndian.PutUint16(pkt[4:6], f.Seq)
		pkt[8] = defaultTTL
		pkt[9] = protoICMP
		s, d := src.As4(), dst.As4()
		copy(pkt[12:16], s[:])
		copy(pkt[16:20], d[:])
		binary.BigEndian.PutUint16(pkt[10:12], fold(sum16(pkt[:ipv4HeaderLen], 0)))
		icmp[0] = icmpv4EchoRequest
	} else {
		pkt[0] = 0x60
		binary.BigEndian.PutUint16(pkt[4:6], uint16(len(icmp)))
		pkt[6] = protoICMPv6
		pkt[7] = defaultTTL
		s, d := src.As16(), dst.As16()
		copy(pkt[8:24], s[:])
		copy(pkt[24:40], d[:])
		icmp[0] = icmpv6EchoRequest
	}
	binary.BigEndian.PutUint16(icmp[4:6], f.ID)
	binary.BigEndian.PutUint16(icmp[6:8], f.Seq)
	payload := icmp[icmpHeaderLen:]
	binary.BigEndian.PutUint64(payload[payloadNonce:], f.Nonce)
	binary.BigEndian.PutUint32(payload[payloadEndpointID:], f.EndpointID)
	binary.BigEndian.PutUint64(payload[payloadSentAt:], uint64(f.SentAt))
	setICMPChecksum(pkt)
	return pkt
}

// stampEcho writes the send timestamp into an echo request built by
// buildEcho and recomputes its ICMP checksum.
func stampEcho(pkt []byte, sentAt time.Duration) {
	hl, ok := echoHeaderLen(pkt)
	if !ok {
		return
	}
	binary.BigEndian.PutUint64(pkt[hl+icmpHeaderLen+payloadSentAt:], uint64(sentAt))
	setICMPChecksum(pkt)
}

// echoHeaderLen returns the IP header length of a packet built by buildEcho,
// and whether the packet is long enough to carry the probe payload.
func echoHeaderLen(pkt []byte) (int, bool) {
	if len(pkt) == 0 {
		return 0, false
	}
	hl := ipv6HeaderLen
	if pkt[0]>>4 == 4 {
		hl = ipv4HeaderLen
	}
	return hl, len(pkt) >= hl+icmpHeaderLen+MinPayloadSize
}

// setICMPChecksum recomputes the ICMP checksum of a packet built by
// buildEcho. ICMPv6 includes the IPv6 pseudo-header.
func setICMPChecksum(pkt []byte) {
	hl, _ := echoHeaderLen(pkt)
	icmp := pkt[hl:]
	icmp[2], icmp[3] = 0, 0
	var acc uint32
	if hl == ipv6HeaderLen {
		acc = pseudoHeaderSum(pkt[8:24], pkt[24:40], len(icmp))
	}
	binary.BigEndian.PutUint16(icmp[2:4], fold(sum16(icmp, acc)))
}

// parseEchoReply accepts only an unfragmented ICMP echo reply (IPv4) or
// ICMPv6 echo reply (IPv6) from target with identifier id, valid checksums
// and a probe payload. Everything else returns false.
func parseEchoReply(pkt []byte, target netip.Addr, id uint16) (echoFields, bool) {
	var icmp []byte
	switch {
	case len(pkt) >= ipv4HeaderLen && pkt[0]>>4 == 4:
		hl := int(pkt[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(pkt[2:4]))
		if hl < ipv4HeaderLen || total < hl || total > len(pkt) {
			return echoFields{}, false
		}
		pkt = pkt[:total]
		if pkt[9] != protoICMP || binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
			return echoFields{}, false // not ICMP, or a fragment
		}
		if netip.AddrFrom4([4]byte(pkt[12:16])) != target {
			return echoFields{}, false
		}
		if fold(sum16(pkt[:hl], 0)) != 0 {
			return echoFields{}, false
		}
		icmp = pkt[hl:]
		if len(icmp) < icmpHeaderLen || icmp[0] != icmpv4EchoReply || icmp[1] != 0 {
			return echoFields{}, false
		}
		if fold(sum16(icmp, 0)) != 0 {
			return echoFields{}, false
		}
	case len(pkt) >= ipv6HeaderLen && pkt[0]>>4 == 6:
		plen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if ipv6HeaderLen+plen > len(pkt) {
			return echoFields{}, false
		}
		pkt = pkt[:ipv6HeaderLen+plen]
		if pkt[6] != protoICMPv6 {
			return echoFields{}, false // extension headers are not expected on echo replies
		}
		if netip.AddrFrom16([16]byte(pkt[8:24])) != target {
			return echoFields{}, false
		}
		icmp = pkt[ipv6HeaderLen:]
		if len(icmp) < icmpHeaderLen || icmp[0] != icmpv6EchoReply || icmp[1] != 0 {
			return echoFields{}, false
		}
		if fold(sum16(icmp, pseudoHeaderSum(pkt[8:24], pkt[24:40], len(icmp)))) != 0 {
			return echoFields{}, false
		}
	default:
		return echoFields{}, false
	}
	if len(icmp) < icmpHeaderLen+MinPayloadSize {
		return echoFields{}, false
	}
	f := echoFields{
		ID:  binary.BigEndian.Uint16(icmp[4:6]),
		Seq: binary.BigEndian.Uint16(icmp[6:8]),
	}
	if f.ID != id {
		return echoFields{}, false
	}
	payload := icmp[icmpHeaderLen:]
	f.Nonce = binary.BigEndian.Uint64(payload[payloadNonce:])
	f.EndpointID = binary.BigEndian.Uint32(payload[payloadEndpointID:])
	f.SentAt = time.Duration(binary.BigEndian.Uint64(payload[payloadSentAt:]))
	return f, true
}

// pseudoHeaderSum is the unfolded sum of the IPv6 pseudo-header for an
// ICMPv6 message of length n (RFC 8200 section 8.1).
func pseudoHeaderSum(src, dst []byte, n int) uint32 {
	acc := sum16(src, 0)
	acc = sum16(dst, acc)
	return acc + uint32(n>>16) + uint32(n&0xffff) + protoICMPv6
}

// sum16 adds b as big-endian 16-bit words to acc (odd length padded with a
// zero byte). Packets are bounded by the MTU, so acc cannot overflow.
func sum16(b []byte, acc uint32) uint32 {
	for len(b) >= 2 {
		acc += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint32(b[0]) << 8
	}
	return acc
}

// fold folds a sum to 16 bits and returns its ones' complement: the value to
// store as a checksum, or 0 when verifying a range that includes a correct
// checksum.
func fold(acc uint32) uint16 {
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return ^uint16(acc)
}
