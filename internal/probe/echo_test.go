package probe

import (
	"encoding/binary"
)

// echoReply builds the reply a server's IP stack sends for an ICMP or
// ICMPv6 echo request: addresses swapped, type changed, payload copied,
// checksums recomputed. Anything that is not an echo request returns false.
func echoReply(req []byte) ([]byte, bool) {
	if len(req) == 0 {
		return nil, false
	}
	pkt := append([]byte(nil), req...)
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < ipv4HeaderLen+icmpHeaderLen {
			return nil, false
		}
		hl := int(pkt[0]&0x0f) * 4
		if hl < ipv4HeaderLen || len(pkt) < hl+icmpHeaderLen || pkt[9] != protoICMP || pkt[hl] != icmpv4EchoRequest {
			return nil, false
		}
		var src [4]byte
		copy(src[:], pkt[12:16])
		copy(pkt[12:16], pkt[16:20])
		copy(pkt[16:20], src[:])
		pkt[10], pkt[11] = 0, 0
		binary.BigEndian.PutUint16(pkt[10:12], fold(sum16(pkt[:hl], 0)))
		icmp := pkt[hl:]
		icmp[0] = icmpv4EchoReply
		icmp[2], icmp[3] = 0, 0
		binary.BigEndian.PutUint16(icmp[2:4], fold(sum16(icmp, 0)))
	case 6:
		if len(pkt) < ipv6HeaderLen+icmpHeaderLen || pkt[6] != protoICMPv6 || pkt[ipv6HeaderLen] != icmpv6EchoRequest {
			return nil, false
		}
		var src [16]byte
		copy(src[:], pkt[8:24])
		copy(pkt[8:24], pkt[24:40])
		copy(pkt[24:40], src[:])
		icmp := pkt[ipv6HeaderLen:]
		icmp[0] = icmpv6EchoReply
		icmp[2], icmp[3] = 0, 0
		binary.BigEndian.PutUint16(icmp[2:4], fold(sum16(icmp, pseudoHeaderSum(pkt[8:24], pkt[24:40], len(icmp)))))
	default:
		return nil, false
	}
	return pkt, true
}
