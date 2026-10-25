// Package endpoints parses and normalizes the candidate endpoint list.
//
// The list has one literal endpoint per line: a.b.c.d:port for IPv4 and
// [addr]:port for IPv6. Blank lines and '#' comments are allowed. Earlier
// lines are preferred. Endpoints are always compared as normalized
// netip.AddrPort values, never as strings.
package endpoints

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
)

// Parse reads an endpoint list and returns the normalized endpoints in file
// order. Any invalid line or duplicate (after normalization) is an error that
// names the line.
func Parse(r io.Reader) ([]netip.AddrPort, error) {
	var list []netip.AddrPort
	seen := make(map[netip.AddrPort]int)
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ap, err := ParseOne(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if prev, ok := seen[ap]; ok {
			return nil, fmt.Errorf("line %d: duplicate endpoint %s (first on line %d)", lineNo, ap, prev)
		}
		seen[ap] = lineNo
		list = append(list, ap)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read endpoint list: %w", err)
	}
	return list, nil
}

// Load reads and parses an endpoint list file. An empty list is an error.
func Load(path string) ([]netip.AddrPort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open endpoint list: %w", err)
	}
	defer f.Close()
	list, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%s: %w", path, ErrEmpty)
	}
	return list, nil
}

// ParseOne parses a single literal endpoint. It rejects hostnames, zones,
// link-local and IPv4-mapped IPv6 addresses, unspecified and multicast
// addresses, IPv6 without brackets, and port 0.
func ParseOne(s string) (netip.AddrPort, error) {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: %w", s, err)
	}
	if strings.Contains(host, "%") {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: zones are not supported", s)
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		if _, perr := netip.ParseAddr(host); perr != nil {
			return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: not a literal IP address (hostnames are not supported)", s)
		}
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: %w", s, err)
	}
	addr := ap.Addr()
	switch {
	case addr.Is4In6():
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: IPv4-mapped IPv6 address; write it as IPv4", s)
	case addr.Is6() && !strings.HasPrefix(s, "["):
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: IPv6 needs brackets", s)
	case addr.Is6() && (addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast()):
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: link-local IPv6 needs a zone, which is not supported", s)
	case addr.IsUnspecified():
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: unspecified address", s)
	case addr.IsMulticast():
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: multicast address", s)
	case ap.Port() == 0:
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: port 0", s)
	}
	return Normalize(ap), nil
}

// Normalize unmaps IPv4-mapped IPv6 addresses and drops zones, so that values
// from wgctrl (which may carry 16-byte IPv4) compare equal to parsed ones.
func Normalize(ap netip.AddrPort) netip.AddrPort {
	if !ap.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}

// FromUDPAddr converts a wgctrl endpoint to a normalized AddrPort. It returns
// the zero value for nil or invalid addresses.
func FromUDPAddr(a *net.UDPAddr) netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	addr, ok := netip.AddrFromSlice(a.IP)
	if !ok || a.Port <= 0 || a.Port > 65535 {
		return netip.AddrPort{}
	}
	return Normalize(netip.AddrPortFrom(addr, uint16(a.Port)))
}

// ToUDPAddr converts a normalized AddrPort to a net.UDPAddr for wgctrl.
func ToUDPAddr(ap netip.AddrPort) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(ap)
}

// Family returns "ipv4" or "ipv6".
func Family(ap netip.AddrPort) string {
	if ap.Addr().Is4() {
		return "ipv4"
	}
	return "ipv6"
}

// Index returns the position of ap in list, or -1.
func Index(list []netip.AddrPort, ap netip.AddrPort) int {
	for i, e := range list {
		if e == ap {
			return i
		}
	}
	return -1
}

// ErrEmpty reports an endpoint list without entries.
var ErrEmpty = errors.New("no endpoints")
