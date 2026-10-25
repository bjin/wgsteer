package nftable

import (
	"net/netip"
	"slices"

	"github.com/bjin/wgsteer/internal/endpoints"
)

// Ruleset is the complete desired content of the daemon's chain: one drop
// rule per denied source tuple, all matching the live listen port.
type Ruleset struct {
	ListenPort uint16
	Denied     []netip.AddrPort
}

// Desired computes the deny-list: every listed candidate except
// the selected one, plus the aliases being switched away from. A zero
// selected (no selection) denies every listed candidate. The selected
// endpoint is never denied, even if it also appears in aliases. Entries are
// normalized, deduplicated and sorted (IPv4 before IPv6, then by address and
// port), so equal inputs always give identical rule order.
func Desired(listed []netip.AddrPort, selected netip.AddrPort, aliases []netip.AddrPort, listenPort uint16) Ruleset {
	selected = endpoints.Normalize(selected)
	denied := make([]netip.AddrPort, 0, len(listed)+len(aliases))
	for _, list := range [][]netip.AddrPort{listed, aliases} {
		for _, ap := range list {
			ap = endpoints.Normalize(ap)
			if ap == selected {
				continue
			}
			denied = append(denied, ap)
		}
	}
	return Ruleset{ListenPort: listenPort, Denied: canonical(denied)}
}

// Equal reports whether r and o produce the same rules. Denied lists compare
// as sets of normalized endpoints. Two rulesets without denied endpoints are
// equal regardless of the listen port, because both mean an empty chain.
func (r Ruleset) Equal(o Ruleset) bool {
	a, b := r.canonical(), o.canonical()
	if len(a.Denied) == 0 && len(b.Denied) == 0 {
		return true
	}
	return a.ListenPort == b.ListenPort && slices.Equal(a.Denied, b.Denied)
}

// canonical returns a copy with normalized, valid, deduplicated and sorted
// denied endpoints. Apply installs rules in this order.
func (r Ruleset) canonical() Ruleset {
	return Ruleset{ListenPort: r.ListenPort, Denied: canonical(r.Denied)}
}

func canonical(list []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(list))
	for _, ap := range list {
		ap = endpoints.Normalize(ap)
		if !ap.IsValid() {
			continue
		}
		out = append(out, ap)
	}
	slices.SortFunc(out, netip.AddrPort.Compare)
	return slices.Compact(out)
}
