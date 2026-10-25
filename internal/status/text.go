package status

import (
	"bytes"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bjin/wgsteer/internal/policy"
)

// historyLines is the number of recent switch events Lines renders.
const historyLines = 5

// Lines renders the snapshot as a human-readable table, one row per string,
// so a logger can emit one record per row. Rows never contain double quotes
// or newlines.
func (s *Status) Lines() []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	d := s.Daemon
	ver := d.Version
	if d.Revision != "" {
		ver += " (" + d.Revision + ")"
	}
	add("daemon: version=%s state=%s dry_run=%t pid=%d up=%s", ver, d.State, d.DryRun, d.PID, dur(s.At.Sub(d.StartTime)))

	dv := s.Device
	if dv.Present {
		where := "unlisted"
		switch {
		case dv.Listed:
			where = "listed"
		case dv.Alias:
			where = "alias"
		}
		add("device: %s %s listen_port=%d fwmark=%s endpoint=%s (%s) keepalive=%s handshake_age=%s rx=%s tx=%s",
			dv.Name, dv.Type, dv.ListenPort, mark(dv.Fwmark), ep(dv.Endpoint), where, dur(dv.Keepalive),
			age(dv.LastHandshake, dv.HandshakeAge), bytesIEC(dv.RxBytes), bytesIEC(dv.TxBytes))
	} else {
		add("device: %s absent", dv.Name)
	}

	sel := s.Selection
	idx := ""
	if sel.Index >= 0 {
		idx = fmt.Sprintf(" #%d", sel.Index)
	}
	verified := "n/a"
	if sel.Verified != nil {
		verified = fmt.Sprint(*sel.Verified)
	}
	add("selection: %s%s since %s (%s) reason=%s cooldown_left=%s aliases=%s verified=%s",
		ep(sel.Endpoint), idx, clock(sel.Since), dur(s.At.Sub(sel.Since)), clean(sel.Reason), dur(sel.CooldownLeft), eps(sel.Aliases), verified)
	if sel.Removed.IsValid() {
		add("selection: removed by reload %s", ep(sel.Removed))
	}
	if len(sel.RestoreLevels) > 0 {
		var parts []string
		for _, r := range sel.RestoreLevels {
			parts = append(parts, fmt.Sprintf("%s=%d", ep(r.Endpoint), r.Level))
		}
		add("restore levels: %s", strings.Join(parts, " "))
	}
	dec := sel.Decision
	if dec.Switch {
		add("decision: switch kind=%s to=%s reason=%s", dec.Kind, ep(dec.To), clean(dec.Reason))
	} else {
		add("decision: no switch blocker=%s reason=%s", orNone(string(dec.Blocker)), clean(dec.Reason))
	}
	for _, r := range sel.Rules {
		add("rule: %s", RuleText(r))
	}

	p := s.Probe
	sess := "none"
	if p.SessionValid {
		sess = "valid age=" + dur(p.SessionAge)
	} else if !p.LastHandshake.IsZero() {
		sess = "expired age=" + dur(p.SessionAge)
	}
	slot := "none"
	if p.Slot != nil {
		state := "done"
		if p.Slot.Pending {
			state = "pending"
		}
		slot = fmt.Sprintf("#%d %s seq=%d %s valid=%t", p.Slot.Index, ep(p.Slot.Endpoint), p.Slot.Seq, state, p.Slot.Valid)
	}
	add("probe: public_key=%s addr=%s target=%s listen_port=%d fwmark=%s session=%s slot=%s",
		p.PublicKey, p.ProbeAddr, p.Target, p.ListenPort, mark(p.Fwmark), sess, slot)

	out = append(out, s.endpointTable()...)

	n := s.NFT
	if n.Enabled {
		lastErr := "none"
		if n.LastError != "" {
			lastErr = clean(n.LastError) + " at " + clock(n.LastErrorAt)
		}
		add("nft: table=inet %s chain=%s owner_flag=%t owner=%d listen_port=%d denied=%d in_sync=%t last_error=%s",
			n.Table, n.Chain, n.OwnerFlag, n.Owner, n.ListenPort, len(n.Denied), n.InSync, lastErr)
		for _, c := range n.Denied {
			add("nft deny: %s packets=%d bytes=%d", ep(c.Endpoint), c.Packets, c.Bytes)
		}
	} else {
		add("nft: disabled (dry-run, no table)")
	}

	add("history: %d switch events", len(s.History))
	for _, e := range s.History[max(0, len(s.History)-historyLines):] {
		add("history: %s", EventText(e))
	}
	return out
}

func (s *Status) endpointTable() []string {
	var b bytes.Buffer
	tw := tabwriter.NewWriter(&b, 0, 0, 1, ' ', 0)
	fmt.Fprintln(tw, "endpoints:\t#\tendpoint\tfamily\tsel\tsamples\tinvalid\tloss±se\tlatency±se ms\trtt mean/std ms\tcost\tbiased\tG\teligible\tfresh\trun\tlevel\tlast sample\tdenied")
	for _, e := range s.Endpoints {
		sel := ""
		if e.Active {
			sel = "*"
		}
		g := "-"
		if e.Gate != nil {
			g = num(float64(e.Gate.G), 3)
		}
		last := "-"
		if e.Last != nil {
			if e.Last.Replied {
				last = fmt.Sprintf("%s %s ago", ms(e.Last.RTT), dur(s.At.Sub(e.Last.At)))
			} else {
				last = fmt.Sprintf("loss %s ago", dur(s.At.Sub(e.Last.At)))
			}
		}
		deny := "-"
		if e.Denied {
			deny = fmt.Sprintf("%d pkts", e.DenyPackets)
		}
		fmt.Fprintf(tw, "endpoints:\t%d\t%s\t%s\t%s\t%d\t%d\t%s±%s\t%s±%s\t%s/%s\t%s\t%s\t%s\t%t\t%t\t%d\t%d\t%s\t%s\n",
			e.Index, ep(e.Addr), e.Family, sel, e.Samples, e.Invalid,
			pct(float64(e.Loss)), pct(float64(e.LossSE)),
			num(float64(e.Latency), 1), num(float64(e.LatencySE), 1),
			num(float64(e.RTTMean), 1), num(float64(e.RTTStd), 1),
			num(float64(e.Cost), 1), num(float64(e.BiasedCost), 1), g,
			e.Eligible, e.Fresh, e.TrailingLosses, e.RestoreLevel, last, deny)
	}
	tw.Flush()
	return strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
}

// RuleText renders one rule's state on one line.
func RuleText(r policy.RuleState) string {
	var b strings.Builder
	b.WriteString(r.Rule)
	if r.Target.IsValid() {
		b.WriteString(" target=" + r.Target.String())
	}
	switch r.Rule {
	case policy.RuleOutage:
		fmt.Fprintf(&b, " run=%d/%d", r.Run, r.K)
	case policy.RuleDegrade, policy.RuleRestore:
		fmt.Fprintf(&b, " acc=%s/%s", dur(r.Value), dur(r.Hold))
	}
	if r.Rule == policy.RuleRestore {
		fmt.Fprintf(&b, " level=%d", r.Level)
	}
	fmt.Fprintf(&b, " active=%t fired=%t", r.Active, r.Fired)
	return b.String()
}

// EventText renders one switch event on one line.
func EventText(e SwitchEvent) string {
	s := fmt.Sprintf("#%d %s %s %s -> %s %s", e.ID, clock(e.At), e.Kind, ep(e.From), ep(e.To), e.Result)
	if e.BlockSetGap > 0 {
		s += " gap=" + num(float64(e.BlockSetGap)/float64(time.Millisecond), 3) + "ms"
	}
	if e.Error != "" {
		s += " error=" + clean(e.Error)
	}
	return s + " reason=" + clean(e.Reason)
}

func ep(a netip.AddrPort) string {
	if !a.IsValid() {
		return "none"
	}
	return a.String()
}

func eps(l []netip.AddrPort) string {
	if len(l) == 0 {
		return "none"
	}
	parts := make([]string, len(l))
	for i, a := range l {
		parts[i] = a.String()
	}
	return strings.Join(parts, ",")
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// clean keeps a free-text value on one row without double quotes.
func clean(s string) string {
	return strings.NewReplacer("\n", " ", "\"", "'").Replace(s)
}

func dur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d >= time.Minute:
		return d.Round(time.Second).String()
	case d >= time.Second:
		return d.Round(100 * time.Millisecond).String()
	}
	return d.Round(time.Millisecond).String()
}

func ms(d time.Duration) string {
	return num(float64(d)/float64(time.Millisecond), 1) + "ms"
}

func age(t time.Time, a time.Duration) string {
	if t.IsZero() {
		return "never"
	}
	return dur(a)
}

func clock(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02T15:04:05.000")
}

// mark renders a fwmark in decimal, as the startup report and wg-quick
// configurations do.
func mark(m uint32) string {
	return strconv.FormatUint(uint64(m), 10)
}

func num(x float64, prec int) string {
	switch {
	case math.IsInf(x, 1):
		return "inf"
	case math.IsInf(x, -1):
		return "-inf"
	case math.IsNaN(x):
		return "nan"
	}
	return fmt.Sprintf("%.*f", prec, x)
}

func pct(x float64) string {
	if math.IsInf(x, 0) || math.IsNaN(x) {
		return num(x, 1)
	}
	return fmt.Sprintf("%.1f%%", 100*x)
}

func bytesIEC(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
