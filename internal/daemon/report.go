package daemon

import (
	"fmt"
	"math"
	"net/netip"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/bjin/wgsteer/internal/nftable"
	"github.com/bjin/wgsteer/internal/policy"
)

// buildInfo identifies the binary for the startup report and snapshot.
type buildInfo struct {
	version, revision, goVersion string
}

func readBuildInfo() buildInfo {
	b := buildInfo{version: "(devel)", goVersion: runtime.Version()}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return b
	}
	if info.Main.Version != "" {
		b.version = info.Main.Version
	}
	modified := false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			b.revision = s.Value[:min(12, len(s.Value))]
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if modified && b.revision != "" {
		b.revision += "-dirty"
	}
	return b
}

// Version renders the build for --version, e.g.
// "wgsteer v0.1.0 (99e63646c2a9, go1.26.2, linux/arm64)".
func Version() string {
	b := readBuildInfo()
	rev := ""
	if b.revision != "" {
		rev = b.revision + ", "
	}
	return fmt.Sprintf("wgsteer %s (%s%s, %s/%s)", b.version, rev, b.goVersion, runtime.GOOS, runtime.GOARCH)
}

func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "unknown"
	}
	return unix.ByteSliceToString(u.Release[:])
}

// reportHeader emits the first startup report lines: build, runtime
// and the effective configuration.
func (d *daemon) reportHeader() {
	d.log.Info("starting", "version", d.build.version, "revision", d.build.revision, "go_version", d.build.goVersion,
		"kernel", kernelRelease(), "pid", os.Getpid())
	d.log.Info("config", d.cfg.attrs()...)
}

// trace logs the per-tick decision trace at debug.
func (d *daemon) trace(dec policy.Decision) {
	for _, v := range dec.Record.Endpoints {
		d.log.Debug("trace endpoint", endpointAttrs(v)...)
	}
	for _, r := range dec.Record.Rules {
		d.log.Debug("trace rule", ruleAttrs(r)...)
	}
	d.log.Debug("trace decision", "switch", dec.Switch, "kind", string(dec.Kind), "to", epAttr(dec.To),
		"blocker", string(dec.Blocker), "reason", dec.Reason,
		"cooldown_left", dec.Record.CooldownLeft.Round(time.Millisecond), "gap", dec.Record.Gap)
}

// endpointAttrs renders one endpoint view of a decision record.
func endpointAttrs(v policy.EndpointView) []any {
	a := []any{"endpoint", v.Addr, "index", v.Index, "name", v.Name, "active", v.Active, "samples", v.Samples, "replies", v.Replies,
		"invalid", v.Invalid, "loss", round(float64(v.Loss)), "loss_se", round(float64(v.LossSE)),
		"latency_ms", round(float64(v.Latency)), "latency_se_ms", round(float64(v.LatencySE)),
		"rtt_mean_ms", round(float64(v.RTTMean)), "rtt_std_ms", round(float64(v.RTTStd)),
		"loss_factor", round(float64(v.LossFactor)), "cost", round(float64(v.Cost)), "biased_cost", round(float64(v.BiasedCost))}
	if g := v.Gate; g != nil {
		a = append(a, gateAttrs(g)...)
	}
	return append(a, "eligible", v.Eligible, "fresh", v.Fresh, "trailing_losses", v.TrailingLosses, "restore_level", v.RestoreLevel)
}

// gateAttrs renders a gated comparison G(active→candidate) with every term
// it is made of: G = exp(r_lat_gated + r_loss_gated) · bias.
func gateAttrs(g *policy.Gated) []any {
	return []any{"g", round(float64(g.G)), "r_lat", round(float64(g.RLat)), "s_lat", round(float64(g.SLat)),
		"r_lat_gated", round(float64(g.RLatGated)), "r_loss", round(float64(g.RLoss)), "s_loss", round(float64(g.SLoss)),
		"r_loss_gated", round(float64(g.RLossGated)), "bias", round(float64(g.Bias))}
}

// ruleAttrs renders one rule state of a decision record.
func ruleAttrs(r policy.RuleState) []any {
	a := []any{"rule", r.Rule, "target", epAttr(r.Target)}
	switch r.Rule {
	case policy.RuleOutage:
		a = append(a, "run", r.Run, "k", r.K)
	case policy.RuleDegrade:
		a = append(a, "value", r.Value, "hold", r.Hold)
	case policy.RuleRestore:
		a = append(a, "value", r.Value, "hold", r.Hold, "level", r.Level)
	}
	return append(a, "active", r.Active, "fired", r.Fired)
}

// summary logs one line per endpoint from the snapshot.
func (d *daemon) summary() {
	s := d.snap.Load()
	for _, e := range s.Endpoints {
		d.log.Info("summary", "endpoint", e.Addr, "index", e.Index, "name", e.Name, "selected", e.Active,
			"loss", round(float64(e.Loss)), "rtt_mean_ms", round(float64(e.RTTMean)), "rtt_std_ms", round(float64(e.RTTStd)),
			"cost", round(float64(e.Cost)), "valid", e.Samples, "invalid", e.Invalid,
			"eligible", e.Eligible, "fresh", e.Fresh, "deny_packets", e.DenyPackets)
	}
}

// dump logs the snapshot as a table, one record per row (SIGUSR1).
func (d *daemon) dump() {
	for _, row := range d.snap.Load().Lines() {
		d.log.Info("status", "row", row)
	}
}

// epAttr renders an endpoint, "none" for the zero value.
func epAttr(ap netip.AddrPort) string {
	if !ap.IsValid() {
		return "none"
	}
	return ap.String()
}

func epsAttr(l []netip.AddrPort) string {
	if len(l) == 0 {
		return "none"
	}
	parts := make([]string, len(l))
	for i, ap := range l {
		parts[i] = ap.String()
	}
	return strings.Join(parts, ",")
}

// countersAttr renders drop counters as endpoint=packets/bytes.
func countersAttr(cs []nftable.Counter) string {
	if len(cs) == 0 {
		return "none"
	}
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = c.Addr.String() + "=" + strconv.FormatUint(c.Packets, 10) + "/" + strconv.FormatUint(c.Bytes, 10)
	}
	return strings.Join(parts, ",")
}

func timeAttr(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format(time.RFC3339Nano)
}

// msAttr renders a duration in milliseconds with microsecond precision.
func msAttr(d time.Duration) float64 {
	return math.Round(float64(d)/1e3) / 1e3
}

// round keeps four decimals; non-finite values pass through.
func round(x float64) float64 {
	if math.IsInf(x, 0) || math.IsNaN(x) {
		return x
	}
	return math.Round(x*1e4) / 1e4
}

func itoa(i int) string { return strconv.Itoa(i) }
