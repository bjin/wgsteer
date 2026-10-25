package daemon

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/bjin/wgsteer/internal/policy"
	"github.com/bjin/wgsteer/internal/probe"
)

// Config holds every command-line setting.
type Config struct {
	Device      string
	ProbeConfig string
	Endpoints   string
	ProbeAddr   netip.Addr
	Target      netip.Addr

	ProbeInterval     time.Duration
	ProbeTimeout      time.Duration
	ProbeSize         int
	ProbeMTU          int
	History           int
	HalfLife          float64
	MinSamples        int
	NoiseGate         float64
	LossWeight        float64
	JitterWeight      float64
	OrderBias         float64
	Margin            float64
	MarginAbs         time.Duration
	Persist           time.Duration
	Cooldown          time.Duration
	WaitToRestore     time.Duration
	OutageEpsilon     float64
	ReconcileInterval time.Duration
	Kick              bool
	NftTable          string
	DryRun            bool
	LogLevel          slog.Level
	LogDir            string
	LogMaxAge         time.Duration
	SummaryInterval   time.Duration
	Watchdog          time.Duration
}

// DefaultConfig returns the defaults of every tunable. The
// scoring constants come from policy.DefaultParams, the package that owns
// their tuning.
func DefaultConfig() Config {
	p := policy.DefaultParams()
	return Config{
		ProbeInterval:     p.Interval,
		ProbeTimeout:      500 * time.Millisecond,
		ProbeSize:         56,
		ProbeMTU:          probe.DefaultMTU,
		History:           p.History,
		HalfLife:          p.HalfLife,
		MinSamples:        p.MinSamples,
		NoiseGate:         p.NoiseGate,
		LossWeight:        p.LossWeight,
		JitterWeight:      p.JitterWeight,
		OrderBias:         p.OrderBias,
		Margin:            p.Margin,
		MarginAbs:         p.MarginAbs,
		Persist:           p.Persist,
		Cooldown:          p.Cooldown,
		WaitToRestore:     p.WaitToRestore,
		OutageEpsilon:     p.OutageEpsilon,
		ReconcileInterval: time.Second,
		Kick:              true,
		LogLevel:          slog.LevelInfo,
		LogMaxAge:         7 * 24 * time.Hour,
		SummaryInterval:   10 * time.Minute,
		Watchdog:          15 * time.Second,
	}
}

// Params maps the configuration to the policy parameters.
func (c *Config) Params() policy.Params {
	return policy.Params{
		Interval:      c.ProbeInterval,
		Persist:       c.Persist,
		Cooldown:      c.Cooldown,
		WaitToRestore: c.WaitToRestore,
		MarginAbs:     c.MarginAbs,
		History:       c.History,
		MinSamples:    c.MinSamples,
		HalfLife:      c.HalfLife,
		NoiseGate:     c.NoiseGate,
		LossWeight:    c.LossWeight,
		JitterWeight:  c.JitterWeight,
		OrderBias:     c.OrderBias,
		Margin:        c.Margin,
		OutageEpsilon: c.OutageEpsilon,
	}
}

// attrs lists every effective setting for the startup report.
func (c *Config) attrs() []any {
	return []any{
		"device", c.Device, "probe_config", c.ProbeConfig, "endpoints", c.Endpoints,
		"probe_addr", c.ProbeAddr, "target", c.Target,
		"probe_interval", c.ProbeInterval, "probe_timeout", c.ProbeTimeout, "probe_size", c.ProbeSize, "probe_mtu", c.ProbeMTU,
		"history", c.History, "half_life", c.HalfLife, "min_samples", c.MinSamples,
		"noise_gate", c.NoiseGate, "loss_weight", c.LossWeight, "jitter_weight", c.JitterWeight,
		"order_bias", c.OrderBias, "margin", c.Margin, "margin_abs", c.MarginAbs,
		"persist", c.Persist, "cooldown", c.Cooldown, "wait_to_restore", c.WaitToRestore,
		"outage_epsilon", c.OutageEpsilon, "reconcile_interval", c.ReconcileInterval,
		"kick", c.Kick, "nft_table", c.NftTable, "dry_run", c.DryRun, "log_level", c.LogLevel.String(),
		"log_dir", c.LogDir, "log_max_age", c.LogMaxAge, "summary_interval", c.SummaryInterval, "watchdog", c.Watchdog,
	}
}

// ErrVersion is returned by ParseFlags when --version is given; the caller
// prints Version and exits.
var ErrVersion = errors.New("version requested")

// ParseFlags parses the command line into a validated Config. Defaults for
// the scoring constants come from defaults, so the policy package stays the
// single source of truth for them.
func ParseFlags(args []string, defaults Config, output io.Writer) (Config, error) {
	c := defaults
	fs := flag.NewFlagSet("wgsteer", flag.ContinueOnError)
	fs.SetOutput(output)
	var probeAddr, target, logLevel string

	fs.StringVar(&c.Device, "device", c.Device, "live WireGuard device (required)")
	fs.StringVar(&c.ProbeConfig, "probe-config", c.ProbeConfig, "probe identity in xplatform UAPI set format (required)")
	fs.StringVar(&c.Endpoints, "endpoints", c.Endpoints, "candidate endpoint list, one ip:port per line, earlier preferred (required)")
	fs.StringVar(&probeAddr, "probe-addr", "", "probe tunnel address, source of the probe ICMP (required)")
	fs.StringVar(&target, "target", "", "server tunnel address, destination of the probe ICMP (required)")

	fs.DurationVar(&c.ProbeInterval, "probe-interval", c.ProbeInterval, "probe slot length; endpoints are probed round-robin, one per slot")
	fs.DurationVar(&c.ProbeTimeout, "probe-timeout", c.ProbeTimeout, "maximum RTT counted as a reply (< probe-interval)")
	fs.IntVar(&c.ProbeSize, "probe-size", c.ProbeSize, "ICMP payload bytes (at most --probe-mtu minus 28 for IPv4, 48 for IPv6)")
	fs.IntVar(&c.ProbeMTU, "probe-mtu", c.ProbeMTU, "MTU of the probe's tunnel device; set it to the live device's MTU to probe with full-size packets")
	fs.IntVar(&c.History, "history", c.History, "valid samples kept per endpoint")
	fs.Float64Var(&c.HalfLife, "half-life", c.HalfLife, "recency weighting half-life, in samples of that endpoint")
	fs.IntVar(&c.MinSamples, "min-samples", c.MinSamples, "valid samples before an endpoint can be a score-based target")
	fs.Float64Var(&c.NoiseGate, "noise-gate", c.NoiseGate, "per-component noise gate, in standard errors")
	fs.Float64Var(&c.LossWeight, "loss-weight", c.LossWeight, "loss weight (alpha) in the cost model")
	fs.Float64Var(&c.JitterWeight, "jitter-weight", c.JitterWeight, "jitter weight (k) in the cost model")
	fs.Float64Var(&c.OrderBias, "order-bias", c.OrderBias, "cost penalty per list position (beta)")
	fs.Float64Var(&c.Margin, "margin", c.Margin, "minimum relative effect for significantly worse, after the noise gate")
	fs.DurationVar(&c.MarginAbs, "margin-abs", c.MarginAbs, "minimum absolute effect for significantly worse")
	fs.DurationVar(&c.Persist, "persist", c.Persist, "net time a degradation must hold before a switch")
	fs.DurationVar(&c.Cooldown, "cooldown", c.Cooldown, "minimum time between switches")
	fs.DurationVar(&c.WaitToRestore, "wait-to-restore", c.WaitToRestore, "net time an earlier endpoint must stay not worse before reverting to it (0 disables)")
	fs.Float64Var(&c.OutageEpsilon, "outage-epsilon", c.OutageEpsilon, "outage threshold probability")
	fs.DurationVar(&c.ReconcileInterval, "reconcile-interval", c.ReconcileInterval, "poll interval of the live device")
	fs.BoolVar(&c.Kick, "kick", c.Kick, "force an immediate keepalive after a switch")
	fs.StringVar(&c.NftTable, "nft-table", "", "daemon-owned inet table (default wgsteer_<device>)")
	fs.BoolVar(&c.DryRun, "dry-run", c.DryRun, "probe, score and log decisions; never touch the device or nftables")
	fs.StringVar(&logLevel, "log-level", c.LogLevel.String(), "log level: debug, info, warn, error")
	fs.StringVar(&c.LogDir, "log-dir", c.LogDir, "write the log to hourly gzip files wgsteer-YYYY-MM-DDTHH.log.gz (UTC) in this directory instead of stderr")
	fs.DurationVar(&c.LogMaxAge, "log-max-age", c.LogMaxAge, "with --log-dir, delete files of hours that ended longer ago than this (at least 1h)")
	fs.DurationVar(&c.SummaryInterval, "summary-interval", c.SummaryInterval, "periodic per-endpoint summary (0 disables)")
	fs.DurationVar(&c.Watchdog, "watchdog", c.Watchdog, "exit if the event loop stalls this long")
	showVersion := fs.Bool("version", false, "print the version and exit")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if *showVersion {
		return Config{}, ErrVersion
	}
	if fs.NArg() > 0 {
		return Config{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	var missing []string
	for _, f := range []struct{ name, value string }{
		{"--device", c.Device}, {"--probe-config", c.ProbeConfig}, {"--endpoints", c.Endpoints},
		{"--probe-addr", probeAddr}, {"--target", target},
	} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required flags: %s", strings.Join(missing, ", "))
	}
	var err error
	if c.ProbeAddr, err = netip.ParseAddr(probeAddr); err != nil {
		return Config{}, fmt.Errorf("--probe-addr: %w", err)
	}
	if c.Target, err = netip.ParseAddr(target); err != nil {
		return Config{}, fmt.Errorf("--target: %w", err)
	}
	c.ProbeAddr, c.Target = c.ProbeAddr.Unmap(), c.Target.Unmap()
	if err := c.LogLevel.UnmarshalText([]byte(logLevel)); err != nil {
		return Config{}, fmt.Errorf("--log-level: %w", err)
	}
	if c.NftTable == "" {
		c.NftTable = "wgsteer_" + c.Device
	}
	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c *Config) validate() error {
	var errs []error
	check := func(ok bool, format string, args ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, args...))
		}
	}
	check(len(c.Device) <= 15, "--device %q: interface names are at most 15 bytes", c.Device)
	check(c.ProbeInterval > 0, "--probe-interval must be positive")
	check(c.ProbeTimeout > 0 && c.ProbeTimeout < c.ProbeInterval, "--probe-timeout must be positive and below --probe-interval")
	minMTU := probe.MinMTU(c.ProbeAddr)
	check(c.ProbeMTU >= minMTU && c.ProbeMTU <= probe.MaxMTU, "--probe-mtu must be in [%d, %d]", minMTU, probe.MaxMTU)
	maxSize := probe.MaxPayloadSize(c.ProbeMTU, c.ProbeAddr)
	check(c.ProbeSize >= probe.MinPayloadSize && c.ProbeSize <= maxSize,
		"--probe-size must be in [%d, %d] (--probe-mtu %d minus the IP and ICMP headers)", probe.MinPayloadSize, maxSize, c.ProbeMTU)
	check(c.ReconcileInterval > 0, "--reconcile-interval must be positive")
	check(c.Watchdog >= 2*max(c.ProbeInterval, c.ReconcileInterval), "--watchdog must be at least twice the probe and reconcile intervals")
	check(c.SummaryInterval >= 0, "--summary-interval must not be negative")
	check(c.LogMaxAge >= time.Hour, "--log-max-age must be at least 1h")
	check(c.NftTable != "" && len(c.NftTable) < 256, "--nft-table must be 1-255 bytes")
	if err := c.Params().Validate(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
