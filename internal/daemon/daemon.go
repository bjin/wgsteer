// Package daemon wires the probe, the policy engine, the live device and the
// nft deny-list into one event loop.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/bjin/wgsteer/internal/endpoints"
	"github.com/bjin/wgsteer/internal/nftable"
	"github.com/bjin/wgsteer/internal/policy"
	"github.com/bjin/wgsteer/internal/probe"
	"github.com/bjin/wgsteer/internal/probecfg"
	"github.com/bjin/wgsteer/internal/status"
	"github.com/bjin/wgsteer/internal/wgdev"
)

// StartupError is a failed startup step; the process exits with code 1.
type StartupError struct {
	Step string
	Err  error
}

func (e *StartupError) Error() string { return e.Step + ": " + e.Err.Error() }

func (e *StartupError) Unwrap() error { return e.Err }

// verification is a switch waiting to be confirmed on the device.
type verification struct {
	id        int
	target    netip.AddrPort
	handshake time.Time
	ticks     int
}

// verifyTicks is the number of reconcile ticks after which a switch whose
// target is not on the device is reported as not verified.
const verifyTicks = 3

// drainDelay separates the nft commit from the endpoint write of a switch:
// time for old-path packets already accepted (queued in kernel WireGuard's
// asynchronous receive path) to be processed before the endpoint changes.
const drainDelay = time.Millisecond

// postSwitchCheck is when an extra reconcile runs after a switch, so a
// device roamed back by late old-path packets is re-asserted at once
// instead of on the next reconcile tick.
const postSwitchCheck = 200 * time.Millisecond

// staleHandshake is wg0's last-handshake age that triggers the "device
// handshake stale" warning: REJECT_AFTER_TIME, after which the session is
// unusable.
const staleHandshake = probe.RejectAfterTime

// daemon is the event loop's state. Only the loop goroutine touches it;
// other goroutines read the published snapshot.
type daemon struct {
	cfg     Config
	logging *Logging
	log     *slog.Logger
	clock   Clock
	wall    func() time.Time
	deps    deps
	hb      *Heartbeat
	build   buildInfo

	dev Device
	nft Firewall // nil in dry-run
	prb Prober

	ident *probecfg.Config
	eps   []endpoints.Endpoint // the parsed list, with names
	list  []netip.AddrPort     // addresses of eps
	eng   *policy.Engine
	sched *probe.Scheduler

	startWall time.Time
	state     status.State

	// Live device, as last read and validated.
	devInfo      *wgdev.Device
	peer         wgdev.Peer
	listenPort   uint16
	fwmark       uint32
	probeMark    uint32 // fwmark the probe's sockets last fully took
	markDirty    bool   // a SetFwmark failed: socket marks unknown
	markWarned   bool
	checkDue     bool // a switch ran: arm the post-switch check
	write        *pendingWrite
	detachReason string
	staleWarned  bool

	// Selection bookkeeping around the engine's selection.
	selSince  time.Time // loop clock
	selReason string
	// aliases are unlisted endpoints seen on the device while the current
	// selection (or no selection) was active.
	aliases []netip.AddrPort
	// away are the aliases (and a reload-removed selection) the last switch
	// left; they stay denied until the next switch.
	away []netip.AddrPort
	// removed is a selection dropped by a reload, until the next switch.
	removed netip.AddrPort

	// nft state. desired is what should be in force; dirty forces a
	// re-apply after any failed Apply or Reconnect (the outcome may be
	// unknown, or the table may be missing).
	desired  nftable.Ruleset
	dirty    bool
	nftErr   string
	nftErrAt time.Time
	counters []nftable.Counter

	verify   *verification
	verified *bool

	// Probe state.
	probeState   probe.State
	sessionValid bool
	stateErr     bool
	sendErr      bool
	slot         probe.Slot

	decision     policy.Decision
	haveDecision bool
	eligible     map[netip.AddrPort]bool

	history []status.SwitchEvent
	nextID  int

	snap atomic.Pointer[status.Status]
}

func newDaemon(cfg Config, logging *Logging, clock Clock, wall func() time.Time, hb *Heartbeat, dp deps) *daemon {
	d := &daemon{
		cfg:       cfg,
		logging:   logging,
		log:       logging.Logger,
		clock:     clock,
		wall:      wall,
		deps:      dp,
		hb:        hb,
		build:     readBuildInfo(),
		dev:       dp.dev,
		startWall: wall(),
		state:     status.StateWaitingDevice,
		eligible:  make(map[netip.AddrPort]bool),
	}
	d.publish()
	return d
}

// Run starts the daemon and runs it until SIGTERM or SIGINT. It returns nil
// after a clean stop and a *StartupError if startup failed; the caller then
// closes logging. A stalled loop exits the process with code 3 through the
// watchdog, which closes logging on a best-effort basis first.
func Run(cfg Config, logging *Logging) error {
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)

	hb := NewHeartbeat(time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wd := &Watchdog{Heartbeat: hb, Limit: cfg.Watchdog, Now: time.Now, Exit: os.Exit, Logger: logging.Logger, Flush: logging.Close}
	go wd.Run(ctx)

	d := newDaemon(cfg, logging, bootClock{}, time.Now, hb, deps{})
	d.reportHeader()
	if err := d.reportPrivileges(); err != nil {
		return err
	}
	if err := d.loadInputs(); err != nil {
		return err
	}
	wg, err := wgdev.Open()
	if err != nil {
		return d.fail("wgctrl", err)
	}
	d.deps = realDeps(wg)
	d.dev = wg
	dev, peer, stop, err := d.waitDevice(sigs)
	if err != nil {
		d.closeAll()
		return err
	}
	if stop {
		d.shutdown("")
		return nil
	}
	if err := d.setup(dev, peer); err != nil {
		d.closeAll()
		return err
	}
	d.loop(sigs)
	return nil
}

// fail logs a startup failure naming the step and returns it.
func (d *daemon) fail(step string, err error) error {
	d.log.Error("startup failed", "step", step, "error", err)
	return &StartupError{Step: step, Err: err}
}

// loadInputs reads the endpoint list and the probe identity.
func (d *daemon) loadInputs() error {
	list, err := endpoints.Load(d.cfg.Endpoints)
	if err != nil {
		return d.fail("endpoints", err)
	}
	d.setList(list)
	d.logEndpoints()
	ident, err := probecfg.Load(d.cfg.ProbeConfig)
	if err != nil {
		return d.fail("probe config", err)
	}
	if err := ident.Validate(d.cfg.ProbeAddr, d.cfg.Target); err != nil {
		return d.fail("probe config", err)
	}
	if ident.Keepalive != 0 {
		d.log.Warn("probe config sets a persistent keepalive; the probe does not need it", "keepalive", time.Duration(ident.Keepalive)*time.Second)
	}
	d.ident = ident
	return nil
}

// setList adopts a parsed endpoint list.
func (d *daemon) setList(list []endpoints.Endpoint) {
	d.eps, d.list = list, endpoints.Addrs(list)
}

// displayName is the display name of list position i (endpoints.DisplayName).
func (d *daemon) displayName(i int) string {
	return endpoints.DisplayName(d.eps[i].Name, i)
}

func (d *daemon) logEndpoints() {
	for i, ep := range d.list {
		d.log.Info("endpoint", "index", i, "name", d.displayName(i), "endpoint", ep, "family", endpoints.Family(ep))
	}
}

// inspect validates a device read. wait is non-empty when the device is not
// usable (missing, unconfigured or failing validation); err is set only for
// a validation failure.
func (d *daemon) inspect(dev *wgdev.Device, getErr error) (peer wgdev.Peer, wait string, err error) {
	switch {
	case errors.Is(getErr, wgdev.ErrNotFound):
		return peer, "device not found", nil
	case getErr != nil:
		return peer, "device read failed: " + getErr.Error(), nil
	case len(dev.Peers) == 0 || dev.PublicKey == (wgtypes.Key{}):
		return peer, "device not configured (no key or no peers)", nil
	}
	keys := make([]wgtypes.Key, len(dev.Peers))
	for i, p := range dev.Peers {
		keys[i] = p.PublicKey
	}
	if err := d.ident.CheckDevice(dev.PublicKey, keys); err != nil {
		err = fmt.Errorf("%w on %s", err, dev.Name)
		return peer, "validation failed: " + err.Error(), err
	}
	peer, _ = dev.Peer(d.ident.PeerKey)
	return peer, "", nil
}

// waitDevice polls until the device exists with its managed peer. stop
// reports SIGTERM/SIGINT while waiting.
func (d *daemon) waitDevice(sigs <-chan os.Signal) (dev *wgdev.Device, peer wgdev.Peer, stop bool, err error) {
	t := time.NewTicker(d.cfg.ReconcileInterval)
	defer t.Stop()
	logged := false
	for {
		d.hb.Beat(time.Now())
		dev, getErr := d.dev.Get(d.cfg.Device)
		if getErr != nil && !errors.Is(getErr, wgdev.ErrNotFound) {
			return nil, peer, false, d.fail("device", privilegeHint(getErr))
		}
		peer, wait, verr := d.inspect(dev, getErr)
		if verr != nil {
			return nil, peer, false, d.fail("probe config", verr)
		}
		if wait == "" {
			return dev, peer, false, nil
		}
		if !logged {
			d.log.Info("waiting for device", "device", d.cfg.Device, "reason", wait, "poll", d.cfg.ReconcileInterval)
			logged = true
		}
		select {
		case <-t.C:
		case s := <-sigs:
			switch s {
			case syscall.SIGTERM, syscall.SIGINT:
				d.log.Info("signal", "signal", s.String())
				return nil, peer, true, nil
			case syscall.SIGHUP:
				if list, err := endpoints.Load(d.cfg.Endpoints); err != nil {
					d.log.Error("reload failed", "error", err)
				} else {
					d.setList(list)
					d.log.Info("endpoints reloaded", "endpoints", len(list))
					d.logEndpoints()
				}
			default:
				d.handleInfoSignal(s)
			}
		}
		d.publish()
	}
}

// setup validates against the device, adopts the selection, creates the nft
// table and starts the probe.
func (d *daemon) setup(dev *wgdev.Device, peer wgdev.Peer) error {
	now := d.clock.Now()
	d.setDevice(dev, peer)
	d.log.Info("device", "device", dev.Name, "type", dev.Type, "public_key", dev.PublicKey.String(),
		"peer", peer.PublicKey.String(), "listen_port", dev.ListenPort, "fwmark", dev.Fwmark,
		"keepalive", peer.Keepalive, "endpoint", epAttr(peer.Endpoint),
		"listed", endpoints.Index(d.list, peer.Endpoint) >= 0, "peers", len(dev.Peers),
		"last_handshake", timeAttr(peer.LastHandshake))
	if len(dev.Peers) > 1 {
		d.log.Warn("device has more than one peer; only the probe's peer is managed", "peers", len(dev.Peers), "peer", peer.PublicKey.String())
	}

	var sel netip.AddrPort
	if i := endpoints.Index(d.list, peer.Endpoint); i >= 0 {
		sel = d.list[i]
		d.selReason = "device endpoint is listed (" + endpoints.Label(d.eps[i].Name, i) + ")"
	} else if peer.Endpoint.IsValid() {
		d.aliases = []netip.AddrPort{peer.Endpoint}
		d.selReason = "device endpoint is unlisted; all listed candidates denied until the startup switch"
	} else {
		d.selReason = "device peer has no endpoint; all listed candidates denied until the startup switch"
	}
	selAttrs := []any{"selection", epAttr(sel), "index", -1}
	if i := endpoints.Index(d.list, sel); i >= 0 {
		selAttrs = []any{"selection", epAttr(sel), "index", i, "name", d.displayName(i)}
	}
	d.log.Info("initial selection", append(selAttrs, "reason", d.selReason)...)
	eng, err := policy.New(d.cfg.Params(), d.eps, sel, now)
	if err != nil {
		return d.fail("policy", err)
	}
	d.eng = eng
	d.selSince = now
	d.sched = probe.NewScheduler(d.cfg.ProbeTimeout, nil)

	if d.cfg.DryRun {
		d.log.Info("nft table skipped", "reason", "dry-run")
	} else {
		nft, err := d.deps.openNFT(d.cfg.NftTable)
		if err != nil {
			if errors.Is(err, nftable.ErrOwnedElsewhere) {
				err = fmt.Errorf("%w: another instance manages %s", err, d.cfg.Device)
			}
			return d.fail("nft", privilegeHint(err))
		}
		d.nft = nft
		d.desired = d.rules()
		if _, err := nft.Apply(d.desired); err != nil {
			return d.fail("nft", privilegeHint(err))
		}
		info := nft.Info()
		d.log.Info("nft table", "table", info.Name, "chain", info.Chain, "owner_flag", info.OwnerFlag,
			"owner", info.Owner, "replaced_stale", info.ReplacedStale, "listen_port", d.desired.ListenPort,
			"denied", epsAttr(d.desired.Denied))
	}

	prb, err := d.deps.newProbe(probe.Config{
		Identity:    d.ident,
		ProbeAddr:   d.cfg.ProbeAddr,
		Target:      d.cfg.Target,
		PayloadSize: d.cfg.ProbeSize,
		MTU:         d.cfg.ProbeMTU,
		Endpoint:    d.list[0],
		Fwmark:      dev.Fwmark,
		Logger:      d.log.With("component", "probe"),
	})
	if err != nil {
		return d.fail("probe", err)
	}
	d.prb, d.probeMark = prb, dev.Fwmark
	st, err := prb.State()
	if err != nil {
		return d.fail("probe", err)
	}
	d.probeState = st
	d.log.Info("probe", "public_key", prb.PublicKey().String(), "probe_addr", d.cfg.ProbeAddr, "target", d.cfg.Target,
		"listen_port", st.ListenPort, "fwmark", st.Fwmark, "payload_size", d.cfg.ProbeSize, "mtu", d.cfg.ProbeMTU,
		"endpoint", epAttr(st.Endpoint))

	eta := time.Duration(d.cfg.MinSamples*len(d.list)) * d.cfg.ProbeInterval
	d.state = status.StateRunning
	d.log.Info("ready", "eligibility_eta", eta, "endpoints", len(d.list), "selection", epAttr(sel), "dry_run", d.cfg.DryRun)
	d.publish()
	return nil
}

// setDevice stores a validated device read.
func (d *daemon) setDevice(dev *wgdev.Device, peer wgdev.Peer) {
	d.devInfo, d.peer = dev, peer
	d.listenPort, d.fwmark = uint16(dev.ListenPort), dev.Fwmark
}

// shutdown deletes the table and closes the probe. The device
// keeps its endpoint.
func (d *daemon) shutdown(sig string) {
	d.state = status.StateStopping
	d.publish()
	d.log.Info("stopping", "signal", sig)
	d.closeAll()
	d.log.Info("stopped")
}

func (d *daemon) closeAll() {
	if d.nft != nil {
		if err := d.nft.Close(); err != nil {
			d.log.Warn("nft error", "op", "close", "error", err)
		} else {
			d.log.Info("nft table deleted", "table", d.cfg.NftTable)
		}
		d.nft = nil
	}
	if d.prb != nil {
		d.prb.Close()
		d.prb = nil
	}
	if d.dev != nil {
		d.dev.Close()
		d.dev = nil
	}
}
