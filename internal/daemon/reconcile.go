package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/bjin/wgsteer/internal/endpoints"
	"github.com/bjin/wgsteer/internal/nftable"
	"github.com/bjin/wgsteer/internal/status"
	"github.com/bjin/wgsteer/internal/wgdev"
)

// reconcile polls the live device and handles external changes:
// attach/detach, listen-port and fwmark changes, nft retries,
// switch verification, re-asserts and aliases.
func (d *daemon) reconcile(now time.Time) {
	dev, err := d.dev.Get(d.cfg.Device)
	peer, wait, _ := d.inspect(dev, err)
	if wait != "" {
		d.detach(wait)
		return
	}
	if d.state != status.StateRunning {
		d.attach(dev, peer)
	}
	d.devInfo, d.peer = dev, peer

	if dev.Fwmark != d.fwmark {
		d.log.Info("fwmark changed", "old", d.fwmark, "new", dev.Fwmark)
		d.fwmark = dev.Fwmark
	}
	d.syncProbeMark()
	if port := uint16(dev.ListenPort); port != d.listenPort {
		d.log.Info("listen port changed", "old", d.listenPort, "new", port)
		d.listenPort = port
		if d.nft != nil {
			d.desired = d.rules()
			d.rebuild("listen-port")
		}
	}
	d.syncNFT()
	d.readCounters()
	// A tick that redid a pending write has no read of its result yet:
	// endpoint handling and verification wait for the next read, so the old
	// endpoint (or its alias) is neither re-asserted twice nor mistaken for
	// an alias of the new selection.
	if !d.resumeWrite(peer) {
		d.verifySwitch(peer)
		d.checkEndpoint(peer)
	}
	d.checkHandshake(peer)
}

// detach enters the detached state: keep probing, leave nft alone.
// It logs once per reason.
func (d *daemon) detach(reason string) {
	if d.state == status.StateDetached && reason == d.detachReason {
		return
	}
	d.state, d.detachReason = status.StateDetached, reason
	d.log.Warn("device detached", "device", d.cfg.Device, "reason", reason)
}

// attach leaves the detached state after the device passed re-validation.
// The caller then runs a full reconcile; the nft rules are re-applied.
func (d *daemon) attach(dev *wgdev.Device, peer wgdev.Peer) {
	d.state, d.detachReason = status.StateRunning, ""
	d.dirty = true
	d.log.Info("device attached", "device", dev.Name, "type", dev.Type, "listen_port", dev.ListenPort,
		"fwmark", dev.Fwmark, "endpoint", epAttr(peer.Endpoint), "peers", len(dev.Peers))
	if len(dev.Peers) > 1 {
		d.log.Warn("device has more than one peer; only the probe's peer is managed", "peers", len(dev.Peers), "peer", peer.PublicKey.String())
	}
}

// readCounters refreshes the per-tuple drop counters for the snapshot.
func (d *daemon) readCounters() {
	if d.nft == nil || d.state != status.StateRunning {
		return
	}
	c, err := d.nft.Counters()
	if err != nil {
		d.nftError("counters", "reconcile", err)
		d.dirty = true
		return
	}
	d.counters = c
}

// verifySwitch confirms the last switch on the device.
func (d *daemon) verifySwitch(peer wgdev.Peer) {
	v := d.verify
	if v == nil {
		return
	}
	v.ticks++
	if peer.Endpoint == v.target && d.write == nil {
		unchanged := peer.LastHandshake.Equal(v.handshake)
		level := slog.LevelInfo
		if !unchanged {
			level = slog.LevelWarn
		}
		d.log.Log(context.Background(), level, "switch verified", "switch_id", v.id, "endpoint", v.target,
			"handshake_unchanged", unchanged, "ticks", v.ticks, "drops", countersAttr(d.deniedCounters()))
		ok := true
		d.verify, d.verified = nil, &ok
		return
	}
	if v.ticks >= verifyTicks {
		d.log.Warn("switch not verified", "switch_id", v.id, "target", v.target, "observed", epAttr(peer.Endpoint),
			"write_pending", d.write != nil, "ticks", v.ticks)
		ok := false
		d.verify, d.verified = nil, &ok
	}
}

// deniedCounters returns the counters of the currently denied tuples.
func (d *daemon) deniedCounters() []nftable.Counter {
	var out []nftable.Counter
	for _, c := range d.counters {
		if slices.Contains(d.desired.Denied, c.Addr) {
			out = append(out, c)
		}
	}
	return out
}

// checkEndpoint applies the reconcile table (docs/switching.md) to the device's endpoint.
func (d *daemon) checkEndpoint(peer wgdev.Peer) {
	ep, sel := peer.Endpoint, d.eng.Selected()
	if ep == sel && sel.IsValid() {
		return
	}
	if d.cfg.DryRun {
		d.log.Debug("device endpoint differs from simulated selection", "observed", epAttr(ep), "selection", epAttr(sel))
		return
	}
	listed := endpoints.Index(d.list, ep) >= 0
	switch {
	// A denied unlisted endpoint (an alias of a selection the device left)
	// can only be reached by late packets roaming the device back; its
	// replies are dropped, so it is re-asserted like a listed one, never
	// learned as the new selection's alias.
	case !ep.IsValid() || listed || slices.Contains(d.away, ep):
		if sel.IsValid() {
			d.reassert(ep, sel)
		} else {
			d.log.Debug("device endpoint without selection", "observed", epAttr(ep))
		}
	case ep == d.removed:
		// The removed selection stays allowed until the reload switch.
	case !slices.Contains(d.aliases, ep):
		d.aliases = append(d.aliases, ep)
		d.log.Info("alias learned", "alias", ep, "selection", epAttr(sel))
	}
}

// reassert points the device back at the selection (not a switch: no
// cooldown, nft already denies the observed endpoint).
func (d *daemon) reassert(observed, sel netip.AddrPort) {
	if _, err := d.writeEndpoint(sel); err != nil {
		d.log.Warn("re-assert failed", "observed", epAttr(observed), "selection", sel, "error", err)
		return
	}
	d.log.Info("re-assert", "observed", epAttr(observed), "selection", sel, "kick", d.cfg.Kick)
}

// pendingWrite tracks an endpoint write (switch or re-assert) until a read
// confirms it. wgdev.SetEndpoint is several netlink calls, so after a
// failure the device may already hold the target with the kick's temporary
// keepalive (0, or 1 s when the original is 0) and no longer report the
// original. Reconcile redoes the whole write, with the original keepalive,
// until it succeeds; every call in it is idempotent. After a successful
// redo (written) the original is kept until a read shows it restored, so no
// write in between can pick up the temporary value.
type pendingWrite struct {
	target    netip.AddrPort
	keepalive time.Duration // the peer's keepalive before the failed write
	failures  int
	written   bool // redone successfully; waiting for a read to confirm
}

// keepalive is the persistent keepalive a write restores after the kick:
// the original one while a write is pending, else the device's.
func (d *daemon) keepalive() time.Duration {
	if d.write != nil {
		return d.write.keepalive
	}
	return d.peer.Keepalive
}

// writeEndpoint sets the device's endpoint with the kick and tracks the
// write while the device's keepalive cannot be trusted (pendingWrite). It
// returns the keepalive used.
func (d *daemon) writeEndpoint(target netip.AddrPort) (time.Duration, error) {
	k := d.keepalive()
	if err := d.dev.SetEndpoint(d.cfg.Device, d.ident.PeerKey, target, k, d.cfg.Kick); err != nil {
		if d.write == nil {
			d.write = &pendingWrite{keepalive: k}
		}
		d.write.target, d.write.written = target, false
		d.write.failures++
		return k, err
	}
	if d.write != nil {
		// The last read may show a temporary keepalive; keep the original
		// until a read confirms it.
		d.write = &pendingWrite{target: target, keepalive: k, failures: d.write.failures, written: true}
	}
	return k, nil
}

// resumeWrite handles a pending write against the latest read and reports
// whether it wrote this tick. A written write whose keepalive the read
// shows restored is done. Otherwise the write is redone toward the
// selection, even when the device already shows the target (the kick or
// the keepalive restoration may be missing). A keepalive that is neither
// the original nor the kick's temporary value means the device was
// reconfigured (netifd): that configuration wins, and the normal endpoint
// check takes over.
func (d *daemon) resumeWrite(peer wgdev.Peer) bool {
	w := d.write
	if w == nil {
		return false
	}
	if w.written && peer.Keepalive == w.keepalive {
		d.write = nil
		return false
	}
	temp := time.Duration(0)
	if w.keepalive == 0 && d.cfg.Kick {
		temp = time.Second
	}
	if peer.Keepalive != w.keepalive && peer.Keepalive != temp {
		d.log.Info("endpoint write superseded", "target", w.target, "keepalive", w.keepalive,
			"observed_keepalive", peer.Keepalive, "observed", epAttr(peer.Endpoint))
		d.write = nil
		return false
	}
	target := d.eng.Selected()
	if !target.IsValid() {
		target = w.target
	}
	k, err := d.writeEndpoint(target)
	if err != nil {
		level := slog.LevelDebug
		if d.write.failures == 2 {
			level = slog.LevelWarn
		}
		d.log.Log(context.Background(), level, "endpoint write retry failed", "target", target,
			"keepalive", k, "failures", d.write.failures, "error", err)
		return true
	}
	d.log.Info("endpoint write resumed", "target", target, "keepalive", k, "attempts", w.failures+1,
		"observed", epAttr(peer.Endpoint), "observed_keepalive", peer.Keepalive)
	return true
}

// syncProbeMark copies the device's fwmark to the probe. After any failure
// the probe's sockets are in an unknown state (the bind marks IPv4 and IPv6
// one after the other), so the mark is re-applied on every reconcile until
// one succeeds, even if the device's mark meanwhile returned to the last
// successful value.
func (d *daemon) syncProbeMark() {
	if d.probeMark == d.fwmark && !d.markDirty {
		return
	}
	if err := d.prb.SetFwmark(d.fwmark); err != nil {
		d.markDirty = true
		level := slog.LevelDebug
		if !d.markWarned {
			level, d.markWarned = slog.LevelWarn, true
		}
		d.log.Log(context.Background(), level, "probe fwmark failed", "fwmark", d.fwmark, "error", err)
		return
	}
	d.probeMark, d.markDirty, d.markWarned = d.fwmark, false, false
}

// checkHandshake warns once per episode when wg0's session is stale while
// the selection probes fresh: a wg0 problem that switching cannot fix.
func (d *daemon) checkHandshake(peer wgdev.Peer) {
	age := d.wall().Sub(peer.LastHandshake)
	if !peer.LastHandshake.IsZero() && age <= staleHandshake {
		d.staleWarned = false
		return
	}
	if d.staleWarned || !d.selectionFresh() {
		return
	}
	d.staleWarned = true
	hs := "never"
	if !peer.LastHandshake.IsZero() {
		hs = age.Round(time.Second).String()
	}
	d.log.Warn("device handshake stale", "handshake_age", hs, "selection", epAttr(d.eng.Selected()))
}

func (d *daemon) selectionFresh() bool {
	sel := d.eng.Selected()
	for _, v := range d.decision.Record.Endpoints {
		if v.Addr == sel {
			return v.Fresh
		}
	}
	return false
}
