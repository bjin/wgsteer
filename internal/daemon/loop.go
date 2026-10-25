package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"time"

	"github.com/bjin/wgsteer/internal/endpoints"
	"github.com/bjin/wgsteer/internal/probe"
	"github.com/bjin/wgsteer/internal/stats"
	"github.com/bjin/wgsteer/internal/status"
)

// loop is the single event loop: probe slots on a fixed grid,
// slot deadlines, probe replies, reconcile and summary ticks and signals.
// It returns after SIGTERM/SIGINT and a clean shutdown.
func (d *daemon) loop(sigs <-chan os.Signal) {
	interval := d.cfg.ProbeInterval
	base := d.clock.Now()
	slotTimer := time.NewTimer(0)
	defer slotTimer.Stop()
	pending := false
	reconcile := time.NewTicker(d.cfg.ReconcileInterval)
	defer reconcile.Stop()
	var summary <-chan time.Time
	if d.cfg.SummaryInterval > 0 {
		t := time.NewTicker(d.cfg.SummaryInterval)
		defer t.Stop()
		summary = t.C
	}
	replies := d.prb.Replies()
	var check <-chan time.Time // post-switch check, armed after each switch

	for {
		d.hb.Beat(time.Now())
		select {
		case <-slotTimer.C:
			now := d.clock.Now()
			if !pending {
				if deadline, ok := d.beginSlot(now); ok {
					pending = true
					slotTimer.Reset(max(deadline.Sub(d.clock.Now()), 0))
					break
				}
			} else {
				pending = false
				d.finishSlot(now)
			}
			// Next grid point strictly after now: slots never drift, and
			// a stall skips the missed slots instead of bunching them.
			next := base.Add((now.Sub(base)/interval + 1) * interval)
			slotTimer.Reset(max(next.Sub(d.clock.Now()), 0))
		case r := <-replies:
			d.onReply(r)
			continue
		case <-reconcile.C:
			d.reconcile(d.clock.Now())
		case <-check:
			check = nil
			d.log.Debug("post-switch check")
			d.reconcile(d.clock.Now())
		case <-summary:
			d.summary()
		case s := <-sigs:
			switch s {
			case syscall.SIGTERM, syscall.SIGINT:
				d.log.Info("signal", "signal", s.String())
				d.shutdown(s.String())
				return
			case syscall.SIGHUP:
				d.log.Info("signal", "signal", s.String())
				d.reload(d.clock.Now())
			default:
				d.handleInfoSignal(s)
			}
		}
		if d.checkDue {
			d.checkDue = false
			check = time.After(postSwitchCheck)
		}
		d.publish()
	}
}

// handleInfoSignal handles SIGUSR1 (status dump) and SIGUSR2 (debug toggle).
func (d *daemon) handleInfoSignal(s os.Signal) {
	switch s {
	case syscall.SIGUSR1:
		d.dump()
	case syscall.SIGUSR2:
		d.logging.ToggleDebug()
	}
}

func (d *daemon) debug() bool {
	return d.log.Enabled(context.Background(), slog.LevelDebug)
}

// beginSlot opens a probe slot: read the probe's session, pick the next
// endpoint, retarget and send one echo. ok is false when nothing is
// pending (empty list or a failed send, which is discarded, not a loss).
func (d *daemon) beginSlot(now time.Time) (deadline time.Time, ok bool) {
	wallNow := d.wall()
	valid := false
	st, err := d.prb.State()
	if err != nil {
		if !d.stateErr {
			d.log.Warn("probe state failed", "error", err)
			d.stateErr = true
		}
	} else {
		d.stateErr = false
		d.probeState = st
		valid = probe.SessionValid(st.LastHandshake, wallNow)
	}
	if valid != d.sessionValid {
		d.sessionValid = valid
		age := "never"
		if !st.LastHandshake.IsZero() {
			age = wallNow.Sub(st.LastHandshake).Round(time.Millisecond).String()
		}
		if valid {
			d.log.Info("probe session established", "handshake_age", age)
		} else {
			d.log.Info("probe session expired", "handshake_age", age)
		}
	}

	slot := d.sched.Begin(d.list, now, valid)
	if !slot.Endpoint.IsValid() {
		return time.Time{}, false
	}
	d.slot = slot
	step := "retarget"
	err = d.prb.Retarget(slot.Endpoint)
	if err == nil {
		step = "send"
		err = d.prb.Send(slot.Seq, slot.Nonce, slot.EndpointID)
	}
	if err != nil {
		d.sched.Finish()
		if !d.sendErr {
			d.log.Warn("probe send failed", "step", step, "endpoint", slot.Endpoint, "error", err)
			d.sendErr = true
		}
		return time.Time{}, false
	}
	d.sendErr = false
	return slot.Deadline, true
}

// onReply passes a probe reply to the pending slot.
func (d *daemon) onReply(r probe.Reply) {
	if d.sched.Match(r) {
		return
	}
	if d.debug() {
		d.log.Debug("unmatched reply", "seq", r.Seq, "endpoint_id", r.EndpointID, "rtt_ms", msAttr(r.RTT()))
	}
}

// finishSlot closes the pending slot at its deadline, records the sample
// and runs the policy tick.
func (d *daemon) finishSlot(now time.Time) {
	for drained := false; !drained; {
		select {
		case r := <-d.prb.Replies():
			d.onReply(r)
		default:
			drained = true
		}
	}
	res, ok := d.sched.Finish()
	if !ok {
		return
	}
	idx := endpoints.Index(d.list, res.Endpoint)
	switch {
	case idx < 0:
		d.log.Debug("sample ignored", "endpoint", res.Endpoint, "seq", res.Seq, "reason", "endpoint no longer listed")
	case !res.Valid:
		d.eng.RecordInvalid(res.Endpoint, res.At)
	default:
		d.eng.Record(res.Endpoint, stats.Sample{At: res.At, Replied: res.Replied, RTT: res.RTT})
	}
	if idx >= 0 && d.debug() {
		outcome := "loss"
		switch {
		case !res.Valid:
			outcome = "invalid"
		case res.Replied:
			outcome = "reply"
		}
		d.log.Debug("sample", "endpoint", res.Endpoint, "index", idx, "seq", res.Seq, "outcome", outcome,
			"rtt_ms", msAttr(res.RTT), "slot_start", d.wallAt(res.At), "finished_after_ms", msAttr(now.Sub(res.At)))
	}
	d.tick(now)
}

// tick runs the policy after a slot and executes a proposed switch.
func (d *daemon) tick(now time.Time) {
	dec := d.eng.Tick(now)
	d.decision, d.haveDecision = dec, true
	for _, v := range dec.Record.Endpoints {
		was := d.eligible[v.Addr]
		if v.Eligible != was {
			d.eligible[v.Addr] = v.Eligible
			msg := "endpoint eligible"
			if !v.Eligible {
				msg = "endpoint ineligible"
			}
			d.log.Info(msg, "endpoint", v.Addr, "index", v.Index, "name", v.Name, "samples", v.Samples, "cost", round(float64(v.Cost)))
		}
	}
	if d.debug() {
		d.trace(dec)
	}
	if dec.Switch {
		d.execute(dec, now)
	}
}

// reload re-reads the endpoint list on SIGHUP (policy rule 6). The
// probe config is not reloaded.
func (d *daemon) reload(now time.Time) {
	eps, err := endpoints.Load(d.cfg.Endpoints)
	if err != nil {
		d.log.Error("reload failed", "error", err, "kept", len(d.list))
		return
	}
	oldSel := d.eng.Selected()
	if err := d.eng.Reload(eps, now); err != nil {
		d.log.Error("reload failed", "error", err, "kept", len(d.list))
		return
	}
	list := endpoints.Addrs(eps)
	var added, removed []string
	for _, ep := range list {
		if endpoints.Index(d.list, ep) < 0 {
			added = append(added, ep.String())
		}
	}
	for _, ep := range d.list {
		if endpoints.Index(list, ep) < 0 {
			removed = append(removed, ep.String())
			delete(d.eligible, ep)
		}
	}
	d.setList(eps)
	// Aliases that became listed are ordinary candidates now.
	d.aliases = slices.DeleteFunc(d.aliases, func(a netip.AddrPort) bool { return endpoints.Index(list, a) >= 0 })
	if oldSel.IsValid() && !d.eng.Selected().IsValid() {
		d.removed = oldSel
	}
	d.log.Info("endpoints reloaded", "endpoints", len(list), "added", added, "removed", removed,
		"selection_removed", d.removed.IsValid())
	d.logEndpoints()
	if d.nft != nil && d.state == status.StateRunning {
		d.desired = d.rules()
		d.rebuild("reload")
	}
	d.tick(now)
}
