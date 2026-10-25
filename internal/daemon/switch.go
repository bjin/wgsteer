package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/bjin/wgsteer/internal/nftable"
	"github.com/bjin/wgsteer/internal/policy"
	"github.com/bjin/wgsteer/internal/status"
)

// rules is the deny-list for the current state: every listed
// candidate except the selection, plus the aliases the last switch left. A
// selection removed by a reload stays allowed until the reload switch.
func (d *daemon) rules() nftable.Ruleset {
	sel := d.eng.Selected()
	if !sel.IsValid() {
		sel = d.removed
	}
	return nftable.Desired(d.list, sel, d.away, d.listenPort)
}

// execute carries out a proposed switch: block first (atomic nft
// commit), then set the endpoint with a kick, then commit the engine. A
// failed nft commit aborts the switch without touching the device or the
// engine, so a later tick proposes it again.
func (d *daemon) execute(dec policy.Decision, now time.Time) {
	if d.cfg.DryRun {
		d.simulate(dec, now)
		return
	}
	if d.state != status.StateRunning {
		d.log.Debug("switch deferred", "reason", "device detached", "kind", string(dec.Kind), "to", dec.To)
		return
	}
	// Aliases of the endpoint being left, and a selection a reload removed,
	// stay denied until the next switch. Without a previous selection
	// (startup on an unlisted endpoint) there is nothing to retire: the
	// startup endpoint stays allowed, and reconcile learns it as an alias of
	// the new selection if the device keeps using it.
	var away []netip.AddrPort
	if dec.From.IsValid() || d.removed.IsValid() {
		away = slices.Clone(d.aliases)
		if d.removed.IsValid() {
			away = append(away, d.removed)
		}
	}
	desired := nftable.Desired(d.list, dec.To, away, d.listenPort)
	ev := d.newEvent(dec, desired.Denied)

	t0 := time.Now()
	before, err := d.applyNFT(desired, "switch")
	t1 := time.Now()
	if err != nil {
		ev.Result, ev.Error = status.ResultAborted, err.Error()
		d.logSwitch(slog.LevelWarn, "switch aborted", ev, dec, "error", err, "nft_ms", msAttr(t1.Sub(t0)))
		d.addHistory(ev)
		return
	}
	// Old-path packets accepted before the commit may still sit in kernel
	// WireGuard's receive queue (decryption is asynchronous); give them
	// drainDelay to be processed, so they cannot roam the device back after
	// the endpoint is set. postSwitchCheck catches what still slips through.
	time.Sleep(drainDelay)
	keepalive, setErr := d.writeEndpoint(dec.To)
	t2 := time.Now()

	d.eng.Commit(dec, now)
	d.desired, d.dirty = desired, false
	d.away, d.aliases, d.removed = away, nil, netip.AddrPort{}
	d.selSince, d.selReason = now, "switch #"+itoa(ev.ID)+" ("+string(dec.Kind)+")"
	d.verify = &verification{id: ev.ID, target: dec.To, handshake: d.peer.LastHandshake}
	d.verified = nil
	d.checkDue = true
	ev.BlockSetGap = t2.Sub(t1)
	ev.Result = status.ResultOK
	attrs := []any{"nft_ms", msAttr(t1.Sub(t0)), "block_set_gap_ms", msAttr(t2.Sub(t1)),
		"drops_before", countersAttr(before), "keepalive", keepalive, "kick", d.cfg.Kick}
	if setErr != nil {
		// The rules already deny the old path; reconcile redoes the write
		// with the original keepalive (resumeWrite).
		ev.Result, ev.Error = status.ResultSetFailed, setErr.Error()
		d.log.Error("switch set endpoint failed", "switch_id", ev.ID, "to", dec.To, "error", setErr)
		attrs = append(attrs, "error", setErr)
	}
	d.logSwitch(slog.LevelInfo, "switch", ev, dec, attrs...)
	d.addHistory(ev)
}

// simulate commits a switch to the engine only (--dry-run).
func (d *daemon) simulate(dec policy.Decision, now time.Time) {
	ev := d.newEvent(dec, nil)
	ev.Result = status.ResultDryRun
	d.eng.Commit(dec, now)
	d.away, d.aliases, d.removed = nil, nil, netip.AddrPort{}
	d.selSince, d.selReason = now, "simulated switch #"+itoa(ev.ID)+" ("+string(dec.Kind)+")"
	d.logSwitch(slog.LevelInfo, "would switch", ev, dec)
	d.addHistory(ev)
}

func (d *daemon) newEvent(dec policy.Decision, denied []netip.AddrPort) status.SwitchEvent {
	d.nextID++
	return status.SwitchEvent{
		ID:     d.nextID,
		At:     d.wall().Round(time.Millisecond),
		Kind:   dec.Kind,
		From:   dec.From,
		To:     dec.To,
		Reason: dec.Reason,
		Denied: denied,
		Record: d.wallRecord(dec.Record),
	}
}

func (d *daemon) addHistory(ev status.SwitchEvent) {
	if len(d.history) == status.HistorySize {
		d.history = slices.Delete(d.history, 0, 1)
	}
	d.history = append(d.history, ev)
}

// rebuild applies d.desired outside a switch and logs it.
func (d *daemon) rebuild(reason string) {
	before, err := d.applyNFT(d.desired, reason)
	if err != nil {
		return
	}
	d.log.Info("nft rebuild", "reason", reason, "listen_port", d.desired.ListenPort,
		"denied", epsAttr(d.desired.Denied), "drops_before", countersAttr(before))
}

// applyNFT commits rs. A failed commit leaves the previous rules in force
// and keeps the connection; only a broken socket is replaced, via
// Reconnect with d.desired (for a switch: the pre-switch state).
func (d *daemon) applyNFT(rs nftable.Ruleset, reason string) ([]nftable.Counter, error) {
	before, err := d.nft.Apply(rs)
	if err == nil {
		d.dirty = false
		return before, nil
	}
	d.dirty = true
	d.nftError("apply", reason, err)
	if errors.Is(err, nftable.ErrConnBroken) {
		d.reconnectNFT(d.desired, reason)
	}
	return nil, err
}

// reconnectNFT replaces the lasting connection and rebuilds rs, which is
// always d.desired. Reconnect closes the old socket first, so the table is
// briefly absent.
func (d *daemon) reconnectNFT(rs nftable.Ruleset, reason string) {
	if err := d.nft.Reconnect(rs); err != nil {
		// A failed creation leaves the Manager without a connection: the
		// next Apply returns ErrConnBroken and reconnects again.
		d.dirty = true
		d.nftError("reconnect", reason, err)
		return
	}
	d.dirty = false
	info := d.nft.Info()
	d.log.Warn("nft reconnect", "reason", reason, "table", info.Name, "owner", info.Owner,
		"listen_port", rs.ListenPort, "denied", epsAttr(rs.Denied))
}

func (d *daemon) nftError(op, reason string, err error) {
	d.nftErr, d.nftErrAt = op+": "+err.Error(), d.wall()
	d.log.Warn("nft error", "op", op, "reason", reason, "error", err)
}

// syncNFT retries the desired rules while they are not known to be in force
// (a failed or unknown commit, or a failed reconnect).
func (d *daemon) syncNFT() {
	if d.nft == nil || d.state != status.StateRunning {
		return
	}
	if !d.dirty && d.nft.Committed().Equal(d.desired) {
		return
	}
	d.rebuild("retry")
}

// logSwitch logs a switch event headline followed by the full decision
// record, one line per endpoint and per rule.
func (d *daemon) logSwitch(level slog.Level, msg string, ev status.SwitchEvent, dec policy.Decision, extra ...any) {
	rec := dec.Record
	attrs := []any{"switch_id", ev.ID, "kind", string(dec.Kind), "from", epAttr(dec.From), "to", epAttr(dec.To),
		"reason", dec.Reason, "cooldown_left", rec.CooldownLeft.Round(time.Millisecond), "gap", rec.Gap}
	for _, r := range rec.Rules {
		if r.Rule == ruleOf(dec.Kind) && (r.Rule != policy.RuleRestore || r.Target == dec.To) {
			attrs = append(attrs, "rule", r.Rule)
			switch r.Rule {
			case policy.RuleOutage:
				attrs = append(attrs, "outage_run", r.Run, "outage_k", r.K)
			case policy.RuleDegrade:
				attrs = append(attrs, "rule_value", r.Value, "rule_hold", r.Hold)
			case policy.RuleRestore:
				attrs = append(attrs, "rule_value", r.Value, "rule_hold", r.Hold, "restore_level", r.Level)
			}
			break
		}
	}
	for _, v := range rec.Endpoints {
		switch v.Addr {
		case dec.From:
			attrs = append(attrs, "cost_from", round(float64(v.Cost)), "biased_from", round(float64(v.BiasedCost)))
		case dec.To:
			attrs = append(attrs, "cost_to", round(float64(v.Cost)), "biased_to", round(float64(v.BiasedCost)))
			if g := v.Gate; g != nil {
				attrs = append(attrs, gateAttrs(g)...)
			}
		}
	}
	if len(ev.Denied) > 0 {
		attrs = append(attrs, "denied", epsAttr(ev.Denied))
	}
	attrs = append(attrs, extra...)
	d.log.Log(context.Background(), level, msg, attrs...)
	for _, v := range rec.Endpoints {
		d.log.Log(context.Background(), level, "switch record endpoint", append([]any{"switch_id", ev.ID}, endpointAttrs(v)...)...)
	}
	for _, r := range rec.Rules {
		d.log.Log(context.Background(), level, "switch record rule", append([]any{"switch_id", ev.ID}, ruleAttrs(r)...)...)
	}
}

func ruleOf(k policy.Kind) string {
	switch k {
	case policy.KindOutage:
		return policy.RuleOutage
	case policy.KindDegrade:
		return policy.RuleDegrade
	case policy.KindRestore:
		return policy.RuleRestore
	case policy.KindReload:
		return policy.RuleReload
	}
	return policy.RuleStartup
}
