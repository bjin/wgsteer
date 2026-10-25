package daemon

import (
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/bjin/wgsteer/internal/endpoints"
	"github.com/bjin/wgsteer/internal/nftable"
	"github.com/bjin/wgsteer/internal/policy"
	"github.com/bjin/wgsteer/internal/status"
)

// publish rebuilds and publishes the immutable snapshot.
func (d *daemon) publish() { d.snap.Store(d.snapshot()) }

// wallAt converts a loop-clock time to wall time; zero stays zero.
func (d *daemon) wallAt(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return d.wall().Add(t.Sub(d.clock.Now())).Round(time.Millisecond)
}

// wallRecord copies a decision record with every loop-clock time converted
// to wall time, so snapshots only hold wall times.
func (d *daemon) wallRecord(r policy.Record) policy.Record {
	r.At = d.wallAt(r.At)
	r.Endpoints = slices.Clone(r.Endpoints)
	for i := range r.Endpoints {
		v := &r.Endpoints[i]
		if v.Last != nil {
			last := *v.Last
			last.At = d.wallAt(last.At)
			v.Last = &last
		}
		v.LastInvalid = d.wallAt(v.LastInvalid)
	}
	r.Rules = slices.Clone(r.Rules)
	return r
}

func (d *daemon) snapshot() *status.Status {
	now := d.wall().Round(time.Millisecond)
	s := &status.Status{
		At: now,
		Daemon: status.Daemon{
			Version:   d.build.version,
			Revision:  d.build.revision,
			GoVersion: d.build.goVersion,
			PID:       os.Getpid(),
			StartTime: d.startWall.Round(time.Millisecond),
			State:     d.state,
			DryRun:    d.cfg.DryRun,
		},
		Selection: status.Selection{Index: -1, Reason: d.selReason, Removed: d.removed,
			Aliases: slices.Clone(d.aliases), Verified: d.verified},
		History: slices.Clone(d.history),
	}
	if d.ident != nil {
		s.Device.Peer = d.ident.PeerKey.String()
	}

	// Device.
	s.Device.Name = d.cfg.Device
	s.Device.Present = d.state == status.StateRunning
	if dev := d.devInfo; dev != nil {
		p := d.peer
		s.Device.Type = dev.Type
		s.Device.PublicKey = dev.PublicKey.String()
		s.Device.ListenPort = dev.ListenPort
		s.Device.Fwmark = dev.Fwmark
		s.Device.Endpoint = p.Endpoint
		s.Device.Listed = endpoints.Index(d.list, p.Endpoint) >= 0
		s.Device.Alias = slices.Contains(d.aliases, p.Endpoint)
		s.Device.Keepalive = p.Keepalive
		s.Device.LastHandshake = p.LastHandshake
		if !p.LastHandshake.IsZero() {
			s.Device.HandshakeAge = now.Sub(p.LastHandshake)
		}
		s.Device.RxBytes, s.Device.TxBytes = p.RxBytes, p.TxBytes
	}

	// Selection and decision.
	if d.eng != nil {
		sel := d.eng.Selected()
		s.Selection.Endpoint = sel
		s.Selection.Index = endpoints.Index(d.list, sel)
		if s.Selection.Index >= 0 {
			s.Selection.Name = d.displayName(s.Selection.Index)
		}
		s.Selection.Since = d.wallAt(d.selSince)
	}
	var rec policy.Record
	if d.haveDecision {
		dec := d.decision
		rec = d.wallRecord(dec.Record)
		s.Selection.CooldownLeft = rec.CooldownLeft
		s.Selection.Rules = rec.Rules
		s.Selection.Decision = status.Decision{At: rec.At, Switch: dec.Switch, Kind: dec.Kind, To: dec.To,
			Blocker: dec.Blocker, Reason: dec.Reason}
		for _, v := range rec.Endpoints {
			if v.RestoreLevel > 0 {
				s.Selection.RestoreLevels = append(s.Selection.RestoreLevels, status.RestoreLevel{Endpoint: v.Addr, Level: v.RestoreLevel})
			}
		}
	}
	if n := len(d.history); n > 0 {
		last := d.history[n-1]
		s.Selection.LastSwitch = &last
	}

	// Probe.
	s.Probe = status.Probe{
		ProbeAddr:     d.cfg.ProbeAddr,
		Target:        d.cfg.Target,
		ListenPort:    d.probeState.ListenPort,
		Fwmark:        d.probeState.Fwmark,
		SessionValid:  d.sessionValid,
		LastHandshake: d.probeState.LastHandshake,
		RxBytes:       d.probeState.RxBytes,
		TxBytes:       d.probeState.TxBytes,
	}
	if !d.probeState.LastHandshake.IsZero() {
		s.Probe.SessionAge = now.Sub(d.probeState.LastHandshake)
	}
	if d.prb != nil {
		s.Probe.PublicKey = d.prb.PublicKey().String()
	}
	if d.slot.Endpoint.IsValid() {
		_, pending := d.sched.Pending()
		s.Probe.Slot = &status.Slot{Endpoint: d.slot.Endpoint, Index: d.slot.Index, Seq: d.slot.Seq,
			Start: d.wallAt(d.slot.Start), Valid: d.slot.Valid, Pending: pending}
		// The slot may predate a reload: name it only while still listed.
		if i := endpoints.Index(d.list, d.slot.Endpoint); i >= 0 {
			s.Probe.Slot.Name = d.displayName(i)
		}
	}

	// nft.
	var committed nftable.Ruleset
	counters := make(map[netip.AddrPort]nftable.Counter, len(d.counters))
	for _, c := range d.counters {
		counters[c.Addr] = c
	}
	s.NFT.Table = d.cfg.NftTable
	if d.nft != nil {
		info := d.nft.Info()
		committed = d.nft.Committed()
		s.NFT.Enabled = true
		s.NFT.Chain, s.NFT.OwnerFlag, s.NFT.Owner = info.Chain, info.OwnerFlag, info.Owner
		s.NFT.ListenPort = committed.ListenPort
		s.NFT.InSync = !d.dirty && committed.Equal(d.desired)
		for _, a := range committed.Denied {
			c := counters[a]
			s.NFT.Denied = append(s.NFT.Denied, status.Counter{Endpoint: a, Packets: c.Packets, Bytes: c.Bytes})
		}
	}
	s.NFT.LastError = d.nftErr
	s.NFT.LastErrorAt = d.nftErrAt

	// Endpoints.
	views := rec.Endpoints
	if views == nil {
		for i, a := range d.list {
			views = append(views, policy.EndpointView{Addr: a, Index: i, Name: d.displayName(i)})
		}
	}
	for _, v := range views {
		e := status.Endpoint{EndpointView: v, Family: endpoints.Family(v.Addr)}
		// The record is from the last tick; a switch since then moved the
		// selection.
		e.Active = s.Selection.Endpoint.IsValid() && v.Addr == s.Selection.Endpoint
		if slices.Contains(committed.Denied, v.Addr) {
			c := counters[v.Addr]
			e.Denied, e.DenyPackets, e.DenyBytes = true, c.Packets, c.Bytes
		}
		s.Endpoints = append(s.Endpoints, e)
	}
	return s
}
