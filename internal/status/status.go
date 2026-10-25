// Package status defines the daemon's immutable status snapshot.
// The event loop builds a Status after every handled event and publishes it
// atomically; every reader (SIGUSR1 dump, periodic summary, a future HTTP
// handler) reads only snapshots. All times are wall-clock times; durations
// are time.Duration (JSON: nanoseconds).
package status

import (
	"net/netip"
	"time"

	"github.com/bjin/wgsteer/internal/policy"
)

// HistorySize is the number of switch events kept in a snapshot.
const HistorySize = 50

// State is the daemon's lifecycle state.
type State string

// Daemon states.
const (
	// StateWaitingDevice: startup is waiting for the device to appear.
	StateWaitingDevice State = "waiting-device"
	// StateRunning: the device and its managed peer are present.
	StateRunning State = "running"
	// StateDetached: the device or its managed peer disappeared (or failed
	// re-validation); probing continues, nft is left alone.
	StateDetached State = "detached"
	// StateStopping: a clean shutdown is in progress.
	StateStopping State = "stopping"
)

// Result is the outcome of a switch event.
type Result string

// Switch results.
const (
	// ResultOK: nft committed and the device endpoint was set.
	ResultOK Result = "ok"
	// ResultSetFailed: nft committed, but setting the device endpoint
	// failed; the selection still changed and reconcile repairs the device.
	ResultSetFailed Result = "set-failed"
	// ResultAborted: the nft commit failed; nothing changed.
	ResultAborted Result = "aborted"
	// ResultDryRun: a simulated switch in --dry-run.
	ResultDryRun Result = "dry-run"
)

// Status is one immutable snapshot of the daemon.
type Status struct {
	// At is when the snapshot was built.
	At        time.Time  `json:"at"`
	Daemon    Daemon     `json:"daemon"`
	Device    Device     `json:"device"`
	Selection Selection  `json:"selection"`
	Probe     Probe      `json:"probe"`
	Endpoints []Endpoint `json:"endpoints"`
	NFT       NFT        `json:"nft"`
	// History holds the most recent switch events, oldest first (at most
	// HistorySize).
	History []SwitchEvent `json:"history"`
}

// Daemon describes the process.
type Daemon struct {
	Version   string    `json:"version"`
	Revision  string    `json:"revision,omitempty"`
	GoVersion string    `json:"go_version"`
	PID       int       `json:"pid"`
	StartTime time.Time `json:"start_time"`
	State     State     `json:"state"`
	DryRun    bool      `json:"dry_run"`
}

// Device is the live WireGuard device as last read.
type Device struct {
	Name string `json:"name"`
	// Present reports that the device and its managed peer were found and
	// validated on the last read.
	Present   bool   `json:"present"`
	Type      string `json:"type,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	// Peer is the managed peer's public key.
	Peer       string         `json:"peer"`
	ListenPort int            `json:"listen_port"`
	Fwmark     uint32         `json:"fwmark"`
	Endpoint   netip.AddrPort `json:"endpoint,omitzero"`
	// Listed reports that Endpoint is in the endpoint list.
	Listed bool `json:"listed"`
	// Alias reports that Endpoint is a learned alias of the selection.
	Alias         bool          `json:"alias"`
	Keepalive     time.Duration `json:"keepalive"`
	LastHandshake time.Time     `json:"last_handshake,omitzero"`
	// HandshakeAge is At − LastHandshake (0 without a handshake).
	HandshakeAge time.Duration `json:"handshake_age"`
	RxBytes      int64         `json:"rx_bytes"`
	TxBytes      int64         `json:"tx_bytes"`
}

// Selection is the selected endpoint and the decision state around it.
type Selection struct {
	// Endpoint is the selection; zero when none (startup on an unlisted
	// endpoint, or a reload removed it).
	Endpoint netip.AddrPort `json:"endpoint,omitzero"`
	// Index is Endpoint's list position, −1 without a selection.
	Index int       `json:"index"`
	Since time.Time `json:"since"`
	// Reason says how the selection was made.
	Reason string `json:"reason"`
	// Removed is a selection dropped by a list reload, until the next switch.
	Removed netip.AddrPort `json:"removed,omitzero"`
	// Aliases are unlisted endpoints observed on the device while this
	// selection was active.
	Aliases      []netip.AddrPort `json:"aliases"`
	CooldownLeft time.Duration    `json:"cooldown_left"`
	// Rules are the accumulators and outage state of the last tick.
	Rules []policy.RuleState `json:"rules"`
	// RestoreLevels lists endpoints with a nonzero restore backoff level.
	RestoreLevels []RestoreLevel `json:"restore_levels"`
	// Decision is the last tick's outcome.
	Decision Decision `json:"decision"`
	// LastSwitch is the most recent switch event of any result.
	LastSwitch *SwitchEvent `json:"last_switch,omitempty"`
	// Verified reports whether the last executed switch was verified on the
	// device; nil while pending or without one.
	Verified *bool `json:"verified,omitempty"`
}

// RestoreLevel is one endpoint's revert backoff level (hold = WTR·2^level).
type RestoreLevel struct {
	Endpoint netip.AddrPort `json:"endpoint"`
	Level    int            `json:"level"`
}

// Decision is the outcome of one policy tick.
type Decision struct {
	At      time.Time      `json:"at,omitzero"`
	Switch  bool           `json:"switch"`
	Kind    policy.Kind    `json:"kind,omitempty"`
	To      netip.AddrPort `json:"to,omitzero"`
	Blocker policy.Blocker `json:"blocker,omitempty"`
	Reason  string         `json:"reason"`
}

// Probe is the probe device and its current slot.
type Probe struct {
	PublicKey  string     `json:"public_key"`
	ProbeAddr  netip.Addr `json:"probe_addr"`
	Target     netip.Addr `json:"target"`
	ListenPort uint16     `json:"listen_port"`
	Fwmark     uint32     `json:"fwmark"`
	// SessionValid reports a usable probe session at the last slot start.
	SessionValid  bool          `json:"session_valid"`
	LastHandshake time.Time     `json:"last_handshake,omitzero"`
	SessionAge    time.Duration `json:"session_age"`
	// Slot is the current or most recent slot.
	Slot    *Slot  `json:"slot,omitempty"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

// Slot is one probe slot.
type Slot struct {
	Endpoint netip.AddrPort `json:"endpoint"`
	Index    int            `json:"index"`
	Seq      uint16         `json:"seq"`
	Start    time.Time      `json:"start"`
	Valid    bool           `json:"valid"`
	Pending  bool           `json:"pending"`
}

// Endpoint is one listed endpoint: the decision trace view plus its deny
// rule state.
type Endpoint struct {
	policy.EndpointView
	Family string `json:"family"`
	// Denied reports a drop rule for this endpoint in the committed rules.
	Denied      bool   `json:"denied"`
	DenyPackets uint64 `json:"deny_packets"`
	DenyBytes   uint64 `json:"deny_bytes"`
}

// NFT is the daemon-owned table.
type NFT struct {
	// Enabled is false in --dry-run (no table exists).
	Enabled    bool   `json:"enabled"`
	Table      string `json:"table"`
	Chain      string `json:"chain,omitempty"`
	OwnerFlag  bool   `json:"owner_flag"`
	Owner      uint32 `json:"owner"`
	ListenPort uint16 `json:"listen_port"`
	// Denied are the committed drop rules with their counters.
	Denied []Counter `json:"denied"`
	// InSync reports that the committed rules equal the desired rules.
	InSync      bool      `json:"in_sync"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitzero"`
}

// Counter is the drop counter of one denied tuple.
type Counter struct {
	Endpoint netip.AddrPort `json:"endpoint"`
	Packets  uint64         `json:"packets"`
	Bytes    uint64         `json:"bytes"`
}

// SwitchEvent is one executed, simulated or aborted switch.
type SwitchEvent struct {
	ID     int            `json:"id"`
	At     time.Time      `json:"at"`
	Kind   policy.Kind    `json:"kind"`
	From   netip.AddrPort `json:"from,omitzero"`
	To     netip.AddrPort `json:"to"`
	Result Result         `json:"result"`
	Error  string         `json:"error,omitempty"`
	Reason string         `json:"reason"`
	// BlockSetGap is the time from the nft commit ACK until the device
	// endpoint (and kick) was set.
	BlockSetGap time.Duration `json:"block_set_gap,omitempty"`
	// Denied is the deny-list the switch committed (or tried to).
	Denied []netip.AddrPort `json:"denied,omitempty"`
	Record policy.Record    `json:"record"`
}
