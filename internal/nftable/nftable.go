// Package nftable manages the daemon-owned nftables deny-list.
//
// The table is `table inet <name>` with one base chain `input` (type filter,
// hook input, priority filter - 5, policy accept). It is created with the
// owner flag over a single lasting netlink connection, so the kernel deletes
// it as soon as that socket closes, however the process exits. Every
// operation goes through that connection; a second connection cannot modify
// an owned table.
//
// A Manager is not safe for concurrent use; the daemon's event loop owns it.
package nftable

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/bjin/wgsteer/internal/endpoints"
)

const (
	chainName = "input"

	// maxReadFailures is the number of consecutive failed read-backs over
	// the lasting connection (Apply's counter read and unknown-outcome
	// check, Verify, Counters) after which the socket is declared unusable
	// and ErrConnBroken is returned. Any successful read resets the count.
	maxReadFailures = 3

	// udTypeTuple is the userdata TLV type that identifies the daemon's
	// rules. nft ignores unknown TLV types, so listings stay comment-free.
	udTypeTuple userdata.Type = 0xd7
	udPrefix                  = "wgsteer "
)

var (
	// ErrOwnedElsewhere means the table exists and is owned by another live
	// netlink socket: a second instance for the same device.
	ErrOwnedElsewhere = errors.New("nft table owned by another process")
	// ErrNoOwnerSupport means the kernel cannot create owner-flag tables
	// (Linux < 5.12). There is no unowned fallback.
	ErrNoOwnerSupport = errors.New("kernel does not support nft owner-flag tables (needs Linux >= 5.12)")
	// ErrRejected means the transaction did not take effect: the previously
	// committed rules (Committed) are still in force and the connection is
	// kept. Retry later on the same Manager.
	ErrRejected = errors.New("nft transaction rejected")
	// ErrUnknown means the transaction outcome could not be determined: the
	// kernel holds either Committed() or the requested rules. Verify later.
	ErrUnknown = errors.New("nft transaction outcome unknown")
	// ErrConnBroken means the lasting socket is unusable; the caller must
	// call Reconnect.
	ErrConnBroken = errors.New("nft netlink connection broken")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("nft manager closed")
)

// Counter is the drop counter of one denied tuple.
type Counter struct {
	Addr    netip.AddrPort
	Packets uint64
	Bytes   uint64
}

// TableInfo describes the created table, as read back from the kernel.
type TableInfo struct {
	Name  string // table name; family is always inet
	Chain string // base chain name
	// OwnerFlag and Owner are the table's owner flag and owning netlink
	// port ID, both confirmed by reading the table back.
	OwnerFlag bool
	Owner     uint32
	// ReplacedStale reports that an unowned table with the same name existed
	// and was deleted in the creation transaction.
	ReplacedStale bool
}

// Manager owns the table and the lasting netlink connection.
type Manager struct {
	table     *nftables.Table
	chain     *nftables.Chain
	conn      *nftables.Conn // nil after Close or a failed Reconnect
	closed    bool
	info      TableInfo
	committed Ruleset
	readFails int

	// flush replaces conn.Flush in tests to inject failures.
	flush func(*nftables.Conn) error
}

// Open creates the owner-flag table over a new lasting connection that lives
// until Close or Reconnect. An existing table owned by another socket yields
// ErrOwnedElsewhere; an existing unowned table is stale and is deleted inside
// the creation transaction. A table that does not read back with the owner
// flag yields ErrNoOwnerSupport.
func Open(table string) (*Manager, error) {
	if table == "" || len(table) >= unix.NFT_NAME_MAXLEN {
		return nil, fmt.Errorf("nftable: invalid table name %q", table)
	}
	t := &nftables.Table{Name: table, Family: nftables.TableFamilyINet, Flags: nftables.TableFlagOwner}
	m := &Manager{
		table: t,
		chain: &nftables.Chain{
			Name:     chainName,
			Table:    t,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookInput,
			Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityFilter - 5),
			Policy:   new(nftables.ChainPolicyAccept),
		},
	}
	if err := m.connect(); err != nil {
		return nil, err
	}
	return m, nil
}

// connect opens a lasting connection and creates the table on it. On error
// the new connection is closed and m.conn stays nil.
func (m *Manager) connect() error {
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return fmt.Errorf("nftable: open netlink connection: %w", err)
	}
	info, err := m.create(conn)
	if err != nil {
		_ = conn.CloseLasting()
		return err
	}
	m.conn = conn
	m.info = info
	m.committed = Ruleset{}
	m.readFails = 0
	return nil
}

func (m *Manager) create(conn *nftables.Conn) (TableInfo, error) {
	name := m.table.Name
	info := TableInfo{Name: name, Chain: chainName}

	existing, err := findTable(conn, name)
	if err != nil {
		return info, fmt.Errorf("nftable: list tables: %w", err)
	}
	if existing != nil {
		if existing.Flags&nftables.TableFlagOwner != 0 {
			return info, fmt.Errorf("%w: table inet %s, owner netlink port %d", ErrOwnedElsewhere, name, existing.Owner)
		}
		conn.DelTable(existing)
		info.ReplacedStale = true
	}
	conn.CreateTable(m.table)
	conn.AddChain(m.chain)
	if err := conn.Flush(); err != nil {
		switch {
		case errors.Is(err, unix.EOPNOTSUPP):
			return info, fmt.Errorf("%w: create table inet %s: %w", ErrNoOwnerSupport, name, err)
		case errors.Is(err, unix.EPERM) || errors.Is(err, unix.EEXIST):
			// Lost a race against another instance that created the table
			// between our listing and our transaction.
			return info, fmt.Errorf("%w: create table inet %s: %w", ErrOwnedElsewhere, name, err)
		}
		return info, fmt.Errorf("nftable: create table inet %s: %w", name, err)
	}

	got, err := findTable(conn, name)
	if err == nil && got == nil {
		err = errors.New("table missing after creation")
	}
	if err != nil {
		return info, fmt.Errorf("nftable: read back table inet %s: %w", name, err)
	}
	port, err := conn.GetPortID()
	if err != nil {
		return info, fmt.Errorf("nftable: netlink port ID: %w", err)
	}
	info.OwnerFlag = got.Flags&nftables.TableFlagOwner != 0
	info.Owner = got.Owner
	if !info.OwnerFlag || got.Owner != port {
		conn.DelTable(m.table)
		_ = conn.Flush()
		return info, fmt.Errorf("%w: table inet %s read back with flags %#x owner %d, want owner flag and port %d",
			ErrNoOwnerSupport, name, uint32(got.Flags), got.Owner, port)
	}
	return info, nil
}

func findTable(conn *nftables.Conn, name string) (*nftables.Table, error) {
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil, err
	}
	for _, t := range tables {
		if t.Name == name {
			return t, nil
		}
	}
	return nil, nil
}

// Info describes the table as created by Open or the last Reconnect.
func (m *Manager) Info() TableInfo { return m.info }

// Committed returns the last rule set known to be in force: the last one
// Apply confirmed (by ACK or read-back). It is empty right after Open or
// Reconnect until the first successful Apply.
func (m *Manager) Committed() Ruleset { return m.committed }

func (m *Manager) usable() error {
	if m.closed {
		return ErrClosed
	}
	if m.conn == nil {
		return fmt.Errorf("%w: no connection (Reconnect failed)", ErrConnBroken)
	}
	return nil
}

// Apply replaces the chain's rules with rs in one atomic transaction (flush
// the chain, then add one `udp dport L ip[6] saddr A udp sport p counter
// drop` rule per denied tuple). before holds the counters read just before
// the transaction; it is nil if that read failed, which does not stop the
// transaction.
//
// Errors:
//   - ErrRejected: the kernel rejected the batch (or a read-back after an
//     unknown outcome shows the old rules); Committed() is still in force
//     and the connection is kept.
//   - ErrUnknown: the outcome is unknown and reading the chain back failed.
//   - ErrConnBroken: sending failed at the socket level, or read-back has
//     failed maxReadFailures times in a row. Call Reconnect.
//   - ErrClosed after Close.
//
// An unknown outcome (any receive error that is not a kernel error reply,
// e.g. ENOBUFS) is resolved by reading the chain back: a match returns nil.
func (m *Manager) Apply(rs Ruleset) (before []Counter, err error) {
	if err := m.usable(); err != nil {
		return nil, err
	}
	rs = rs.canonical()

	if states, err := m.readChain(); err == nil {
		before = countersOf(states)
	}

	m.conn.FlushChain(m.chain)
	for _, ap := range rs.Denied {
		m.conn.AddRule(&nftables.Rule{
			Table:    m.table,
			Chain:    m.chain,
			Exprs:    ruleExprs(rs.ListenPort, ap),
			UserData: ruleUserData(rs.ListenPort, ap),
		})
	}
	flush := (*nftables.Conn).Flush
	if m.flush != nil {
		flush = m.flush
	}
	ferr := flush(m.conn)
	if ferr == nil {
		m.committed = rs
		return before, nil
	}

	switch classify(ferr) {
	case outcomeRejected:
		return before, fmt.Errorf("%w: %w", ErrRejected, ferr)
	case outcomeBroken:
		return before, fmt.Errorf("%w: %w", ErrConnBroken, ferr)
	}

	ok, verr := m.Verify(rs)
	switch {
	case verr != nil && errors.Is(verr, ErrConnBroken):
		return before, fmt.Errorf("transaction (%w), then %w", ferr, verr)
	case verr != nil:
		return before, fmt.Errorf("%w: transaction: %w; read-back: %w", ErrUnknown, ferr, verr)
	case ok:
		m.committed = rs
		return before, nil
	default:
		return before, fmt.Errorf("%w: read-back after unknown outcome shows the old rules: %w", ErrRejected, ferr)
	}
}

type outcome int

const (
	outcomeUnknown outcome = iota
	outcomeRejected
	outcomeBroken
)

// classify sorts a Flush error. A netlink error reply carries the sequence
// number of the offending message: the kernel processed and aborted the
// whole batch. A send failure means the socket is unusable. Everything else
// (e.g. ENOBUFS while receiving the replies) leaves the outcome unknown.
func classify(err error) outcome {
	var op *netlink.OpError
	if !errors.As(err, &op) {
		return outcomeUnknown
	}
	switch {
	case strings.HasPrefix(op.Op, "send"):
		return outcomeBroken
	case op.Op == "receive" && op.Sequence != 0:
		return outcomeRejected
	}
	return outcomeUnknown
}

// Verify reads the chain back over the lasting connection and reports whether
// it holds exactly the rules Apply(rs) installs. A read failure is returned
// as an error, wrapping ErrConnBroken once maxReadFailures consecutive reads
// have failed.
func (m *Manager) Verify(rs Ruleset) (bool, error) {
	if err := m.usable(); err != nil {
		return false, err
	}
	states, err := m.readChain()
	if err != nil {
		return false, err
	}
	rs = rs.canonical()
	if len(states) != len(rs.Denied) {
		return false, nil
	}
	for i, s := range states {
		if !s.valid || s.port != rs.ListenPort || s.addr != rs.Denied[i] {
			return false, nil
		}
	}
	return true, nil
}

// Counters reads the current drop counters over the lasting connection, in
// chain order. Errors follow Verify.
func (m *Manager) Counters() ([]Counter, error) {
	if err := m.usable(); err != nil {
		return nil, err
	}
	states, err := m.readChain()
	if err != nil {
		return nil, err
	}
	return countersOf(states), nil
}

// Reconnect replaces the connection: it closes the old lasting socket first
// (the kernel deletes the owned table, so the device roams freely until the
// rebuild), then opens a new one, recreates the table and applies rs. It
// never has two sockets open at once. Apply errors are returned as is; the
// table then exists with an empty chain. On a creation error the Manager has
// no connection and further calls return ErrConnBroken until a later
// Reconnect succeeds.
func (m *Manager) Reconnect(rs Ruleset) error {
	if m.closed {
		return ErrClosed
	}
	if m.conn != nil {
		err := m.conn.CloseLasting()
		m.conn = nil
		m.committed = Ruleset{}
		if err != nil {
			return fmt.Errorf("nftable: close old connection: %w", err)
		}
	}
	if err := m.connect(); err != nil {
		return err
	}
	_, err := m.Apply(rs)
	return err
}

// Close deletes the table explicitly, then closes the lasting connection
// (which would delete the owned table anyway).
func (m *Manager) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	if m.conn == nil {
		return nil
	}
	conn := m.conn
	m.conn = nil
	conn.DelTable(m.table)
	var errs []error
	if err := conn.Flush(); err != nil {
		errs = append(errs, fmt.Errorf("nftable: delete table inet %s: %w", m.table.Name, err))
	}
	if err := conn.CloseLasting(); err != nil {
		errs = append(errs, fmt.Errorf("nftable: close connection: %w", err))
	}
	return errors.Join(errs...)
}

// ruleState is one rule read back from the chain.
type ruleState struct {
	port    uint16
	addr    netip.AddrPort
	packets uint64
	bytes   uint64
	// valid: the userdata decodes and the expressions are exactly the ones
	// Apply builds for that tuple.
	valid bool
}

func (m *Manager) readChain() ([]ruleState, error) {
	rules, err := m.conn.GetRules(m.table, m.chain)
	if err != nil {
		m.readFails++
		if m.readFails >= maxReadFailures {
			return nil, fmt.Errorf("%w: %d consecutive read-backs failed: %w", ErrConnBroken, m.readFails, err)
		}
		return nil, fmt.Errorf("nftable: read chain %s: %w", chainName, err)
	}
	m.readFails = 0
	states := make([]ruleState, len(rules))
	for i, r := range rules {
		states[i] = parseRule(r)
	}
	return states, nil
}

func parseRule(r *nftables.Rule) ruleState {
	var s ruleState
	port, addr, ok := parseUserData(r.UserData)
	if !ok {
		return s
	}
	s.port, s.addr = port, addr
	exprs := make([]expr.Any, len(r.Exprs))
	copy(exprs, r.Exprs)
	for i, e := range exprs {
		if c, ok := e.(*expr.Counter); ok {
			s.packets, s.bytes = c.Packets, c.Bytes
			exprs[i] = &expr.Counter{}
		}
	}
	s.valid = reflect.DeepEqual(exprs, ruleExprs(port, addr))
	return s
}

func countersOf(states []ruleState) []Counter {
	out := make([]Counter, 0, len(states))
	for _, s := range states {
		if s.valid {
			out = append(out, Counter{Addr: s.addr, Packets: s.packets, Bytes: s.bytes})
		}
	}
	return out
}

func ruleUserData(port uint16, ap netip.AddrPort) []byte {
	return userdata.AppendString(nil, udTypeTuple, udPrefix+strconv.Itoa(int(port))+" "+ap.String())
}

func parseUserData(ud []byte) (uint16, netip.AddrPort, bool) {
	v, ok := userdata.GetString(ud, udTypeTuple)
	if !ok {
		return 0, netip.AddrPort{}, false
	}
	rest, ok := strings.CutPrefix(v, udPrefix)
	if !ok {
		return 0, netip.AddrPort{}, false
	}
	ps, as, ok := strings.Cut(rest, " ")
	if !ok {
		return 0, netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(ps, 10, 16)
	if err != nil {
		return 0, netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(as)
	if err != nil {
		return 0, netip.AddrPort{}, false
	}
	return uint16(port), endpoints.Normalize(ap), true
}

// ruleExprs builds `udp dport L ip[6] saddr A udp sport p counter drop` with
// the same dependencies nft generates (meta l4proto udp before the first
// transport match, meta nfproto before the network match), so `nft list`
// renders it in exactly that order.
func ruleExprs(port uint16, ap netip.AddrPort) []expr.Any {
	nfproto, offset := byte(unix.NFPROTO_IPV4), uint32(12)
	if ap.Addr().Is6() {
		nfproto, offset = unix.NFPROTO_IPV6, 8
	}
	addr := ap.Addr().AsSlice()
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be16(port)},
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(addr))},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be16(ap.Port())},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

func be16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
