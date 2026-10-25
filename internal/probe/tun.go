package probe

import (
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// outboundQueueLen bounds echo requests waiting for wireguard-go to read them.
const outboundQueueLen = 16

// errQueueFull is returned by Send when wireguard-go is not reading the TUN.
var errQueueFull = errors.New("probe TUN queue full")

// chanTUN is a tun.Device backed by channels. Read hands crafted echo
// requests to wireguard-go and stamps their send time; Write receives the
// decrypted packets from the server and turns valid echo replies into
// Replies. Everything else written is discarded.
type chanTUN struct {
	start   time.Time // monotonic base for SentAt/RecvAt
	target  netip.Addr
	ident   uint16
	mtu     int
	out     chan []byte
	replies chan Reply
	events  chan tun.Event
	closed  chan struct{}
	once    sync.Once
	log     *slog.Logger
}

func newChanTUN(start time.Time, target netip.Addr, ident uint16, mtu int, replies chan Reply, log *slog.Logger) *chanTUN {
	t := &chanTUN{
		start:   start,
		target:  target,
		ident:   ident,
		mtu:     mtu,
		out:     make(chan []byte, outboundQueueLen),
		replies: replies,
		events:  make(chan tun.Event, 1),
		closed:  make(chan struct{}),
		log:     log,
	}
	t.events <- tun.EventUp
	return t
}

// enqueue queues a crafted packet for wireguard-go without blocking.
func (t *chanTUN) enqueue(pkt []byte) error {
	select {
	case <-t.closed:
		return os.ErrClosed
	default:
	}
	select {
	case t.out <- pkt:
		return nil
	default:
		return errQueueFull
	}
}

func (t *chanTUN) File() *os.File { return nil }

// Read blocks until a probe packet is queued or the device is closed. The
// send timestamp is stamped here, at the moment wireguard-go takes the packet.
func (t *chanTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case pkt := <-t.out:
		buf := bufs[0][offset:]
		n := copy(buf, pkt)
		stampEcho(buf[:n], time.Since(t.start))
		sizes[0] = n
		return 1, nil
	}
}

// Write receives decrypted packets from the server. The receive timestamp is
// taken on entry. Valid echo replies are delivered without blocking; if the
// reply channel is full they are dropped (and so count as loss).
func (t *chanTUN) Write(bufs [][]byte, offset int) (int, error) {
	recvAt := time.Since(t.start)
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	default:
	}
	for _, b := range bufs {
		f, ok := parseEchoReply(b[offset:], t.target, t.ident)
		if !ok {
			continue
		}
		r := Reply{Seq: f.Seq, Nonce: f.Nonce, EndpointID: f.EndpointID, SentAt: f.SentAt, RecvAt: recvAt}
		select {
		case t.replies <- r:
		default:
			t.log.Debug("probe reply dropped: reply channel full", "seq", f.Seq)
		}
	}
	return len(bufs), nil
}

func (t *chanTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *chanTUN) Name() (string, error)    { return "probe", nil }
func (t *chanTUN) Events() <-chan tun.Event { return t.events }
func (t *chanTUN) BatchSize() int           { return 1 }

// Close unblocks Read and closes the event channel. It is idempotent.
func (t *chanTUN) Close() error {
	t.once.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}
