package probe

import (
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

const testOffset = 16 // wireguard-go's MessageTransportHeaderSize

func newTestTUN(t *testing.T, replies chan Reply) *chanTUN {
	t.Helper()
	tn := newChanTUN(time.Now(), v4Target, 0x1234, DefaultMTU, replies, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { tn.Close() })
	return tn
}

func TestChanTUNReadStampsSendTime(t *testing.T) {
	tn := newTestTUN(t, make(chan Reply, 1))
	pkt := buildEcho(v4Probe, v4Target, echoFields{ID: 0x1234, Seq: 1, Nonce: 2, EndpointID: 3}, 56)
	if err := tn.enqueue(pkt); err != nil {
		t.Fatal(err)
	}
	before := time.Since(tn.start)
	bufs := [][]byte{make([]byte, 2048)}
	sizes := []int{0}
	n, err := tn.Read(bufs, sizes, testOffset)
	after := time.Since(tn.start)
	if err != nil || n != 1 || sizes[0] != len(pkt) {
		t.Fatalf("Read = %d, %v (size %d)", n, err, sizes[0])
	}
	got := bufs[0][testOffset : testOffset+sizes[0]]
	verifyChecksums(t, got)
	f, ok := parseEchoReply(echoReplyOf(t, got), v4Target, 0x1234)
	if !ok {
		t.Fatal("stamped packet does not round-trip")
	}
	if f.SentAt < before || f.SentAt > after {
		t.Errorf("SentAt %v not within Read [%v, %v]", f.SentAt, before, after)
	}
}

func TestChanTUNWriteFiltersAndNeverBlocks(t *testing.T) {
	replies := make(chan Reply, 1)
	tn := newTestTUN(t, replies)
	req := buildEcho(v4Probe, v4Target, echoFields{ID: 0x1234, Seq: 9, Nonce: 10, EndpointID: 11}, 56)
	stampEcho(req, 5*time.Millisecond)
	good := echoReplyOf(t, req)
	other := echoReplyOf(t, buildEcho(v4Probe, v4Target, echoFields{ID: 0x9999, Seq: 9}, 56))

	frame := func(p []byte) []byte { return append(make([]byte, testOffset), p...) }
	// Another host's echo, the request itself, garbage, then two valid
	// replies: the second must be dropped (channel full) without blocking.
	bufs := [][]byte{frame(other), frame(req), frame([]byte{0x45, 0}), frame(good), frame(good)}
	if n, err := tn.Write(bufs, testOffset); n != len(bufs) || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if len(replies) != 1 {
		t.Fatalf("%d replies delivered, want 1", len(replies))
	}
	r := <-replies
	if r.Seq != 9 || r.Nonce != 10 || r.EndpointID != 11 || r.SentAt != 5*time.Millisecond {
		t.Errorf("reply %+v", r)
	}
	if r.RecvAt <= 0 || r.RTT() != r.RecvAt-r.SentAt {
		t.Errorf("RecvAt %v, RTT %v", r.RecvAt, r.RTT())
	}
}

func TestChanTUNClose(t *testing.T) {
	tn := newTestTUN(t, make(chan Reply, 1))
	if ev := <-tn.Events(); ev != tun.EventUp {
		t.Fatalf("first event %v, want EventUp", ev)
	}
	if mtu, _ := tn.MTU(); mtu != DefaultMTU || tn.BatchSize() != 1 {
		t.Errorf("MTU %d, BatchSize %d", mtu, tn.BatchSize())
	}
	done := make(chan error)
	go func() {
		_, err := tn.Read([][]byte{make([]byte, 2048)}, []int{0}, 0)
		done <- err
	}()
	tn.Close()
	tn.Close() // idempotent
	if err := <-done; !errors.Is(err, os.ErrClosed) {
		t.Errorf("blocked Read returned %v, want os.ErrClosed", err)
	}
	if _, ok := <-tn.Events(); ok {
		t.Error("events channel not closed")
	}
	if err := tn.enqueue([]byte{1}); !errors.Is(err, os.ErrClosed) {
		t.Errorf("enqueue after Close = %v", err)
	}
	if _, err := tn.Write([][]byte{make([]byte, 64)}, 0); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Write after Close = %v", err)
	}
}

func TestChanTUNQueueFull(t *testing.T) {
	tn := newTestTUN(t, make(chan Reply, 1))
	for range outboundQueueLen {
		if err := tn.enqueue([]byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tn.enqueue([]byte{1}); !errors.Is(err, errQueueFull) {
		t.Errorf("enqueue on full queue = %v, want errQueueFull", err)
	}
}
