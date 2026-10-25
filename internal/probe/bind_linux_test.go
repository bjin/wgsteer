package probe

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

// TestUDPBindSetMark needs CAP_NET_ADMIN (e.g. under `unshare -rn`).
func TestUDPBindSetMark(t *testing.T) {
	b, _, _ := openTestBind(t)
	const mark = 0x51820
	if err := b.SetMark(mark); errors.Is(err, syscall.EPERM) {
		t.Skip("SO_MARK needs CAP_NET_ADMIN; run under unshare -rn")
	} else if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*net.UDPConn{b.v4, b.v6} {
		if c == nil {
			continue
		}
		rc, err := c.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var got int
		var opErr error
		if err := rc.Control(func(fd uintptr) {
			got, opErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
		}); err != nil {
			t.Fatal(err)
		}
		if opErr != nil || got != mark {
			t.Errorf("SO_MARK on %v = %#x, %v; want %#x", c.LocalAddr(), got, opErr, mark)
		}
	}
}
