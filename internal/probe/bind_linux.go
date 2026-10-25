package probe

import (
	"net"
	"syscall"
)

// setMark sets SO_MARK on c (needs CAP_NET_ADMIN or CAP_NET_RAW).
func setMark(c *net.UDPConn, mark uint32) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	if err := rc.Control(func(fd uintptr) {
		opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
	}); err != nil {
		return err
	}
	return opErr
}
