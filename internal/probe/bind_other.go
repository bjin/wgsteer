//go:build !linux

package probe

import (
	"errors"
	"net"
)

// setMark: fwmarks exist only on Linux.
func setMark(_ *net.UDPConn, mark uint32) error {
	if mark == 0 {
		return nil
	}
	return errors.New("fwmark is only supported on Linux")
}
