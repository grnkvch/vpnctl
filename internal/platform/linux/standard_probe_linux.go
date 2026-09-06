//go:build linux

package linux

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

func markStandardProbeSocket(_ string, _ string, connection syscall.RawConn) error {
	var socketErr error
	controlErr := connection.Control(func(descriptor uintptr) {
		socketErr = unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_MARK, int(VPNCTLStandardProbeMark))
	})
	return errors.Join(controlErr, socketErr)
}
