//go:build !linux

package linux

import (
	"fmt"
	"syscall"
)

func markStandardProbeSocket(string, string, syscall.RawConn) error {
	return fmt.Errorf("standard probe socket marking requires Linux")
}
