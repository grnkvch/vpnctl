package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const gatewayMutationLockName = "gateway-mutation.lock"

var ErrGatewayMutationBusy = errors.New("another gateway mutation is active")

// AcquireGatewayMutationLock serializes controller mutations with the narrow
// privileged CLI transaction used to complete an interrupted Gateway
// bootstrap. The lock lives in the root-only runtime directory and is never a
// substitute for the authoritative state generation checks.
func AcquireGatewayMutationLock(ctx context.Context, runtimeDirectory string, wait bool) (func(), error) {
	if ctx == nil || !filepath.IsAbs(runtimeDirectory) || filepath.Clean(runtimeDirectory) != runtimeDirectory {
		return nil, fmt.Errorf("gateway mutation lock runtime directory is invalid")
	}
	directoryFD, err := unix.Open(runtimeDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open gateway mutation runtime directory: %w", err)
	}
	defer unix.Close(directoryFD)
	var directoryStat unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryStat); err != nil {
		return nil, fmt.Errorf("inspect gateway mutation runtime directory: %w", err)
	}
	if directoryStat.Uid != uint32(os.Geteuid()) || directoryStat.Mode&unix.S_IFMT != unix.S_IFDIR || directoryStat.Mode&0o022 != 0 {
		return nil, fmt.Errorf("gateway mutation runtime directory must be owned by the current user and not group/world writable")
	}
	descriptor, err := unix.Openat(directoryFD, gatewayMutationLockName, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		descriptor, err = unix.Openat(directoryFD, gatewayMutationLockName, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open gateway mutation lock: %w", err)
	}
	lock := os.NewFile(uintptr(descriptor), filepath.Join(runtimeDirectory, gatewayMutationLockName))
	keep := false
	defer func() {
		if !keep {
			_ = lock.Close()
		}
	}()
	if created {
		if err := unix.Fchmod(descriptor, 0o600); err != nil {
			return nil, fmt.Errorf("secure gateway mutation lock: %w", err)
		}
	}
	var lockStat unix.Stat_t
	if err := unix.Fstat(descriptor, &lockStat); err != nil {
		return nil, fmt.Errorf("inspect gateway mutation lock: %w", err)
	}
	if lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Mode&0o777 != 0o600 || lockStat.Uid != uint32(os.Geteuid()) || lockStat.Nlink != 1 {
		return nil, fmt.Errorf("gateway mutation lock must be an owned 0600 single-link regular file")
	}
	for {
		err = unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("lock gateway mutation transaction: %w", err)
		}
		if !wait {
			return nil, ErrGatewayMutationBusy
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	keep = true
	return func() {
		_ = unix.Flock(descriptor, unix.LOCK_UN)
		_ = lock.Close()
	}, nil
}
