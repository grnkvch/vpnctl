//go:build linux

package cli

import (
	"os/exec"
	"syscall"
)

func configureNodeTransportCandidateProcess(command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return nil
}
