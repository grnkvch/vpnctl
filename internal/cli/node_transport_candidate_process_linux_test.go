//go:build linux

package cli

import (
	"os/exec"
	"syscall"
	"testing"
)

func TestConfigureNodeTransportCandidateProcessKillsChildWithParent(t *testing.T) {
	command := exec.Command("/bin/true")
	if err := configureNodeTransportCandidateProcess(command); err != nil {
		t.Fatal(err)
	}
	if command.SysProcAttr == nil || command.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("candidate process attributes = %+v", command.SysProcAttr)
	}
}
