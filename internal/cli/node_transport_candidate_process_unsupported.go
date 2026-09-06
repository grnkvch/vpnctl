//go:build !linux

package cli

import (
	"fmt"
	"os/exec"
)

func configureNodeTransportCandidateProcess(*exec.Cmd) error {
	return fmt.Errorf("restricted candidate process requires Linux")
}
