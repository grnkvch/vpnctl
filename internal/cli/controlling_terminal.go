package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

const (
	controllingTTYPath = "/dev/tty"
	maxVisibleInput    = 4 << 10
	maxHiddenInput     = 16 << 10
)

// ControllingTerminal keeps prompts and one-time secret output away from
// redirected stdin/stdout. vpnctl's supported hosts are Unix systems where the
// controlling terminal is exposed as /dev/tty.
type ControllingTerminal struct {
	file *os.File
}

func OpenControllingTerminal() (*ControllingTerminal, error) {
	file, err := os.OpenFile(controllingTTYPath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open controlling terminal: %w", err)
	}
	if !term.IsTerminal(int(file.Fd())) {
		_ = file.Close()
		return nil, fmt.Errorf("%s is not a terminal", controllingTTYPath)
	}
	return &ControllingTerminal{file: file}, nil
}

func (terminal *ControllingTerminal) Close() error {
	if terminal == nil || terminal.file == nil {
		return nil
	}
	err := terminal.file.Close()
	terminal.file = nil
	return err
}

func (terminal *ControllingTerminal) ReadVisible(step InteractionStep) (string, error) {
	if err := terminal.ready(); err != nil {
		return "", err
	}
	if _, err := fmt.Fprint(terminal.file, visiblePrompt(step)); err != nil {
		return "", err
	}
	line := make([]byte, 0, 64)
	var one [1]byte
	for len(line) <= maxVisibleInput {
		read, err := terminal.file.Read(one[:])
		if read == 1 {
			if one[0] == '\n' {
				if len(line) > 0 && line[len(line)-1] == '\r' {
					line = line[:len(line)-1]
				}
				return string(line), nil
			}
			line = append(line, one[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return string(line), nil
			}
			return "", err
		}
	}
	return "", fmt.Errorf("visible terminal input exceeds %d bytes", maxVisibleInput)
}

func (terminal *ControllingTerminal) ReadHidden(step InteractionStep, entry int) ([]byte, error) {
	if err := terminal.ready(); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprint(terminal.file, hiddenPrompt(step, entry)); err != nil {
		return nil, err
	}
	value, err := term.ReadPassword(int(terminal.file.Fd()))
	_, newlineErr := fmt.Fprintln(terminal.file)
	if err != nil {
		wipeBytes(value)
		return nil, err
	}
	if newlineErr != nil {
		wipeBytes(value)
		return nil, newlineErr
	}
	if len(value) > maxHiddenInput {
		wipeBytes(value)
		return nil, fmt.Errorf("hidden terminal input exceeds %d bytes", maxHiddenInput)
	}
	return value, nil
}

func (terminal *ControllingTerminal) WriteSecret(_ InteractionStep, secret []byte) error {
	if err := terminal.ready(); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(terminal.file, "One-time secret (store it now; it will not be shown again):"); err != nil {
		return err
	}
	if _, err := terminal.file.Write(secret); err != nil {
		return err
	}
	_, err := fmt.Fprintln(terminal.file)
	return err
}

func (terminal *ControllingTerminal) ready() error {
	if terminal == nil || terminal.file == nil {
		return fmt.Errorf("controlling terminal is closed")
	}
	return nil
}

func visiblePrompt(step InteractionStep) string {
	if step.ID == StepManagedSwap {
		return "Create a vpnctl-managed 1 GB swap file? [y/N]: "
	}
	if step.Prompt == PromptTyped {
		return fmt.Sprintf("Type %q to continue: ", step.Exact)
	}
	return "Apply the displayed impact plan? [y/N]: "
}

func hiddenPrompt(step InteractionStep, entry int) string {
	switch step.ID {
	case StepInviteToken:
		return "Invite token: "
	case StepRecoveryToken:
		return "Recovery token: "
	case StepRestorePassphrase:
		return "Backup passphrase: "
	case StepBackupPassphrase:
		if entry == 2 {
			return "Confirm new backup passphrase: "
		}
		return "New backup passphrase: "
	default:
		return "Secret: "
	}
}
