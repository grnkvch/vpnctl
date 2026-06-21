package wireguard

import (
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
)

type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

type Runner interface {
	Run(ctx context.Context, name string, args []string, stdin string) (string, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args []string, stdin string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("run %s: %w", name, err)
	}
	return string(output), nil
}

func GenerateKeyPair(ctx context.Context, runner Runner) (KeyPair, error) {
	privateKey, err := GeneratePrivateKey(ctx, runner)
	if err != nil {
		return KeyPair{}, err
	}
	publicKey, err := PublicKey(ctx, runner, privateKey)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{PrivateKey: privateKey, PublicKey: publicKey}, nil
}

func GeneratePrivateKey(ctx context.Context, runner Runner) (string, error) {
	runner = defaultRunner(runner)
	out, err := runner.Run(ctx, "wg", []string{"genkey"}, "")
	if err != nil {
		return "", fmt.Errorf("generate WireGuard private key: %w", err)
	}
	key := strings.TrimSpace(out)
	if err := ValidateKey(key); err != nil {
		return "", fmt.Errorf("generated invalid WireGuard private key: %w", err)
	}
	return key, nil
}

func PublicKey(ctx context.Context, runner Runner, privateKey string) (string, error) {
	runner = defaultRunner(runner)
	if err := ValidateKey(privateKey); err != nil {
		return "", fmt.Errorf("invalid WireGuard private key: %w", err)
	}
	out, err := runner.Run(ctx, "wg", []string{"pubkey"}, privateKey+"\n")
	if err != nil {
		return "", fmt.Errorf("derive WireGuard public key: %w", err)
	}
	key := strings.TrimSpace(out)
	if err := ValidateKey(key); err != nil {
		return "", fmt.Errorf("derived invalid WireGuard public key: %w", err)
	}
	return key, nil
}

func GeneratePresharedKey(ctx context.Context, runner Runner) (string, error) {
	runner = defaultRunner(runner)
	out, err := runner.Run(ctx, "wg", []string{"genpsk"}, "")
	if err != nil {
		return "", fmt.Errorf("generate WireGuard preshared key: %w", err)
	}
	key := strings.TrimSpace(out)
	if err := ValidateKey(key); err != nil {
		return "", fmt.Errorf("generated invalid WireGuard preshared key: %w", err)
	}
	return key, nil
}

func ValidateKey(key string) error {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil {
		return fmt.Errorf("must be base64: %w", err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("must decode to 32 bytes")
	}
	return nil
}

func defaultRunner(runner Runner) Runner {
	if runner == nil {
		return ExecRunner{}
	}
	return runner
}
