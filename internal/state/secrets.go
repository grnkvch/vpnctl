package state

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const serverPrivateKeyFile = "server_private.key"

type ServerKeyPair struct {
	PrivateKey string
	PublicKey  string
}

type ServerKeyGenerator interface {
	GenerateServerKeyPair(ctx context.Context) (ServerKeyPair, error)
}

func EnsureServerKeyPair(ctx context.Context, dir string, generator ServerKeyGenerator) (ServerKeyPair, bool, error) {
	if dir == "" {
		dir = DefaultDir
	}

	if _, err := Init(dir, false); err != nil {
		return ServerKeyPair{}, false, err
	}
	st, err := Load(dir)
	if err != nil {
		return ServerKeyPair{}, false, err
	}
	if st.Server == nil {
		return ServerKeyPair{}, false, fmt.Errorf("server is not configured")
	}

	privateKeyPath := ServerPrivateKeyPath(dir)
	privateKey, privateErr := readSecret(privateKeyPath)
	publicKey := strings.TrimSpace(st.Server.WireGuardPublicKey)
	if privateErr == nil && publicKey != "" {
		if err := wireguard.ValidateKey(privateKey); err != nil {
			return ServerKeyPair{}, false, fmt.Errorf("stored server private key is invalid: %w", err)
		}
		if err := wireguard.ValidateKey(publicKey); err != nil {
			return ServerKeyPair{}, false, fmt.Errorf("stored server public key is invalid: %w", err)
		}
		return ServerKeyPair{PrivateKey: privateKey, PublicKey: publicKey}, false, nil
	}
	if privateErr == nil && publicKey == "" {
		return ServerKeyPair{}, false, fmt.Errorf("server public key is missing from state")
	}
	if !os.IsNotExist(privateErr) {
		return ServerKeyPair{}, false, fmt.Errorf("read server private key: %w", privateErr)
	}
	if publicKey != "" {
		return ServerKeyPair{}, false, fmt.Errorf("server private key is missing: %s", privateKeyPath)
	}
	if generator == nil {
		return ServerKeyPair{}, false, fmt.Errorf("server key generator is required")
	}

	keyPair, err := generator.GenerateServerKeyPair(ctx)
	if err != nil {
		return ServerKeyPair{}, false, err
	}
	if err := wireguard.ValidateKey(keyPair.PrivateKey); err != nil {
		return ServerKeyPair{}, false, fmt.Errorf("generated server private key is invalid: %w", err)
	}
	if err := wireguard.ValidateKey(keyPair.PublicKey); err != nil {
		return ServerKeyPair{}, false, fmt.Errorf("generated server public key is invalid: %w", err)
	}
	if err := writeSecret(privateKeyPath, keyPair.PrivateKey); err != nil {
		return ServerKeyPair{}, false, err
	}

	st.Server.WireGuardPublicKey = keyPair.PublicKey
	if err := Save(dir, st); err != nil {
		_ = os.Remove(privateKeyPath)
		return ServerKeyPair{}, false, err
	}
	return keyPair, true, nil
}

func ServerPrivateKeyPath(dir string) string {
	if dir == "" {
		dir = DefaultDir
	}
	return filepath.Join(dir, "secrets", serverPrivateKeyFile)
}

func ClientPrivateKeyPath(dir string, clientID string) string {
	if dir == "" {
		dir = DefaultDir
	}
	return filepath.Join(dir, "secrets", "clients", clientID+".key")
}

func readSecret(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func writeSecret(path string, value string) error {
	if err := os.WriteFile(path, []byte(strings.TrimSpace(value)+"\n"), 0o600); err != nil {
		return fmt.Errorf("write secret %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("set permissions on secret %s: %w", path, err)
	}
	return nil
}

func removeSecret(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
