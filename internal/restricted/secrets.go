// Package restricted owns the wire constants and strict credential codecs
// shared by the restricted transport and Clash export capabilities.
package restricted

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	ProviderName          = "mihomo"
	Cipher                = "2022-blake3-aes-256-gcm"
	ShadowTLSVersion      = 3
	UDPOverTCPVersion     = 2
	TCPPort               = 8443
	SecretSchemaVersion   = 1
	SymmetricKeyByteCount = 32
)

const GatewayCredentialRef model.SecretRef = "restricted-server:gateway-g1"

type GatewaySecret struct {
	SchemaVersion              int    `json:"schema_version"`
	ShadowsocksPassword        string `json:"shadowsocks_password"`
	BootstrapShadowTLSPassword string `json:"bootstrap_shadowtls_password"`
}

type IdentitySecret struct {
	SchemaVersion     int    `json:"schema_version"`
	ShadowTLSPassword string `json:"shadowtls_password"`
}

func NewGatewaySecret(random io.Reader) (GatewaySecret, error) {
	if random == nil {
		random = rand.Reader
	}
	serverKey := make([]byte, SymmetricKeyByteCount)
	if _, err := io.ReadFull(random, serverKey); err != nil {
		return GatewaySecret{}, fmt.Errorf("generate restricted server credential: %w", err)
	}
	bootstrap, err := randomHex256(random)
	if err != nil {
		return GatewaySecret{}, fmt.Errorf("generate restricted bootstrap credential: %w", err)
	}
	return GatewaySecret{
		SchemaVersion:              SecretSchemaVersion,
		ShadowsocksPassword:        base64.StdEncoding.EncodeToString(serverKey),
		BootstrapShadowTLSPassword: bootstrap,
	}, nil
}

func GenerateIdentitySecret(random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	password, err := randomHex256(random)
	if err != nil {
		return nil, fmt.Errorf("generate restricted identity credential: %w", err)
	}
	return EncodeSecret(IdentitySecret{
		SchemaVersion: SecretSchemaVersion, ShadowTLSPassword: password,
	})
}

func EncodeSecret(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode restricted credential: %w", err)
	}
	return append(encoded, '\n'), nil
}

func DecodeGatewaySecret(content []byte) (GatewaySecret, error) {
	var secret GatewaySecret
	if err := decodeSecret(content, &secret); err != nil {
		return GatewaySecret{}, err
	}
	if secret.SchemaVersion != SecretSchemaVersion {
		return GatewaySecret{}, fmt.Errorf("unsupported restricted credential schema")
	}
	if err := ValidateServerPassword(secret.ShadowsocksPassword); err != nil {
		return GatewaySecret{}, err
	}
	if err := ValidateIdentityPassword(secret.BootstrapShadowTLSPassword); err != nil {
		return GatewaySecret{}, err
	}
	return secret, nil
}

func DecodeIdentitySecret(content []byte) (IdentitySecret, error) {
	var secret IdentitySecret
	if err := decodeSecret(content, &secret); err != nil {
		return IdentitySecret{}, err
	}
	if secret.SchemaVersion != SecretSchemaVersion {
		return IdentitySecret{}, fmt.Errorf("unsupported restricted identity credential schema")
	}
	if err := ValidateIdentityPassword(secret.ShadowTLSPassword); err != nil {
		return IdentitySecret{}, err
	}
	return secret, nil
}

func ValidateServerPassword(password string) error {
	decoded, err := base64.StdEncoding.Strict().DecodeString(password)
	if err != nil || len(decoded) != SymmetricKeyByteCount || base64.StdEncoding.EncodeToString(decoded) != password {
		return fmt.Errorf("restricted Shadowsocks credential must be canonical base64 for 256 bits")
	}
	return nil
}

func ValidateIdentityPassword(password string) error {
	decoded, err := hex.DecodeString(password)
	if err != nil || len(decoded) != SymmetricKeyByteCount || hex.EncodeToString(decoded) != password {
		return fmt.Errorf("restricted ShadowTLS credential must be 256-bit lower-case hexadecimal")
	}
	return nil
}

func randomHex256(random io.Reader) (string, error) {
	key := make([]byte, SymmetricKeyByteCount)
	if _, err := io.ReadFull(random, key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

func decodeSecret(content []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode restricted credential: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode restricted credential: trailing data")
	}
	return nil
}
