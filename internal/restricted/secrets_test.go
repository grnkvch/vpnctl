package restricted

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestRestrictedSecretCodecsAreDeterministicAndStrict(t *testing.T) {
	t.Parallel()

	gateway, err := NewGatewaySecret(bytes.NewReader(bytes.Repeat([]byte{0x21}, SymmetricKeyByteCount*2)))
	if err != nil {
		t.Fatalf("NewGatewaySecret() error = %v", err)
	}
	if gateway.SchemaVersion != SecretSchemaVersion ||
		gateway.ShadowsocksPassword != base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x21}, SymmetricKeyByteCount)) ||
		gateway.BootstrapShadowTLSPassword != strings.Repeat("21", SymmetricKeyByteCount) {
		t.Fatalf("gateway material = %#v", gateway)
	}
	gatewayBytes, err := EncodeSecret(gateway)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeGatewaySecret(gatewayBytes); err != nil || decoded != gateway {
		t.Fatalf("DecodeGatewaySecret() = %#v, %v", decoded, err)
	}

	identityBytes, err := GenerateIdentitySecret(bytes.NewReader(bytes.Repeat([]byte{0x32}, SymmetricKeyByteCount)))
	if err != nil {
		t.Fatalf("GenerateIdentitySecret() error = %v", err)
	}
	identity, err := DecodeIdentitySecret(identityBytes)
	if err != nil || identity.SchemaVersion != SecretSchemaVersion || identity.ShadowTLSPassword != strings.Repeat("32", SymmetricKeyByteCount) {
		t.Fatalf("DecodeIdentitySecret() = %#v, %v", identity, err)
	}

	for name, content := range map[string][]byte{
		"unknown field":  []byte(`{"schema_version":1,"shadowtls_password":"` + strings.Repeat("32", SymmetricKeyByteCount) + `","extra":true}`),
		"trailing value": append(append([]byte(nil), identityBytes...), []byte("{}")...),
		"short password": []byte(`{"schema_version":1,"shadowtls_password":"32"}`),
		"uppercase":      []byte(`{"schema_version":1,"shadowtls_password":"` + strings.Repeat("AB", SymmetricKeyByteCount) + `"}`),
	} {
		if _, err := DecodeIdentitySecret(content); err == nil {
			t.Fatalf("DecodeIdentitySecret(%s) succeeded", name)
		}
	}
}

func TestRestrictedSecretGenerationRejectsShortEntropy(t *testing.T) {
	t.Parallel()

	if _, err := NewGatewaySecret(bytes.NewReader(make([]byte, SymmetricKeyByteCount))); err == nil {
		t.Fatal("NewGatewaySecret(short entropy) succeeded")
	}
	if _, err := GenerateIdentitySecret(bytes.NewReader(nil)); err == nil {
		t.Fatal("GenerateIdentitySecret(short entropy) succeeded")
	}
}
