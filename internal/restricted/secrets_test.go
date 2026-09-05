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

func TestNodeUpstreamSecretContainsOnlyCanonicalShadowsocksMaterial(t *testing.T) {
	t.Parallel()

	password := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, SymmetricKeyByteCount))
	encoded, err := EncodeNodeUpstreamSecret(password)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":1,"shadowsocks_password":"` + password + `"}`
	if string(encoded) != want || bytes.Contains(encoded, []byte("shadowtls")) {
		t.Fatalf("node upstream credential = %q", encoded)
	}
	decoded, err := DecodeNodeUpstreamSecret(encoded)
	if err != nil || decoded.SchemaVersion != NodeUpstreamSchemaVersion || decoded.ShadowsocksPassword != password {
		t.Fatalf("DecodeNodeUpstreamSecret() = %+v, %v", decoded, err)
	}
	for name, value := range map[string][]byte{
		"gateway-only field": []byte(`{"schema_version":1,"shadowsocks_password":"` + password + `","bootstrap_shadowtls_password":"` + strings.Repeat("42", SymmetricKeyByteCount) + `"}`),
		"non-canonical":      append(append([]byte(nil), encoded...), '\n'),
		"wrong schema":       bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1),
	} {
		if _, err := DecodeNodeUpstreamSecret(value); err == nil {
			t.Fatalf("DecodeNodeUpstreamSecret(%s) succeeded", name)
		}
	}
}
