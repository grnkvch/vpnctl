package regression

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
)

func TestReleaseManifestSchemasMatchStrictSignedImplementation(t *testing.T) {
	t.Parallel()
	payloadPath := filepath.Join(v2SchemaRoot(), "release-manifest-v1.example.json")
	payloadBytes, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	var payloadDocument any
	if err := json.Unmarshal(payloadBytes, &payloadDocument); err != nil {
		t.Fatal(err)
	}
	if err := resolveV2SchemaFile(t, filepath.Join(v2SchemaRoot(), "release-manifest-v1.schema.json")).Validate(payloadDocument); err != nil {
		t.Fatalf("release payload example does not match schema: %v", err)
	}
	var manifest lifecycle.ReleaseManifest
	if err := json.Unmarshal(payloadBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("release payload example does not match implementation: %v", err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := lifecycle.EncodeSignedReleaseManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	var envelopeDocument any
	if err := json.Unmarshal(envelopeBytes, &envelopeDocument); err != nil {
		t.Fatal(err)
	}
	if err := resolveV2SchemaFile(t, filepath.Join(v2SchemaRoot(), "signed-release-manifest-v1.schema.json")).Validate(envelopeDocument); err != nil {
		t.Fatalf("signed release envelope does not match schema: %v", err)
	}
	if _, err := lifecycle.DecodeAndVerifyReleaseManifest(envelopeBytes, publicKey); err != nil {
		t.Fatalf("schema-valid signed release envelope does not verify: %v", err)
	}
}
