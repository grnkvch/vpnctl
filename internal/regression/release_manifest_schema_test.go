package regression

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
)

func TestReleaseManifestSchemaMatchesCanonicalImplementation(t *testing.T) {
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

	canonicalBytes, err := lifecycle.EncodeReleaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.DecodeReleaseManifest(canonicalBytes); err != nil {
		t.Fatalf("schema-valid canonical release manifest does not decode: %v", err)
	}
}
