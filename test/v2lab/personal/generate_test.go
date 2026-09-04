package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateFixtureUsesManagedSecretFreeSCPExports(t *testing.T) {
	root := t.TempDir()
	if err := generateFixture(root); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(root, "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest fixtureManifest
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != 1 || len(manifest.Profiles) != 2 {
		t.Fatalf("fixture manifest = %+v", manifest)
	}
	for _, kind := range []string{"clash", "wireguard"} {
		profile := manifest.Profiles[kind]
		if profile.Path == "" || profile.SHA256 == "" || !strings.HasPrefix(profile.SCPHint, "scp root@192.0.2.1:") {
			t.Fatalf("%s profile metadata = %+v", kind, profile)
		}
		info, err := os.Stat(profile.Path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s profile mode = %v, %v", kind, info, err)
		}
	}
	for _, private := range []string{
		fixtureGatewayPrivateKey,
		"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
		"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
	} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatalf("fixture manifest exposed a private key")
		}
	}
}
