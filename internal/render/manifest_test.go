package render

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

func TestManifestIsDeterministicAndContentFree(t *testing.T) {
	t.Parallel()

	policyA := SourceGeneration{Kind: "node", ID: "node-a", Generation: 7}
	policyB := SourceGeneration{Kind: "node", ID: "node-b", Generation: 3}
	credential := SourceGeneration{Kind: "transport", ID: "node-a-standard", Generation: 2}
	source := SourceGeneration{Kind: "handshake-host", ID: "microsoft", Generation: 1}
	first, err := BuildManifest(12, []ArtifactInput{
		{
			Path:                  "/etc/vpnctl/transport.conf",
			Mode:                  0600,
			Content:               []byte("secret-canary-value"),
			SourceGenerations:     []SourceGeneration{source},
			PolicyGenerations:     []SourceGeneration{policyB, policyA},
			CredentialGenerations: []SourceGeneration{credential},
		},
		{Path: "/etc/vpnctl/routing.conf", Mode: 0644, Content: []byte("routing")},
	})
	if err != nil {
		t.Fatalf("build first manifest: %v", err)
	}
	second, err := BuildManifest(12, []ArtifactInput{
		{Path: "/etc/vpnctl/routing.conf", Mode: 0644, Content: []byte("routing")},
		{
			Path:                  "/etc/vpnctl/transport.conf",
			Mode:                  0600,
			Content:               []byte("secret-canary-value"),
			SourceGenerations:     []SourceGeneration{source},
			PolicyGenerations:     []SourceGeneration{policyA, policyB},
			CredentialGenerations: []SourceGeneration{credential},
		},
	})
	if err != nil {
		t.Fatalf("build second manifest: %v", err)
	}

	firstJSON, err := EncodeManifest(first)
	if err != nil {
		t.Fatalf("encode first manifest: %v", err)
	}
	secondJSON, err := EncodeManifest(second)
	if err != nil {
		t.Fatalf("encode second manifest: %v", err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("same renderer output encoded differently:\n%s\n%s", firstJSON, secondJSON)
	}
	if bytes.Contains(firstJSON, []byte("secret-canary-value")) {
		t.Fatal("manifest serialized artifact content")
	}
	if got := first.Artifacts[0].Path; got != "/etc/vpnctl/routing.conf" {
		t.Fatalf("first sorted artifact = %q", got)
	}
	if got := first.Artifacts[1].PolicyGenerations; !reflect.DeepEqual(got, []SourceGeneration{policyA, policyB}) {
		t.Fatalf("policy generations not canonical: %+v", got)
	}
	if got := first.Artifacts[1].SourceGenerations; !reflect.DeepEqual(got, []SourceGeneration{source}) {
		t.Fatalf("source generations not canonical: %+v", got)
	}

	decoded, err := DecodeManifest(firstJSON)
	if err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if !reflect.DeepEqual(decoded, first) {
		t.Fatalf("manifest round trip changed value:\n%+v\n%+v", decoded, first)
	}
}

func TestCompareManifestsMarksOnlyAffectedArtifacts(t *testing.T) {
	t.Parallel()

	policyV1 := SourceGeneration{Kind: "client", ID: "ios", Generation: 1}
	credentialV1 := SourceGeneration{Kind: "wireguard", ID: "ios", Generation: 1}
	sourceV1 := SourceGeneration{Kind: "handshake-host", ID: "microsoft", Generation: 1}
	before := mustManifest(t, 20, []ArtifactInput{
		{Path: "/etc/vpnctl/client.conf", Mode: 0600, Content: []byte("client-v1"), SourceGenerations: []SourceGeneration{sourceV1}, PolicyGenerations: []SourceGeneration{policyV1}, CredentialGenerations: []SourceGeneration{credentialV1}},
		{Path: "/etc/vpnctl/ingress.conf", Mode: 0644, Content: []byte("ingress-v1")},
	})

	tests := []struct {
		name    string
		inputs  []ArtifactInput
		changes []ArtifactChange
	}{
		{
			name: "state generation alone is provenance",
			inputs: []ArtifactInput{
				{Path: "/etc/vpnctl/ingress.conf", Mode: 0644, Content: []byte("ingress-v1")},
				{Path: "/etc/vpnctl/client.conf", Mode: 0600, Content: []byte("client-v1"), SourceGenerations: []SourceGeneration{sourceV1}, PolicyGenerations: []SourceGeneration{policyV1}, CredentialGenerations: []SourceGeneration{credentialV1}},
			},
			changes: []ArtifactChange{},
		},
		{
			name: "policy change is local",
			inputs: []ArtifactInput{
				{Path: "/etc/vpnctl/client.conf", Mode: 0600, Content: []byte("client-v2"), SourceGenerations: []SourceGeneration{sourceV1}, PolicyGenerations: []SourceGeneration{{Kind: "client", ID: "ios", Generation: 2}}, CredentialGenerations: []SourceGeneration{credentialV1}},
				{Path: "/etc/vpnctl/ingress.conf", Mode: 0644, Content: []byte("ingress-v1")},
			},
			changes: []ArtifactChange{{Path: "/etc/vpnctl/client.conf", Kind: ArtifactUpdated}},
		},
		{
			name: "credential metadata change is local even with same content",
			inputs: []ArtifactInput{
				{Path: "/etc/vpnctl/client.conf", Mode: 0600, Content: []byte("client-v1"), SourceGenerations: []SourceGeneration{sourceV1}, PolicyGenerations: []SourceGeneration{policyV1}, CredentialGenerations: []SourceGeneration{{Kind: "wireguard", ID: "ios", Generation: 2}}},
				{Path: "/etc/vpnctl/ingress.conf", Mode: 0644, Content: []byte("ingress-v1")},
			},
			changes: []ArtifactChange{{Path: "/etc/vpnctl/client.conf", Kind: ArtifactUpdated}},
		},
		{
			name: "generic source change is local even with same content",
			inputs: []ArtifactInput{
				{Path: "/etc/vpnctl/client.conf", Mode: 0600, Content: []byte("client-v1"), SourceGenerations: []SourceGeneration{{Kind: "handshake-host", ID: "apple", Generation: 1}}, PolicyGenerations: []SourceGeneration{policyV1}, CredentialGenerations: []SourceGeneration{credentialV1}},
				{Path: "/etc/vpnctl/ingress.conf", Mode: 0644, Content: []byte("ingress-v1")},
			},
			changes: []ArtifactChange{{Path: "/etc/vpnctl/client.conf", Kind: ArtifactUpdated}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			after := mustManifest(t, 21, test.inputs)
			changes, err := CompareManifests(before, after)
			if err != nil {
				t.Fatalf("compare manifests: %v", err)
			}
			if !reflect.DeepEqual(changes, test.changes) {
				t.Fatalf("changes = %+v, want %+v", changes, test.changes)
			}
		})
	}
}

func TestCompareManifestsReportsCreateAndDeleteInPathOrder(t *testing.T) {
	t.Parallel()

	before := mustManifest(t, 1, []ArtifactInput{
		{Path: "/etc/vpnctl/b.conf", Mode: 0644, Content: []byte("b")},
		{Path: "/etc/vpnctl/c.conf", Mode: 0644, Content: []byte("c")},
	})
	after := mustManifest(t, 2, []ArtifactInput{
		{Path: "/etc/vpnctl/a.conf", Mode: 0644, Content: []byte("a")},
		{Path: "/etc/vpnctl/b.conf", Mode: 0644, Content: []byte("b")},
	})
	changes, err := CompareManifests(before, after)
	if err != nil {
		t.Fatalf("compare manifests: %v", err)
	}
	want := []ArtifactChange{
		{Path: "/etc/vpnctl/a.conf", Kind: ArtifactCreated},
		{Path: "/etc/vpnctl/c.conf", Kind: ArtifactDeleted},
	}
	if !reflect.DeepEqual(changes, want) {
		t.Fatalf("changes = %+v, want %+v", changes, want)
	}
}

func TestCompareDrift(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, 3, []ArtifactInput{
		{Path: "/etc/vpnctl/content.conf", Mode: 0600, Content: []byte("plaintext-canary")},
		{Path: "/etc/vpnctl/missing.conf", Mode: 0644, Content: []byte("missing")},
		{Path: "/etc/vpnctl/mode.conf", Mode: 0644, Content: []byte("same")},
		{Path: "/etc/vpnctl/type.conf", Mode: 0644, Content: []byte("ignored")},
	})
	drift, err := CompareDrift(manifest, []ObservedArtifact{
		{Path: "/etc/vpnctl/content.conf", Mode: 0600, Content: []byte("changed")},
		{Path: "/etc/vpnctl/mode.conf", Mode: 0600, Content: []byte("same")},
		{Path: "/etc/vpnctl/type.conf", Mode: fs.ModeSymlink | 0777, Content: []byte("target")},
		{Path: "/etc/vpnctl/unexpected.conf", Mode: 0644, Content: []byte("unexpected")},
	})
	if err != nil {
		t.Fatalf("compare drift: %v", err)
	}
	if got := driftSummary(drift); got != "content.conf:content,missing.conf:missing,mode.conf:mode,type.conf:type,unexpected.conf:unexpected" {
		t.Fatalf("drift = %q", got)
	}
	if strings.Contains(string(mustJSON(t, drift)), "plaintext-canary") {
		t.Fatal("drift output contains artifact content")
	}
}

func TestManifestRejectsUnsafeOrNonCanonicalInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input ArtifactInput
	}{
		{name: "relative path", input: ArtifactInput{Path: "etc/vpnctl/a", Mode: 0600}},
		{name: "unclean path", input: ArtifactInput{Path: "/etc/vpnctl/../a", Mode: 0600}},
		{name: "root path", input: ArtifactInput{Path: "/", Mode: 0600}},
		{name: "line break path", input: ArtifactInput{Path: "/etc/vpnctl/a\nb", Mode: 0600}},
		{name: "writable mode", input: ArtifactInput{Path: "/etc/vpnctl/a", Mode: 0666}},
		{name: "nonregular mode", input: ArtifactInput{Path: "/etc/vpnctl/a", Mode: fs.ModeSymlink | 0600}},
		{name: "duplicate generation", input: ArtifactInput{Path: "/etc/vpnctl/a", Mode: 0600, PolicyGenerations: []SourceGeneration{{Kind: "node", ID: "a", Generation: 1}, {Kind: "node", ID: "a", Generation: 2}}}},
		{name: "zero generation", input: ArtifactInput{Path: "/etc/vpnctl/a", Mode: 0600, CredentialGenerations: []SourceGeneration{{Kind: "node", ID: "a"}}}},
		{name: "unsafe source id", input: ArtifactInput{Path: "/etc/vpnctl/a", Mode: 0600, CredentialGenerations: []SourceGeneration{{Kind: "node", ID: "/telegram/webhook", Generation: 1}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildManifest(1, []ArtifactInput{test.input}); err == nil {
				t.Fatal("BuildManifest accepted invalid input")
			}
		})
	}
	if _, err := BuildManifest(1, []ArtifactInput{
		{Path: "/etc/vpnctl/a", Mode: 0600},
		{Path: "/etc/vpnctl/a", Mode: 0600},
	}); err == nil {
		t.Fatal("BuildManifest accepted duplicate artifact paths")
	}
}

func TestDecodeManifestIsStrict(t *testing.T) {
	t.Parallel()

	manifest := mustManifest(t, 1, []ArtifactInput{})
	encoded, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	unknown := bytes.Replace(encoded, []byte(`"schema_version": 1`), []byte(`"schema_version": 1, "unknown": true`), 1)
	if _, err := DecodeManifest(unknown); err == nil {
		t.Fatal("DecodeManifest accepted unknown field")
	}
	duplicate := bytes.Replace(encoded, []byte(`"schema_version": 1`), []byte(`"schema_version": 1, "schema_version": 1`), 1)
	if _, err := DecodeManifest(duplicate); err == nil {
		t.Fatal("DecodeManifest accepted duplicate field")
	}
	if _, err := DecodeManifest(append(encoded, []byte(`{}`)...)); err == nil {
		t.Fatal("DecodeManifest accepted a second JSON document")
	}
}

func mustManifest(t *testing.T, generation uint64, inputs []ArtifactInput) ArtifactManifest {
	t.Helper()
	manifest, err := BuildManifest(generation, inputs)
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	return manifest
}

func driftSummary(drift []ArtifactDrift) string {
	parts := make([]string, 0, len(drift))
	for _, item := range drift {
		pathParts := strings.Split(item.Path, "/")
		kinds := make([]string, len(item.Kinds))
		for index, kind := range item.Kinds {
			kinds[index] = string(kind)
		}
		parts = append(parts, pathParts[len(pathParts)-1]+":"+strings.Join(kinds, "+"))
	}
	return strings.Join(parts, ",")
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return data
}
