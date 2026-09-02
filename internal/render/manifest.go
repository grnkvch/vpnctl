package render

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const ArtifactManifestSchemaVersion = 1

var (
	sourceKindPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)
	sourceIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// SourceGeneration identifies a versioned input used to render an artifact.
// Policy and credential dependencies are kept separate in the manifest so a
// planner can explain why an artifact became stale without exposing the input.
type SourceGeneration struct {
	Kind       string `json:"kind"`
	ID         string `json:"id"`
	Generation uint64 `json:"generation"`
}

// ArtifactInput is renderer output before its content is reduced to a hash.
// Content is deliberately absent from ArtifactManifest.
type ArtifactInput struct {
	Path                  string
	Mode                  fs.FileMode
	Content               []byte
	PolicyGenerations     []SourceGeneration
	CredentialGenerations []SourceGeneration
}

type ArtifactManifest struct {
	SchemaVersion         int              `json:"schema_version"`
	SourceStateGeneration uint64           `json:"source_state_generation"`
	Artifacts             []ArtifactRecord `json:"artifacts"`
}

type ArtifactRecord struct {
	Path                  string             `json:"path"`
	Mode                  string             `json:"mode"`
	ContentSHA256         string             `json:"content_sha256"`
	PolicyGenerations     []SourceGeneration `json:"policy_generations"`
	CredentialGenerations []SourceGeneration `json:"credential_generations"`
}

type ArtifactChangeKind string

const (
	ArtifactCreated ArtifactChangeKind = "created"
	ArtifactUpdated ArtifactChangeKind = "updated"
	ArtifactDeleted ArtifactChangeKind = "deleted"
)

type ArtifactChange struct {
	Path string             `json:"path"`
	Kind ArtifactChangeKind `json:"kind"`
}

type ObservedArtifact struct {
	Path    string
	Mode    fs.FileMode
	Content []byte
}

type DriftKind string

const (
	DriftMissing    DriftKind = "missing"
	DriftUnexpected DriftKind = "unexpected"
	DriftType       DriftKind = "type"
	DriftMode       DriftKind = "mode"
	DriftContent    DriftKind = "content"
)

type ArtifactDrift struct {
	Path           string      `json:"path"`
	Kinds          []DriftKind `json:"kinds"`
	ExpectedMode   string      `json:"expected_mode,omitempty"`
	ActualMode     string      `json:"actual_mode,omitempty"`
	ExpectedSHA256 string      `json:"expected_sha256,omitempty"`
	ActualSHA256   string      `json:"actual_sha256,omitempty"`
}

// BuildManifest creates a canonical, content-free description of generated
// artifacts. Input order cannot affect the encoded manifest.
func BuildManifest(stateGeneration uint64, inputs []ArtifactInput) (ArtifactManifest, error) {
	if stateGeneration == 0 {
		return ArtifactManifest{}, fmt.Errorf("source state generation must be positive")
	}
	if inputs == nil {
		return ArtifactManifest{}, fmt.Errorf("artifact inputs must be present")
	}

	manifest := ArtifactManifest{
		SchemaVersion:         ArtifactManifestSchemaVersion,
		SourceStateGeneration: stateGeneration,
		Artifacts:             make([]ArtifactRecord, 0, len(inputs)),
	}
	for index, input := range inputs {
		if err := validateArtifactPath(input.Path); err != nil {
			return ArtifactManifest{}, fmt.Errorf("artifact input %d path: %w", index, err)
		}
		mode, err := canonicalMode(input.Mode)
		if err != nil {
			return ArtifactManifest{}, fmt.Errorf("artifact input %d mode: %w", index, err)
		}
		policies, err := canonicalGenerations(input.PolicyGenerations)
		if err != nil {
			return ArtifactManifest{}, fmt.Errorf("artifact input %d policy generations: %w", index, err)
		}
		credentials, err := canonicalGenerations(input.CredentialGenerations)
		if err != nil {
			return ArtifactManifest{}, fmt.Errorf("artifact input %d credential generations: %w", index, err)
		}
		hash := sha256.Sum256(input.Content)
		manifest.Artifacts = append(manifest.Artifacts, ArtifactRecord{
			Path:                  input.Path,
			Mode:                  mode,
			ContentSHA256:         hex.EncodeToString(hash[:]),
			PolicyGenerations:     policies,
			CredentialGenerations: credentials,
		})
	}
	sort.Slice(manifest.Artifacts, func(i, j int) bool {
		return manifest.Artifacts[i].Path < manifest.Artifacts[j].Path
	})
	if err := manifest.Validate(); err != nil {
		return ArtifactManifest{}, err
	}
	return manifest, nil
}

func (manifest ArtifactManifest) Validate() error {
	if manifest.SchemaVersion != ArtifactManifestSchemaVersion {
		return fmt.Errorf("schema version must be %d", ArtifactManifestSchemaVersion)
	}
	if manifest.SourceStateGeneration == 0 {
		return fmt.Errorf("source state generation must be positive")
	}
	if manifest.Artifacts == nil {
		return fmt.Errorf("artifacts must be present")
	}
	previousPath := ""
	for index, artifact := range manifest.Artifacts {
		if err := artifact.validate(); err != nil {
			return fmt.Errorf("artifact %d: %w", index, err)
		}
		if index > 0 && artifact.Path <= previousPath {
			return fmt.Errorf("artifacts must have unique paths in ascending order")
		}
		previousPath = artifact.Path
	}
	return nil
}

func (artifact ArtifactRecord) validate() error {
	if err := validateArtifactPath(artifact.Path); err != nil {
		return fmt.Errorf("path: %w", err)
	}
	if _, err := parseCanonicalMode(artifact.Mode); err != nil {
		return fmt.Errorf("mode: %w", err)
	}
	if len(artifact.ContentSHA256) != sha256.Size*2 {
		return fmt.Errorf("content sha256 must contain 64 lowercase hexadecimal characters")
	}
	decoded, err := hex.DecodeString(artifact.ContentSHA256)
	if err != nil || hex.EncodeToString(decoded) != artifact.ContentSHA256 {
		return fmt.Errorf("content sha256 must contain 64 lowercase hexadecimal characters")
	}
	if err := validateCanonicalGenerations(artifact.PolicyGenerations); err != nil {
		return fmt.Errorf("policy generations: %w", err)
	}
	if err := validateCanonicalGenerations(artifact.CredentialGenerations); err != nil {
		return fmt.Errorf("credential generations: %w", err)
	}
	return nil
}

// CompareManifests returns the minimal artifact set whose rendered content,
// mode, or direct policy/credential dependencies changed. The global state
// generation is provenance and intentionally does not invalidate every file.
func CompareManifests(previous, desired ArtifactManifest) ([]ArtifactChange, error) {
	if err := previous.Validate(); err != nil {
		return nil, fmt.Errorf("validate previous manifest: %w", err)
	}
	if err := desired.Validate(); err != nil {
		return nil, fmt.Errorf("validate desired manifest: %w", err)
	}

	before := recordsByPath(previous.Artifacts)
	after := recordsByPath(desired.Artifacts)
	paths := unionPaths(before, after)
	changes := make([]ArtifactChange, 0)
	for _, artifactPath := range paths {
		oldRecord, hadOld := before[artifactPath]
		newRecord, hasNew := after[artifactPath]
		switch {
		case !hadOld:
			changes = append(changes, ArtifactChange{Path: artifactPath, Kind: ArtifactCreated})
		case !hasNew:
			changes = append(changes, ArtifactChange{Path: artifactPath, Kind: ArtifactDeleted})
		case !equalArtifactRecord(oldRecord, newRecord):
			changes = append(changes, ArtifactChange{Path: artifactPath, Kind: ArtifactUpdated})
		}
	}
	return changes, nil
}

// CompareDrift compares the expected manifest with observations from the
// vpnctl-owned namespace. Callers must not pass unrelated host files.
func CompareDrift(expected ArtifactManifest, observed []ObservedArtifact) ([]ArtifactDrift, error) {
	if err := expected.Validate(); err != nil {
		return nil, fmt.Errorf("validate expected manifest: %w", err)
	}
	if observed == nil {
		return nil, fmt.Errorf("observed artifacts must be present")
	}

	actual := make(map[string]ObservedArtifact, len(observed))
	for index, artifact := range observed {
		if err := validateArtifactPath(artifact.Path); err != nil {
			return nil, fmt.Errorf("observed artifact %d path: %w", index, err)
		}
		if _, duplicate := actual[artifact.Path]; duplicate {
			return nil, fmt.Errorf("observed artifact path %q is duplicated", artifact.Path)
		}
		actual[artifact.Path] = artifact
	}

	expectedByPath := recordsByPath(expected.Artifacts)
	paths := make([]string, 0, len(expectedByPath)+len(actual))
	for artifactPath := range expectedByPath {
		paths = append(paths, artifactPath)
	}
	for artifactPath := range actual {
		if _, found := expectedByPath[artifactPath]; !found {
			paths = append(paths, artifactPath)
		}
	}
	sort.Strings(paths)

	drift := make([]ArtifactDrift, 0)
	for _, artifactPath := range paths {
		expectedRecord, isExpected := expectedByPath[artifactPath]
		actualArtifact, exists := actual[artifactPath]
		if !isExpected {
			drift = append(drift, unexpectedDrift(actualArtifact))
			continue
		}
		if !exists {
			drift = append(drift, ArtifactDrift{
				Path:           artifactPath,
				Kinds:          []DriftKind{DriftMissing},
				ExpectedMode:   expectedRecord.Mode,
				ExpectedSHA256: expectedRecord.ContentSHA256,
			})
			continue
		}
		if current := compareArtifact(expectedRecord, actualArtifact); len(current.Kinds) > 0 {
			drift = append(drift, current)
		}
	}
	return drift, nil
}

func EncodeManifest(manifest ArtifactManifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("validate artifact manifest: %w", err)
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode artifact manifest: %w", err)
	}
	return append(data, '\n'), nil
}

func DecodeManifest(data []byte) (ArtifactManifest, error) {
	if err := rejectDuplicateJSONFields(data); err != nil {
		return ArtifactManifest{}, fmt.Errorf("decode artifact manifest: %w", err)
	}
	var manifest ArtifactManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return ArtifactManifest{}, fmt.Errorf("decode artifact manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON documents")
		}
		return ArtifactManifest{}, fmt.Errorf("decode artifact manifest: trailing JSON: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return ArtifactManifest{}, fmt.Errorf("validate artifact manifest: %w", err)
	}
	return manifest, nil
}

func validateArtifactPath(artifactPath string) error {
	if artifactPath == "" {
		return fmt.Errorf("must not be empty")
	}
	if len(artifactPath) > 4096 {
		return fmt.Errorf("must not exceed 4096 bytes")
	}
	if strings.ContainsAny(artifactPath, "\x00\r\n\\") {
		return fmt.Errorf("must not contain NUL, line breaks, or backslashes")
	}
	if !path.IsAbs(artifactPath) {
		return fmt.Errorf("must be absolute")
	}
	if artifactPath == "/" || path.Clean(artifactPath) != artifactPath {
		return fmt.Errorf("must be clean")
	}
	return nil
}

func canonicalMode(mode fs.FileMode) (string, error) {
	if !mode.IsRegular() {
		return "", fmt.Errorf("must describe a regular file")
	}
	if mode.Perm() == 0 || mode.Perm()&022 != 0 {
		return "", fmt.Errorf("must be nonzero and not group/world writable")
	}
	return fmt.Sprintf("%04o", mode.Perm()), nil
}

func parseCanonicalMode(value string) (fs.FileMode, error) {
	if len(value) != 4 || value[0] != '0' {
		return 0, fmt.Errorf("must be a four-digit octal permission")
	}
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil || parsed > 0777 {
		return 0, fmt.Errorf("must be a four-digit octal permission")
	}
	mode := fs.FileMode(parsed)
	canonical, err := canonicalMode(mode)
	if err != nil {
		return 0, err
	}
	if canonical != value {
		return 0, fmt.Errorf("must be canonical")
	}
	return mode, nil
}

func canonicalGenerations(values []SourceGeneration) ([]SourceGeneration, error) {
	result := make([]SourceGeneration, len(values))
	copy(result, values)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].ID < result[j].ID
	})
	if err := validateCanonicalGenerations(result); err != nil {
		return nil, err
	}
	return result, nil
}

func validateCanonicalGenerations(values []SourceGeneration) error {
	if values == nil {
		return fmt.Errorf("must be present")
	}
	previous := ""
	for index, value := range values {
		if !sourceKindPattern.MatchString(value.Kind) {
			return fmt.Errorf("entry %d kind is invalid", index)
		}
		if !sourceIDPattern.MatchString(value.ID) {
			return fmt.Errorf("entry %d id is invalid", index)
		}
		if value.Generation == 0 {
			return fmt.Errorf("entry %d generation must be positive", index)
		}
		key := value.Kind + "\x00" + value.ID
		if index > 0 && key <= previous {
			return fmt.Errorf("entries must be unique and in ascending order")
		}
		previous = key
	}
	return nil
}

func recordsByPath(records []ArtifactRecord) map[string]ArtifactRecord {
	result := make(map[string]ArtifactRecord, len(records))
	for _, record := range records {
		result[record.Path] = record
	}
	return result
}

func unionPaths(first, second map[string]ArtifactRecord) []string {
	paths := make([]string, 0, len(first)+len(second))
	for artifactPath := range first {
		paths = append(paths, artifactPath)
	}
	for artifactPath := range second {
		if _, found := first[artifactPath]; !found {
			paths = append(paths, artifactPath)
		}
	}
	sort.Strings(paths)
	return paths
}

func equalArtifactRecord(first, second ArtifactRecord) bool {
	if first.Path != second.Path || first.Mode != second.Mode || first.ContentSHA256 != second.ContentSHA256 {
		return false
	}
	return equalGenerations(first.PolicyGenerations, second.PolicyGenerations) &&
		equalGenerations(first.CredentialGenerations, second.CredentialGenerations)
}

func equalGenerations(first, second []SourceGeneration) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func compareArtifact(expected ArtifactRecord, actual ObservedArtifact) ArtifactDrift {
	result := ArtifactDrift{
		Path:           expected.Path,
		ExpectedMode:   expected.Mode,
		ExpectedSHA256: expected.ContentSHA256,
		ActualMode:     fmt.Sprintf("%04o", actual.Mode.Perm()),
	}
	if !actual.Mode.IsRegular() {
		result.Kinds = append(result.Kinds, DriftType)
		return result
	}
	actualHash := sha256.Sum256(actual.Content)
	result.ActualSHA256 = hex.EncodeToString(actualHash[:])
	expectedMode, _ := parseCanonicalMode(expected.Mode)
	if actual.Mode.Perm() != expectedMode.Perm() {
		result.Kinds = append(result.Kinds, DriftMode)
	}
	if result.ActualSHA256 != expected.ContentSHA256 {
		result.Kinds = append(result.Kinds, DriftContent)
	}
	return result
}

func unexpectedDrift(actual ObservedArtifact) ArtifactDrift {
	result := ArtifactDrift{
		Path:       actual.Path,
		Kinds:      []DriftKind{DriftUnexpected},
		ActualMode: fmt.Sprintf("%04o", actual.Mode.Perm()),
	}
	if !actual.Mode.IsRegular() {
		result.Kinds = append(result.Kinds, DriftType)
		return result
	}
	hash := sha256.Sum256(actual.Content)
	result.ActualSHA256 = hex.EncodeToString(hash[:])
	return result
}

func rejectDuplicateJSONFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSON(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON documents")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func walkJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			keys[key] = struct{}{}
			if err := walkJSON(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := walkJSON(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}
