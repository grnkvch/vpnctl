package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

const (
	ReleaseManifestSchemaVersion          = 1
	ReleaseSignatureEnvelopeSchemaVersion = 1
	ReleaseSignatureAlgorithm             = "Ed25519"
	MaximumSignedReleaseManifestBytes     = 1 << 20
	MaximumReleaseManifestPayloadBytes    = 512 << 10
	releaseManifestSignatureDomain        = "vpnctl-release-manifest-v1\x00"
	maximumReleaseEntries                 = 64
)

var (
	ErrInvalidReleaseManifest     = errors.New("invalid release manifest")
	ErrUnsupportedReleasePlatform = errors.New("unsupported release platform")
	ErrReleaseArtifactMismatch    = errors.New("release artifact mismatch")
	releaseIdentifierPattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	releasePackagePattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}$`)
)

// ReleaseManifest is the signed release source of truth. ComponentManifest is
// also persisted after installation; artifacts and apt ranges are delivery-
// only metadata used before any host mutation.
type ReleaseManifest struct {
	SchemaVersion     int                       `json:"schema_version"`
	ComponentManifest model.ComponentManifest   `json:"component_manifest"`
	Artifacts         []ReleaseArtifact         `json:"artifacts"`
	APTPackages       []APTPackageCompatibility `json:"apt_packages"`
}

type ReleaseArtifact struct {
	Component string       `json:"component"`
	Path      string       `json:"path"`
	SHA256    string       `json:"sha256"`
	Roles     []model.Role `json:"roles"`
}

type APTPackageCompatibility struct {
	Component               string       `json:"component"`
	Package                 string       `json:"package"`
	Source                  string       `json:"source"`
	MinimumVersion          string       `json:"minimum_version"`
	MaximumVersionExclusive string       `json:"maximum_version_exclusive"`
	Roles                   []model.Role `json:"roles"`
	Capabilities            []string     `json:"capabilities"`
}

type SignedReleaseManifest struct {
	SchemaVersion int    `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	Payload       string `json:"payload"`
	Signature     string `json:"signature"`
}

type ReleasePlatform struct {
	OperatingSystem string
	Version         string
	Architecture    string
}

// NewV2ReleaseManifest builds the production v2 delivery contract from the
// same provider pins consumed by runtime validation. The caller supplies only
// build-specific vpnctl identity and the migration reversibility decision.
func NewV2ReleaseManifest(vpnctlVersion, vpnctlSHA256 string, migrationReversible bool) (ReleaseManifest, error) {
	manifest := ReleaseManifest{
		SchemaVersion: ReleaseManifestSchemaVersion,
		ComponentManifest: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: vpnctlVersion,
			ControlProtocols: []string{"1.0"}, StateSchemaMinimum: model.StateSchemaVersion, StateSchemaMaximum: model.StateSchemaVersion,
			TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1,
			MigrationReversible: migrationReversible,
			Components: []model.ComponentPin{
				{Name: tunnel.FRPProviderName, Version: tunnel.FRPProviderVersion, Source: "vpnctl-release-bundle", Bundled: true, SHA256: tunnel.FRPProviderSHA256, Capabilities: []string{"dynamic-reload", "http-plugin-authorization", "tcp-mux", "tls-server-verification"}},
				{Name: transport.RestrictedProviderName, Version: transport.RestrictedProviderVersion, Source: "vpnctl-release-bundle", Bundled: true, SHA256: transport.RestrictedProviderSHA256, Capabilities: []string{"redir-host-split-dns", "shadowsocks-2022-blake3-aes-256-gcm", "shadowtls-v3-strict", "tun-routing", "uot-v2"}},
				{Name: "nftables", Version: "1.0.9", Source: "ubuntu-24.04-noble", Capabilities: []string{"atomic-ruleset", "inet-family"}},
				{Name: ingress.NginxProviderName, Version: ingress.NginxProviderPackageVersion, Source: "ubuntu-24.04-noble-updates", Capabilities: []string{"http-1", "http-2", "streaming-proxy"}},
				{Name: "vpnctl", Version: vpnctlVersion, Source: "vpnctl-release-bundle", Bundled: true, SHA256: vpnctlSHA256, Capabilities: []string{"cli", "controller"}},
				{Name: "wireguard-tools", Version: "1.0.20210914", Source: "ubuntu-24.04-noble", Capabilities: []string{"wireguard-userspace-tools"}},
			},
		},
		Artifacts: []ReleaseArtifact{
			{Component: "vpnctl", Path: "bin/vpnctl", SHA256: vpnctlSHA256, Roles: []model.Role{model.RoleGateway, model.RoleNode}},
			{Component: tunnel.FRPProviderName, Path: "components/" + tunnel.FRPProviderAsset, SHA256: tunnel.FRPProviderSHA256, Roles: []model.Role{model.RoleGateway, model.RoleNode}},
			{Component: transport.RestrictedProviderName, Path: "components/" + transport.RestrictedProviderAsset, SHA256: transport.RestrictedProviderSHA256, Roles: []model.Role{model.RoleGateway, model.RoleNode}},
		},
		APTPackages: []APTPackageCompatibility{
			{Component: "nftables", Package: "nftables", Source: "ubuntu-24.04-noble", MinimumVersion: "1.0.9-1build1", MaximumVersionExclusive: "1.1", Roles: []model.Role{model.RoleGateway, model.RoleNode}, Capabilities: []string{"atomic-ruleset", "inet-family"}},
			{Component: ingress.NginxProviderName, Package: "nginx", Source: "ubuntu-24.04-noble-updates", MinimumVersion: ingress.NginxProviderPackageVersion, MaximumVersionExclusive: "1.24.1", Roles: []model.Role{model.RoleGateway}, Capabilities: []string{"http-1", "http-2", "streaming-proxy"}},
			{Component: "wireguard-tools", Package: "wireguard-tools", Source: "ubuntu-24.04-noble", MinimumVersion: "1.0.20210914-1ubuntu4", MaximumVersionExclusive: "1.1", Roles: []model.Role{model.RoleGateway, model.RoleNode}, Capabilities: []string{"wireguard-userspace-tools"}},
		},
	}
	if err := manifest.Validate(); err != nil {
		return ReleaseManifest{}, err
	}
	return manifest, nil
}

func (manifest ReleaseManifest) Validate() error {
	if manifest.SchemaVersion != ReleaseManifestSchemaVersion {
		return releaseManifestInvalid("schema_version must be %d", ReleaseManifestSchemaVersion)
	}
	if err := manifest.ComponentManifest.Validate(); err != nil {
		return releaseManifestInvalid("component_manifest: %v", err)
	}
	if len(manifest.ComponentManifest.Components) > maximumReleaseEntries {
		return releaseManifestInvalid("component_manifest.components exceeds %d entries", maximumReleaseEntries)
	}
	if len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > maximumReleaseEntries {
		return releaseManifestInvalid("artifacts must contain between 1 and %d entries", maximumReleaseEntries)
	}
	if len(manifest.APTPackages) == 0 || len(manifest.APTPackages) > maximumReleaseEntries {
		return releaseManifestInvalid("apt_packages must contain between 1 and %d entries", maximumReleaseEntries)
	}

	components := make(map[string]model.ComponentPin, len(manifest.ComponentManifest.Components))
	for index, component := range manifest.ComponentManifest.Components {
		if index > 0 && manifest.ComponentManifest.Components[index-1].Name >= component.Name {
			return releaseManifestInvalid("component_manifest.components must be sorted by unique name")
		}
		if !sortedUniqueIdentifiers(component.Capabilities) {
			return releaseManifestInvalid("component_manifest.components[%d].capabilities must be sorted and unique", index)
		}
		components[component.Name] = component
	}

	artifactComponents := make(map[string]ReleaseArtifact, len(manifest.Artifacts))
	artifactPaths := make(map[string]struct{}, len(manifest.Artifacts))
	for index, artifact := range manifest.Artifacts {
		if index > 0 && manifest.Artifacts[index-1].Path >= artifact.Path {
			return releaseManifestInvalid("artifacts must be sorted by unique path")
		}
		component, found := components[artifact.Component]
		if !found || !component.Bundled {
			return releaseManifestInvalid("artifacts[%d].component must reference a bundled component", index)
		}
		if err := validateReleasePath(artifact.Path); err != nil {
			return releaseManifestInvalid("artifacts[%d].path: %v", index, err)
		}
		if artifact.SHA256 != component.SHA256 || !validReleaseSHA256(artifact.SHA256) {
			return releaseManifestInvalid("artifacts[%d].sha256 must match the component pin", index)
		}
		if err := validateReleaseRoles(artifact.Roles); err != nil {
			return releaseManifestInvalid("artifacts[%d].roles: %v", index, err)
		}
		if _, duplicate := artifactComponents[artifact.Component]; duplicate {
			return releaseManifestInvalid("artifacts[%d].component duplicates %s", index, artifact.Component)
		}
		if _, duplicate := artifactPaths[artifact.Path]; duplicate {
			return releaseManifestInvalid("artifacts[%d].path duplicates %s", index, artifact.Path)
		}
		artifactComponents[artifact.Component] = artifact
		artifactPaths[artifact.Path] = struct{}{}
	}

	aptComponents := make(map[string]struct{}, len(manifest.APTPackages))
	aptPackages := make(map[string]struct{}, len(manifest.APTPackages))
	for index, compatibility := range manifest.APTPackages {
		if index > 0 {
			previous := manifest.APTPackages[index-1]
			if previous.Package > compatibility.Package ||
				(previous.Package == compatibility.Package && previous.Component >= compatibility.Component) {
				return releaseManifestInvalid("apt_packages must be sorted by unique package and component")
			}
		}
		component, found := components[compatibility.Component]
		if !found || component.Bundled {
			return releaseManifestInvalid("apt_packages[%d].component must reference an apt-provided component", index)
		}
		if !releasePackagePattern.MatchString(compatibility.Package) {
			return releaseManifestInvalid("apt_packages[%d].package must be a canonical Debian package name", index)
		}
		if compatibility.Source != component.Source {
			return releaseManifestInvalid("apt_packages[%d].source must match the component pin", index)
		}
		for field, value := range map[string]string{
			"source": compatibility.Source, "minimum_version": compatibility.MinimumVersion,
			"maximum_version_exclusive": compatibility.MaximumVersionExclusive,
		} {
			if !validReleaseText(value) {
				return releaseManifestInvalid("apt_packages[%d].%s must be a non-empty single-line value", index, field)
			}
		}
		if compatibility.MinimumVersion == compatibility.MaximumVersionExclusive {
			return releaseManifestInvalid("apt_packages[%d] has an empty version range", index)
		}
		if err := validateReleaseRoles(compatibility.Roles); err != nil {
			return releaseManifestInvalid("apt_packages[%d].roles: %v", index, err)
		}
		if !sortedUniqueIdentifiers(compatibility.Capabilities) {
			return releaseManifestInvalid("apt_packages[%d].capabilities must be sorted and unique", index)
		}
		if !equalReleaseStrings(compatibility.Capabilities, component.Capabilities) {
			return releaseManifestInvalid("apt_packages[%d].capabilities must match the component pin", index)
		}
		if _, duplicate := aptComponents[compatibility.Component]; duplicate {
			return releaseManifestInvalid("apt_packages[%d].component duplicates %s", index, compatibility.Component)
		}
		if _, duplicate := aptPackages[compatibility.Package]; duplicate {
			return releaseManifestInvalid("apt_packages[%d].package duplicates %s", index, compatibility.Package)
		}
		aptComponents[compatibility.Component] = struct{}{}
		aptPackages[compatibility.Package] = struct{}{}
	}

	vpnctl, found := components["vpnctl"]
	if !found || !vpnctl.Bundled || vpnctl.Version != manifest.ComponentManifest.VPNCTLVersion {
		return releaseManifestInvalid("vpnctl must be a bundled component matching vpnctl_version")
	}
	vpnctlArtifact, found := artifactComponents["vpnctl"]
	if !found {
		return releaseManifestInvalid("vpnctl binary artifact is required")
	}
	if !equalReleaseRoles(vpnctlArtifact.Roles, []model.Role{model.RoleGateway, model.RoleNode}) {
		return releaseManifestInvalid("vpnctl binary artifact must serve both roles")
	}
	for name, component := range components {
		if component.Bundled {
			if _, found := artifactComponents[name]; !found {
				return releaseManifestInvalid("bundled component %s has no artifact", name)
			}
		} else if _, found := aptComponents[name]; !found {
			return releaseManifestInvalid("apt-provided component %s has no compatibility range", name)
		}
	}
	return nil
}

func EncodeSignedReleaseManifest(manifest ReleaseManifest, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, releaseManifestInvalid("signing key must be Ed25519")
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return nil, releaseManifestInvalid("encode payload: %v", err)
	}
	if len(payload) > MaximumReleaseManifestPayloadBytes {
		return nil, releaseManifestInvalid("payload exceeds %d bytes", MaximumReleaseManifestPayloadBytes)
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, releaseManifestInvalid("derive Ed25519 public key")
	}
	signature := ed25519.Sign(privateKey, releaseManifestSignedMessage(payload))
	envelope := SignedReleaseManifest{
		SchemaVersion: ReleaseSignatureEnvelopeSchemaVersion,
		Algorithm:     ReleaseSignatureAlgorithm,
		KeyID:         releaseManifestKeyID(publicKey),
		Payload:       base64.RawURLEncoding.EncodeToString(payload),
		Signature:     base64.RawURLEncoding.EncodeToString(signature),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, releaseManifestInvalid("encode signature envelope: %v", err)
	}
	return encoded, nil
}

func DecodeAndVerifyReleaseManifest(data []byte, publicKey ed25519.PublicKey) (ReleaseManifest, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return ReleaseManifest{}, releaseManifestInvalid("verification key must be Ed25519")
	}
	if len(data) == 0 || len(data) > MaximumSignedReleaseManifestBytes {
		return ReleaseManifest{}, releaseManifestInvalid("signature envelope size is invalid")
	}
	var envelope SignedReleaseManifest
	if err := decodeStrictReleaseJSON(data, &envelope); err != nil {
		return ReleaseManifest{}, releaseManifestInvalid("decode signature envelope: %v", err)
	}
	if envelope.SchemaVersion != ReleaseSignatureEnvelopeSchemaVersion || envelope.Algorithm != ReleaseSignatureAlgorithm {
		return ReleaseManifest{}, releaseManifestInvalid("unsupported signature envelope")
	}
	if envelope.KeyID != releaseManifestKeyID(publicKey) {
		return ReleaseManifest{}, releaseManifestInvalid("release key ID mismatch")
	}
	payload, err := decodeCanonicalReleaseBase64(envelope.Payload)
	if err != nil || len(payload) == 0 || len(payload) > MaximumReleaseManifestPayloadBytes {
		return ReleaseManifest{}, releaseManifestInvalid("payload is invalid")
	}
	signature, err := decodeCanonicalReleaseBase64(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ReleaseManifest{}, releaseManifestInvalid("signature is invalid")
	}
	if !ed25519.Verify(publicKey, releaseManifestSignedMessage(payload), signature) {
		return ReleaseManifest{}, releaseManifestInvalid("signature verification failed")
	}
	var manifest ReleaseManifest
	if err := decodeStrictReleaseJSON(payload, &manifest); err != nil {
		return ReleaseManifest{}, releaseManifestInvalid("decode signed payload: %v", err)
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, payload) {
		return ReleaseManifest{}, releaseManifestInvalid("payload is not canonical JSON")
	}
	if err := manifest.Validate(); err != nil {
		return ReleaseManifest{}, err
	}
	return cloneReleaseManifest(manifest), nil
}

func VerifyReleasePlatform(manifest ReleaseManifest, observed ReleasePlatform) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if observed.OperatingSystem != "ubuntu" || observed.Version != "24.04" || observed.Architecture != manifest.ComponentManifest.TargetArchitecture ||
		manifest.ComponentManifest.TargetOS != observed.OperatingSystem+" "+observed.Version {
		return fmt.Errorf("%w: release requires %s %s, observed %s %s %s",
			ErrUnsupportedReleasePlatform, manifest.ComponentManifest.TargetOS, manifest.ComponentManifest.TargetArchitecture,
			observed.OperatingSystem, observed.Version, observed.Architecture)
	}
	return nil
}

func VerifyReleaseArtifact(manifest ReleaseManifest, relativePath string, content io.Reader) error {
	if content == nil {
		return fmt.Errorf("%w: artifact reader is required", ErrReleaseArtifactMismatch)
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	var expected string
	for _, artifact := range manifest.Artifacts {
		if artifact.Path == relativePath {
			expected = artifact.SHA256
			break
		}
	}
	if expected == "" {
		return fmt.Errorf("%w: artifact path is not signed", ErrReleaseArtifactMismatch)
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, content); err != nil {
		return fmt.Errorf("%w: read artifact", ErrReleaseArtifactMismatch)
	}
	if hex.EncodeToString(digest.Sum(nil)) != expected {
		return fmt.Errorf("%w: checksum does not match signed manifest", ErrReleaseArtifactMismatch)
	}
	return nil
}

func releaseManifestSignedMessage(payload []byte) []byte {
	message := make([]byte, 0, len(releaseManifestSignatureDomain)+len(payload))
	message = append(message, releaseManifestSignatureDomain...)
	return append(message, payload...)
}

func releaseManifestKeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func releaseManifestInvalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidReleaseManifest, fmt.Sprintf(format, arguments...))
}

func validateReleasePath(value string) error {
	if value == "" || len(value) > 255 || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "." || strings.HasPrefix(value, "../") {
		return fmt.Errorf("must be a canonical relative slash path")
	}
	for _, segment := range strings.Split(value, "/") {
		if !releaseIdentifierPattern.MatchString(segment) && !validReleaseFileName(segment) {
			return fmt.Errorf("contains an invalid path segment")
		}
	}
	return nil
}

func validReleaseFileName(value string) bool {
	if value == "" || value[0] == '.' || value[len(value)-1] == '.' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func validateReleaseRoles(roles []model.Role) error {
	if len(roles) == 0 || len(roles) > 2 {
		return fmt.Errorf("must contain gateway, node, or both")
	}
	for index, role := range roles {
		if role != model.RoleGateway && role != model.RoleNode {
			return fmt.Errorf("contains unsupported role %q", role)
		}
		if index > 0 && releaseRoleRank(roles[index-1]) >= releaseRoleRank(role) {
			return fmt.Errorf("must be sorted and unique")
		}
	}
	return nil
}

func releaseRoleRank(role model.Role) int {
	if role == model.RoleGateway {
		return 0
	}
	return 1
}

func validReleaseSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func validReleaseText(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}

func sortedUniqueIdentifiers(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for index, value := range values {
		if !releaseIdentifierPattern.MatchString(value) || (index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return true
}

func decodeCanonicalReleaseBase64(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("non-canonical base64url")
	}
	return decoded, nil
}

func equalReleaseStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalReleaseRoles(left, right []model.Role) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneReleaseManifest(manifest ReleaseManifest) ReleaseManifest {
	manifest.ComponentManifest.ControlProtocols = append([]string(nil), manifest.ComponentManifest.ControlProtocols...)
	manifest.ComponentManifest.Components = append([]model.ComponentPin(nil), manifest.ComponentManifest.Components...)
	for index := range manifest.ComponentManifest.Components {
		manifest.ComponentManifest.Components[index].Capabilities = append([]string(nil), manifest.ComponentManifest.Components[index].Capabilities...)
	}
	manifest.Artifacts = append([]ReleaseArtifact(nil), manifest.Artifacts...)
	for index := range manifest.Artifacts {
		manifest.Artifacts[index].Roles = append([]model.Role(nil), manifest.Artifacts[index].Roles...)
	}
	manifest.APTPackages = append([]APTPackageCompatibility(nil), manifest.APTPackages...)
	for index := range manifest.APTPackages {
		manifest.APTPackages[index].Roles = append([]model.Role(nil), manifest.APTPackages[index].Roles...)
		manifest.APTPackages[index].Capabilities = append([]string(nil), manifest.APTPackages[index].Capabilities...)
	}
	return manifest
}

func decodeStrictReleaseJSON(data []byte, destination any) error {
	if err := rejectReleaseDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON documents")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func rejectReleaseDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkReleaseJSON(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON documents")
		}
		return err
	}
	return nil
}

func walkReleaseJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
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
			if err := walkReleaseJSON(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := walkReleaseJSON(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}
