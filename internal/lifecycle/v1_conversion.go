package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/mihomo"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	v1state "github.com/vgrinkevich/vpnctl/internal/state"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

const V1ConversionSchemaVersion = 1

var (
	ErrV1ConversionNotReady = errors.New("v1 installation is not ready for deterministic conversion")
	ErrV1StageExists        = errors.New("v1 conversion staging root already exists")

	v2IdentityPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	v1MigrationCGNAT  = netip.MustParsePrefix("100.64.0.0/10")
	v1MigrationBench  = netip.MustParsePrefix("198.18.0.0/15")
)

// V1ConversionInput contains the explicit environment-dependent facts which
// cannot be safely inferred while translating the inspected v1 state.
type V1ConversionInput struct {
	Inspection    *V1Inspection
	StageRoot     string
	PublicIPv4    string
	SSHPort       int
	NodeCIDR      string
	ConvertedAt   time.Time
	Components    model.ComponentManifest
	HandshakeHost model.HandshakeHost
}

type V1IdentityMapping struct {
	SourceID    string `json:"source_id"`
	TargetID    string `json:"target_id"`
	IDPreserved bool   `json:"id_preserved"`
}

type V1ClientConversion struct {
	V1IdentityMapping
	Name            string          `json:"name"`
	Lifecycle       model.Lifecycle `json:"lifecycle"`
	OverlayIPv4     string          `json:"overlay_ipv4"`
	AssignedPresets []string        `json:"assigned_presets"`
}

type V1PresetConversion struct {
	SourceID   string `json:"source_id"`
	TargetName string `json:"target_name"`
	Selectors  int    `json:"selectors"`
}

type V1ArtifactConversion struct {
	SourcePath     string `json:"source_path"`
	StagedPath     string `json:"staged_path"`
	Kind           string `json:"kind"`
	SourceClientID string `json:"source_client_id,omitempty"`
	TargetClientID string `json:"target_client_id,omitempty"`
	Bytes          int64  `json:"bytes"`
}

// V1ConversionResult intentionally excludes the physical staging root and all
// credential/profile content. The caller already owns the requested target;
// public projections contain only stable logical mappings.
type V1ConversionResult struct {
	SchemaVersion      int                    `json:"schema_version"`
	Status             string                 `json:"status"`
	Gateway            V1IdentityMapping      `json:"gateway"`
	StateGeneration    uint64                 `json:"state_generation"`
	Clients            []V1ClientConversion   `json:"clients"`
	Presets            []V1PresetConversion   `json:"presets"`
	PreservedArtifacts []V1ArtifactConversion `json:"preserved_artifacts"`
}

func (result V1ConversionResult) String() string {
	data, err := json.Marshal(result)
	if err != nil {
		return "<v1-conversion>"
	}
	return string(data)
}

func (result V1ConversionResult) GoString() string { return result.String() }
func (result V1ConversionResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, result.String())
}

type v1ConversionPlan struct {
	state         model.State
	presetSources map[string][]byte
	secrets       map[model.SecretRef][]byte
	artifacts     map[string][]byte
	result        V1ConversionResult
}

// ConvertV1ToV2Stage writes a validated candidate beneath a new, explicit
// staging root. It never changes the inspected installation or a live v2 root.
func ConvertV1ToV2Stage(ctx context.Context, input V1ConversionInput) (result V1ConversionResult, err error) {
	if ctx == nil {
		return V1ConversionResult{}, fmt.Errorf("v1 conversion context is required")
	}
	stageRoot, err := validateV1StageRoot(input.StageRoot)
	if err != nil {
		return V1ConversionResult{}, err
	}
	input.StageRoot = stageRoot
	plan, err := buildV1ConversionPlan(input)
	if err != nil {
		return V1ConversionResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return V1ConversionResult{}, err
	}
	if err := createV1StageRoot(stageRoot); err != nil {
		return V1ConversionResult{}, err
	}
	published := false
	defer func() {
		if published {
			return
		}
		cleanupErr := removeV1StageRoot(stageRoot)
		if cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("remove incomplete v1 conversion stage: %w", cleanupErr))
		}
	}()

	paths, pathErr := store.NewPaths(stageRoot)
	if pathErr != nil {
		return V1ConversionResult{}, pathErr
	}
	if err := createV1StageLayout(paths, plan.artifacts); err != nil {
		return V1ConversionResult{}, err
	}
	for _, filename := range sortedStringKeys(plan.presetSources) {
		if err := ctx.Err(); err != nil {
			return V1ConversionResult{}, err
		}
		if err := writeV1StageFile(filepath.Join(paths.PresetsDir, filename), plan.presetSources[filename], 0o644); err != nil {
			return V1ConversionResult{}, fmt.Errorf("stage converted preset %s: %w", filename, err)
		}
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return V1ConversionResult{}, err
	}
	for _, reference := range sortedSecretRefs(plan.secrets) {
		if err := ctx.Err(); err != nil {
			return V1ConversionResult{}, err
		}
		if err := secrets.PutIfAbsent(reference, plan.secrets[reference]); err != nil {
			return V1ConversionResult{}, fmt.Errorf("stage converted credential %s: %w", reference, err)
		}
	}
	preservedRoot := filepath.Join(paths.ExportsDir, "v1-preserved")
	for _, relative := range sortedStringKeys(plan.artifacts) {
		if err := ctx.Err(); err != nil {
			return V1ConversionResult{}, err
		}
		if err := writeV1StageFile(filepath.Join(preservedRoot, filepath.FromSlash(relative)), plan.artifacts[relative], 0o600); err != nil {
			return V1ConversionResult{}, fmt.Errorf("stage preserved v1 artifact %s: %w", relative, err)
		}
	}
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return V1ConversionResult{}, err
	}
	// Authoritative state is the publication marker and is deliberately last.
	if err := stateStore.Save(0, plan.state); err != nil {
		return V1ConversionResult{}, fmt.Errorf("publish converted v2 state: %w", err)
	}
	if err := verifyV1ConversionStage(ctx, paths, stateStore, secrets, plan); err != nil {
		return V1ConversionResult{}, err
	}
	published = true
	return plan.result, nil
}

func buildV1ConversionPlan(input V1ConversionInput) (v1ConversionPlan, error) {
	inspection := input.Inspection
	if inspection == nil || inspection.destroyed {
		return v1ConversionPlan{}, fmt.Errorf("%w: inspection is absent or destroyed", ErrV1ConversionNotReady)
	}
	if inspection.Report.Status != V1InspectionReady && inspection.Report.Status != V1InspectionPartial {
		return v1ConversionPlan{}, fmt.Errorf("%w: inspection status is %s", ErrV1ConversionNotReady, inspection.Report.Status)
	}
	for _, issue := range inspection.Report.Issues {
		if issue.Severity == V1IssueError {
			return v1ConversionPlan{}, fmt.Errorf("%w: inspection contains error %s", ErrV1ConversionNotReady, issue.Code)
		}
	}
	server := inspection.state.Server
	if server == nil || len(inspection.privateKeys["server"]) == 0 {
		return v1ConversionPlan{}, fmt.Errorf("%w: validated server state and private key are required", ErrV1ConversionNotReady)
	}
	if err := validateV1ConversionPublicIPv4(input.PublicIPv4); err != nil {
		return v1ConversionPlan{}, err
	}
	if input.ConvertedAt.IsZero() || input.ConvertedAt.Location() != time.UTC {
		return v1ConversionPlan{}, fmt.Errorf("v1 conversion time must be a non-zero UTC value")
	}
	if input.NodeCIDR == "" {
		input.NodeCIDR = model.DefaultNodeCIDR
	}
	clientPrefix, err := netip.ParsePrefix(server.WireGuardSubnet)
	if err != nil || !clientPrefix.Addr().Is4() {
		return v1ConversionPlan{}, fmt.Errorf("%w: v1 client subnet cannot be normalized", ErrV1ConversionNotReady)
	}
	clientCIDR := clientPrefix.Masked().String()

	gateway, clientIDs := mapV1Identities(server.ID, inspection.state.Clients)
	network := linuxplatform.GatewayNetworkPlan{
		PublicIPv4: input.PublicIPv4, ClientCIDR: clientCIDR,
		NodeCIDR: input.NodeCIDR, ExternalInterface: server.ExternalInterface,
	}
	candidate := initialGatewayState(gateway.TargetID, input.ConvertedAt, network, input.SSHPort, input.Components, input.HandshakeHost)
	candidate.DNS.IPv4 = append([]string(nil), server.DNSServers...)
	if len(candidate.DNS.IPv4) == 0 {
		candidate.DNS.IPv4 = model.DefaultGatewayDNSUpstreams()
	}

	presetSources := make(map[string][]byte, len(inspection.rulesets))
	presets := make([]model.Preset, 0, len(inspection.rulesets))
	presetResult := make([]V1PresetConversion, 0, len(inspection.rulesets))
	rulesetIDs := make([]string, 0, len(inspection.rulesets))
	for id := range inspection.rulesets {
		rulesetIDs = append(rulesetIDs, id)
	}
	if len(rulesetIDs) > routing.PresetMaximumDocuments {
		return v1ConversionPlan{}, fmt.Errorf("%w: converted preset count exceeds %d", ErrV1ConversionNotReady, routing.PresetMaximumDocuments)
	}
	sort.Slice(rulesetIDs, func(i, j int) bool {
		left, right := strings.ToLower(rulesetIDs[i]), strings.ToLower(rulesetIDs[j])
		if left != right {
			return left < right
		}
		return rulesetIDs[i] < rulesetIDs[j]
	})
	totalSelectors := 0
	for _, id := range rulesetIDs {
		ruleset := inspection.rulesets[id]
		source, err := renderV1PresetSource(ruleset)
		if err != nil {
			return v1ConversionPlan{}, fmt.Errorf("convert v1 ruleset %s: %w", id, err)
		}
		preset, err := routing.CompilePresetSource(source, input.ConvertedAt)
		if err != nil {
			return v1ConversionPlan{}, fmt.Errorf("compile converted v1 ruleset %s: %w", id, err)
		}
		filename := id + ".yaml"
		presetSources[filename] = source
		presets = append(presets, preset)
		totalSelectors += len(preset.Selectors)
		if totalSelectors > routing.PresetMaximumSetSelectors {
			return v1ConversionPlan{}, fmt.Errorf("%w: converted preset selectors exceed %d", ErrV1ConversionNotReady, routing.PresetMaximumSetSelectors)
		}
		presetResult = append(presetResult, V1PresetConversion{SourceID: id, TargetName: preset.Name, Selectors: len(preset.Selectors)})
	}
	candidate.Presets = presets

	secrets := map[model.SecretRef][]byte{
		transport.GatewayStandardCredentialRef: inspection.privateKeys["server"],
	}
	clients := append([]v1state.ClientState(nil), inspection.state.Clients...)
	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	clientResult := make([]V1ClientConversion, 0, len(clients))
	for _, source := range clients {
		mapped := clientIDs[source.ID]
		lifecycle, revokedAt, err := convertV1ClientLifecycle(source, input.ConvertedAt)
		if err != nil {
			return v1ConversionPlan{}, err
		}
		assigned := []string{}
		if lifecycle != model.LifecycleDeleted {
			if presetName := detectV1ClientPreset(inspection, source); presetName != "" {
				names, _, _, resolveErr := routing.ResolveEffectiveAssignment(presets, []string{presetName})
				if resolveErr != nil {
					return v1ConversionPlan{}, fmt.Errorf("resolve converted client %s preset: %w", source.ID, resolveErr)
				}
				assigned = names
			}
		}
		client := model.Client{
			SchemaVersion: model.ResourceSchemaVersion, ID: mapped.TargetID, Name: source.Name, Platform: source.Platform,
			Lifecycle: lifecycle, OverlayIPv4: source.AssignedIP, CredentialGeneration: 1,
			AssignedPresets: append([]string{}, assigned...), ActiveTransport: model.TransportStandard,
			CreatedAt: source.CreatedAt.UTC(), RevokedAt: revokedAt,
		}
		if err := client.Validate(); err != nil {
			return v1ConversionPlan{}, fmt.Errorf("convert v1 client %s: %w", source.ID, err)
		}
		candidate.Clients = append(candidate.Clients, client)
		if len(assigned) != 0 {
			names, selectors, effectiveHash, resolveErr := routing.ResolveEffectiveAssignment(presets, assigned)
			if resolveErr != nil {
				return v1ConversionPlan{}, fmt.Errorf("build converted client %s policy: %w", source.ID, resolveErr)
			}
			candidate.Policies = append(candidate.Policies, model.Policy{
				SchemaVersion: model.ResourceSchemaVersion, TargetKind: model.TargetClient, TargetID: client.ID,
				PresetNames: names, Selectors: selectors, EffectiveHash: effectiveHash, Generation: 1,
			})
		}
		if lifecycle != model.LifecycleDeleted {
			privateKey := inspection.privateKeys["client:"+source.ID]
			if len(privateKey) == 0 {
				return v1ConversionPlan{}, fmt.Errorf("%w: client %s private key is unavailable", ErrV1ConversionNotReady, source.ID)
			}
			standard, transportErr := routing.BuildImportedStandardClientTransport(client, source.WireGuardPublicKey)
			if transportErr != nil {
				return v1ConversionPlan{}, fmt.Errorf("convert v1 client %s transport: %w", source.ID, transportErr)
			}
			candidate.Transports = append(candidate.Transports, standard)
			secrets[standard.CredentialRef] = privateKey
		}
		clientResult = append(clientResult, V1ClientConversion{
			V1IdentityMapping: mapped, Name: client.Name, Lifecycle: client.Lifecycle,
			OverlayIPv4: client.OverlayIPv4, AssignedPresets: append([]string{}, client.AssignedPresets...),
		})
	}
	if err := candidate.Validate(); err != nil {
		return v1ConversionPlan{}, fmt.Errorf("validate converted v2 gateway state: %w", err)
	}
	if _, err := model.EncodeState(candidate); err != nil {
		return v1ConversionPlan{}, fmt.Errorf("encode converted v2 gateway state: %w", err)
	}

	artifacts, artifactResult, err := planV1Artifacts(inspection, clientIDs)
	if err != nil {
		return v1ConversionPlan{}, err
	}
	return v1ConversionPlan{
		state: candidate, presetSources: presetSources, secrets: secrets, artifacts: artifacts,
		result: V1ConversionResult{
			SchemaVersion: V1ConversionSchemaVersion, Status: "staged", Gateway: gateway,
			StateGeneration: candidate.Generation, Clients: clientResult, Presets: presetResult,
			PreservedArtifacts: artifactResult,
		},
	}, nil
}

func mapV1Identities(serverID string, clients []v1state.ClientState) (V1IdentityMapping, map[string]V1IdentityMapping) {
	gatewayID := serverID
	gatewayPreserved := v2IdentityPattern.MatchString(serverID)
	if !gatewayPreserved {
		gatewayID = deterministicV1Identity("gateway", serverID)
	}
	gateway := V1IdentityMapping{SourceID: serverID, TargetID: gatewayID, IDPreserved: gatewayPreserved}
	occupied := map[string]struct{}{gatewayID: {}}
	mappings := make(map[string]V1IdentityMapping, len(clients))
	ordered := append([]v1state.ClientState(nil), clients...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for _, client := range ordered {
		if !v2IdentityPattern.MatchString(client.ID) {
			continue
		}
		if _, conflict := occupied[client.ID]; conflict {
			continue
		}
		mappings[client.ID] = V1IdentityMapping{SourceID: client.ID, TargetID: client.ID, IDPreserved: true}
		occupied[client.ID] = struct{}{}
	}
	for _, client := range ordered {
		if _, found := mappings[client.ID]; found {
			continue
		}
		for attempt := 0; ; attempt++ {
			target := deterministicV1Identity("client", serverID, client.ID, fmt.Sprintf("%d", attempt))
			if _, conflict := occupied[target]; conflict {
				continue
			}
			mappings[client.ID] = V1IdentityMapping{SourceID: client.ID, TargetID: target}
			occupied[target] = struct{}{}
			break
		}
	}
	return gateway, mappings
}

func deterministicV1Identity(parts ...string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("vpnctl-v1-to-v2-identity\x00"))
	for _, part := range parts {
		_, _ = hash.Write([]byte(fmt.Sprintf("%d:", len(part))))
		_, _ = hash.Write([]byte(part))
	}
	value := hash.Sum(nil)[:16]
	value[6] = value[6]&0x0f | 0x80 // RFC 9562 version 8, application-defined bytes.
	value[8] = value[8]&0x3f | 0x80 // RFC variant.
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

func convertV1ClientLifecycle(client v1state.ClientState, convertedAt time.Time) (model.Lifecycle, *time.Time, error) {
	switch client.Status {
	case v1state.ClientStatusActive:
		return model.LifecycleActive, nil, nil
	case v1state.ClientStatusRevoked:
		if client.RevokedAt == nil {
			return "", nil, fmt.Errorf("%w: revoked client %s has no revocation time", ErrV1ConversionNotReady, client.ID)
		}
		value := client.RevokedAt.UTC()
		return model.LifecycleRevoked, &value, nil
	case v1state.ClientStatusDeleted:
		value := convertedAt
		if client.RevokedAt != nil {
			value = client.RevokedAt.UTC()
		}
		return model.LifecycleDeleted, &value, nil
	default:
		return "", nil, fmt.Errorf("%w: client %s lifecycle is unsupported", ErrV1ConversionNotReady, client.ID)
	}
}

func renderV1PresetSource(ruleset v1state.Ruleset) ([]byte, error) {
	domains := append([]string(nil), ruleset.Domains...)
	sort.Strings(domains)
	var source strings.Builder
	fmt.Fprintf(&source, "# Migrated from vpnctl v1 ruleset %s.\n", ruleset.ID)
	fmt.Fprintf(&source, "schema_version: %d\nname: %s\ninclude:\n", routing.PresetDocumentSchemaVersion, ruleset.ID)
	for _, domain := range domains {
		fmt.Fprintf(&source, "  - type: domain-suffix\n    value: %s\n", domain)
	}
	source.WriteString("exclude: []\n")
	encoded := []byte(source.String())
	ast, err := routing.DecodePresetDocument(encoded)
	if err != nil {
		return nil, err
	}
	if ast.Name != ruleset.ID || len(ast.Selectors) != len(domains) {
		return nil, fmt.Errorf("converted preset does not preserve the v1 selector set")
	}
	return encoded, nil
}

func detectV1ClientPreset(inspection *V1Inspection, client v1state.ClientState) string {
	matches := matchingV1ClientPresets(inspection, client)
	if len(matches) != 1 {
		return ""
	}
	return matches[0]
}

func matchingV1ClientPresets(inspection *V1Inspection, client v1state.ClientState) []string {
	privateKey := inspection.privateKeys["client:"+client.ID]
	profile := inspection.generated[filepath.ToSlash(filepath.Join("generated", "delivery", client.ID+".clash.yaml"))]
	if len(privateKey) == 0 || len(profile) == 0 || inspection.state.Server == nil {
		return nil
	}
	dns := append([]string(nil), inspection.state.Server.DNSServers...)
	if len(dns) == 0 {
		dns = []string{"1.1.1.1", "8.8.8.8"}
	}
	matches := []string{}
	for id, ruleset := range inspection.rulesets {
		rendered, err := mihomo.RenderConfig(mihomo.Config{
			DNSServers: dns, Server: inspection.state.Server.PublicEndpoint, Port: inspection.state.Server.WireGuardPort,
			ClientIP: client.AssignedIP, PrivateKey: string(privateKey), ServerPublicKey: inspection.state.Server.WireGuardPublicKey,
			RulesetType: ruleset.Type, Domains: append([]string(nil), ruleset.Domains...),
		})
		if err == nil && bytes.Equal(profile, []byte(rendered)) {
			matches = append(matches, id)
		}
	}
	sort.Strings(matches)
	return matches
}

func planV1Artifacts(inspection *V1Inspection, mappings map[string]V1IdentityMapping) (map[string][]byte, []V1ArtifactConversion, error) {
	metadata := make(map[string]V1GeneratedArtifact, len(inspection.Report.Generated))
	for _, artifact := range inspection.Report.Generated {
		metadata[strings.TrimPrefix(artifact.Path, ".vpnctl/")] = artifact
	}
	artifacts := make(map[string][]byte, len(inspection.generated))
	result := make([]V1ArtifactConversion, 0, len(inspection.generated))
	for _, relative := range sortedStringKeys(inspection.generated) {
		parts := strings.Split(relative, "/")
		if len(parts) != 3 || parts[0] != "generated" || (parts[1] != "wireguard" && parts[1] != "mihomo" && parts[1] != "delivery") ||
			parts[2] == "" || parts[2] == "." || parts[2] == ".." || strings.ContainsAny(parts[2], "\\\x00\r\n") {
			return nil, nil, fmt.Errorf("%w: generated artifact path is not portable", ErrV1ConversionNotReady)
		}
		data := inspection.generated[relative]
		artifacts[relative] = data
		item := metadata[relative]
		converted := V1ArtifactConversion{
			SourcePath: ".vpnctl/" + relative,
			StagedPath: filepath.ToSlash(filepath.Join("/var/lib/vpnctl/exports/v1-preserved", filepath.FromSlash(relative))),
			Kind:       parts[1], SourceClientID: item.ClientID, Bytes: int64(len(data)),
		}
		if mapping, found := mappings[item.ClientID]; found {
			converted.TargetClientID = mapping.TargetID
		}
		result = append(result, converted)
	}
	return artifacts, result, nil
}

func validateV1ConversionPublicIPv4(value string) error {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.String() != value || !address.IsGlobalUnicast() || address.IsPrivate() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() || v1MigrationCGNAT.Contains(address) || v1MigrationBench.Contains(address) {
		return fmt.Errorf("v1 conversion public IPv4 must be an explicit canonical publicly routable address")
	}
	return nil
}

func validateV1StageRoot(value string) (string, error) {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == string(filepath.Separator) {
		return "", fmt.Errorf("v1 conversion staging root must be a clean absolute non-root path")
	}
	parent := filepath.Dir(value)
	info, err := os.Lstat(parent)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("v1 conversion staging parent must be a real existing directory")
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || filepath.Clean(resolved) != parent {
		return "", fmt.Errorf("v1 conversion staging parent must not traverse symlinks")
	}
	if _, err := os.Lstat(value); err == nil {
		return "", fmt.Errorf("%w", ErrV1StageExists)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect v1 conversion staging root: %w", err)
	}
	return value, nil
}

func createV1StageRoot(path string) (err error) {
	if err := os.Mkdir(path, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrV1StageExists
		}
		return fmt.Errorf("create v1 conversion staging root: %w", err)
	}
	defer func() {
		if err == nil {
			return
		}
		_ = os.Remove(path)
		_ = syncLifecycleDirectory(filepath.Dir(path))
	}()
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("set v1 conversion staging root mode: %w", err)
	}
	return syncLifecycleDirectory(filepath.Dir(path))
}

func createV1StageLayout(paths store.Paths, artifacts map[string][]byte) error {
	directories := []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Join(paths.Root, "etc"), 0o755},
		{paths.ConfigDir, 0o755},
		{paths.PresetsDir, 0o755},
		{filepath.Join(paths.Root, "var"), 0o755},
		{filepath.Join(paths.Root, "var", "lib"), 0o755},
		{paths.StateDir, 0o700},
		{paths.ExportsDir, 0o700},
		{paths.ClientExportsDir, 0o700},
		{filepath.Join(paths.ExportsDir, "v1-preserved"), 0o700},
		{filepath.Join(paths.ExportsDir, "v1-preserved", "generated"), 0o700},
	}
	kinds := map[string]struct{}{}
	for relative := range artifacts {
		parts := strings.Split(relative, "/")
		kinds[parts[1]] = struct{}{}
	}
	for _, kind := range sortedSet(kinds) {
		directories = append(directories, struct {
			path string
			mode os.FileMode
		}{filepath.Join(paths.ExportsDir, "v1-preserved", "generated", kind), 0o700})
	}
	for _, directory := range directories {
		if err := os.Mkdir(directory.path, directory.mode); err != nil {
			return fmt.Errorf("create v1 conversion directory: %w", err)
		}
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			return fmt.Errorf("set v1 conversion directory mode: %w", err)
		}
		if err := syncLifecycleDirectory(filepath.Dir(directory.path)); err != nil {
			return err
		}
	}
	return nil
}

func writeV1StageFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syncLifecycleDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	keep = true
	return nil
}

func verifyV1ConversionStage(
	ctx context.Context,
	paths store.Paths,
	stateStore *store.StateStore,
	secrets *store.SecretStore,
	plan v1ConversionPlan,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	loaded, err := stateStore.Load()
	if err != nil || !reflect.DeepEqual(loaded, plan.state) {
		return fmt.Errorf("verify converted v2 state: staged state does not match the validated candidate")
	}
	catalog, err := routing.NewPresetCatalog(paths, stateStore)
	if err != nil {
		return fmt.Errorf("verify converted preset catalog: %w", err)
	}
	validation, err := catalog.Validate()
	if err != nil || !validation.Valid || validation.SourceCount != len(plan.presetSources) {
		return fmt.Errorf("verify converted preset catalog: staged sources do not match effective state")
	}
	for _, reference := range sortedSecretRefs(plan.secrets) {
		stored, err := secrets.Get(reference)
		if err != nil {
			return fmt.Errorf("verify staged credential %s: %w", reference, err)
		}
		matches := bytes.Equal(stored, plan.secrets[reference])
		clear(stored)
		if !matches {
			return fmt.Errorf("verify staged credential %s: content differs", reference)
		}
	}
	for _, filename := range sortedStringKeys(plan.presetSources) {
		data, metadata, err := readV1RegularFile(ctx, filepath.Join(paths.PresetsDir, filename), routing.PresetMaximumDocumentBytes)
		if err != nil || metadata.Mode.Perm() != 0o644 || !bytes.Equal(data, plan.presetSources[filename]) {
			clear(data)
			return fmt.Errorf("verify staged preset %s: content or mode differs", filename)
		}
		clear(data)
	}
	preservedRoot := filepath.Join(paths.ExportsDir, "v1-preserved")
	for _, relative := range sortedStringKeys(plan.artifacts) {
		data, metadata, err := readV1RegularFile(ctx, filepath.Join(preservedRoot, filepath.FromSlash(relative)), v1MaximumGeneratedBytes)
		if err != nil || metadata.Mode.Perm() != 0o600 || !bytes.Equal(data, plan.artifacts[relative]) {
			clear(data)
			return fmt.Errorf("verify preserved v1 artifact %s: content or mode differs", relative)
		}
		clear(data)
	}
	return nil
}

func removeV1StageRoot(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("incomplete staging root changed type; refusing recursive cleanup")
	}
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	return syncLifecycleDirectory(filepath.Dir(path))
}

func sortedStringKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedSecretRefs(values map[model.SecretRef][]byte) []model.SecretRef {
	keys := make([]model.SecretRef, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
