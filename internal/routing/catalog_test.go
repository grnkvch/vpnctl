package routing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const catalogClientID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

func TestPresetCatalogListsShowsAndDiffsSourceAgainstEffectiveState(t *testing.T) {
	t.Parallel()

	telegramSource := catalogPresetSource("telegram", []model.Selector{
		{Kind: model.SelectorDomainSuffix, Value: "telegram.org"},
	})
	openAISource := catalogPresetSource("openai", []model.Selector{
		{Kind: model.SelectorDomainSuffix, Value: "openai.com"},
	})
	obsoleteSource := catalogPresetSource("obsolete", []model.Selector{
		{Kind: model.SelectorDomain, Value: "old.example.com"},
	})
	catalog, paths, _ := newPresetCatalogFixture(t, map[string][]byte{
		"telegram.yaml": telegramSource,
		"openai.yaml":   openAISource,
	}, []model.Preset{
		catalogEffectivePreset("telegram", telegramSource, []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "telegram.org"}}),
		catalogEffectivePreset("obsolete", obsoleteSource, []model.Selector{{Kind: model.SelectorDomain, Value: "old.example.com"}}),
	}, false)

	validation, err := catalog.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !validation.Valid || validation.SourceCount != 2 || len(validation.Issues) != 0 {
		t.Fatalf("Validate() = %#v, want valid two-source set", validation)
	}

	list, err := catalog.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got, want := catalogSummaryNames(list.Items), []string{"obsolete", "openai", "telegram"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("List() names = %v, want %v", got, want)
	}
	telegramSummary := findPresetSummary(t, list.Items, "telegram")
	if !telegramSummary.SourcePresent || !telegramSummary.SourceValid || !telegramSummary.EffectivePresent || telegramSummary.SourceChanged || telegramSummary.SelectorChanged {
		t.Fatalf("telegram summary = %#v, want unchanged source and effective views", telegramSummary)
	}
	openAISummary := findPresetSummary(t, list.Items, "openai")
	if !openAISummary.SourcePresent || openAISummary.EffectivePresent || !openAISummary.SourceChanged || !openAISummary.SelectorChanged {
		t.Fatalf("openai summary = %#v, want pending source-only preset", openAISummary)
	}
	obsoleteSummary := findPresetSummary(t, list.Items, "obsolete")
	if obsoleteSummary.SourcePresent || !obsoleteSummary.EffectivePresent || !obsoleteSummary.SourceChanged || !obsoleteSummary.SelectorChanged {
		t.Fatalf("obsolete summary = %#v, want pending effective-only deletion", obsoleteSummary)
	}

	shown, err := catalog.Show("TELEGRAM")
	if err != nil {
		t.Fatalf("Show() error = %v", err)
	}
	if shown.StateGeneration != 1 || shown.Source == nil || shown.Effective == nil || shown.Source.Name != "telegram" ||
		shown.Source.Path != filepath.Join(paths.PresetsDir, "telegram.yaml") || shown.Effective.Generation != 1 {
		t.Fatalf("Show() = %#v, want source and effective telegram generation", shown)
	}
	if len(shown.Assignments) != 0 || len(shown.Issues) != 0 {
		t.Fatalf("Show() metadata = %#v, want empty arrays", shown)
	}

	diff, err := catalog.Diff()
	if err != nil {
		t.Fatalf("Diff() error = %v", err)
	}
	if !diff.Valid || len(diff.Issues) != 0 {
		t.Fatalf("Diff() = %#v, want valid diff", diff)
	}
	if got, want := catalogChangeKinds(diff.Changes), []string{"obsolete:deleted", "openai:added"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Diff() changes = %v, want %v", got, want)
	}

	changedTelegram := catalogPresetSource("telegram", []model.Selector{
		{Kind: model.SelectorDomainSuffix, Value: "telegram.org"},
		{Kind: model.SelectorDomainSuffix, Value: "t.me"},
	})
	writeCatalogPreset(t, paths, "telegram.yaml", changedTelegram)
	diff, err = catalog.Diff()
	if err != nil {
		t.Fatalf("Diff() after semantic edit error = %v", err)
	}
	telegramChange := findPresetChange(t, diff.Changes, "telegram")
	if telegramChange.Kind != PresetModified || !telegramChange.SourceChanged || !telegramChange.SelectorChanged ||
		!reflect.DeepEqual(telegramChange.AddedSelectors, []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "t.me"}}) || len(telegramChange.RemovedSelectors) != 0 {
		t.Fatalf("telegram semantic change = %#v", telegramChange)
	}

	commentOnly := append([]byte("# operator note\n"), telegramSource...)
	writeCatalogPreset(t, paths, "telegram.yaml", commentOnly)
	diff, err = catalog.Diff()
	if err != nil {
		t.Fatalf("Diff() after source-only edit error = %v", err)
	}
	telegramChange = findPresetChange(t, diff.Changes, "telegram")
	if telegramChange.Kind != PresetModified || !telegramChange.SourceChanged || telegramChange.SelectorChanged || len(telegramChange.AddedSelectors) != 0 || len(telegramChange.RemovedSelectors) != 0 {
		t.Fatalf("telegram source-only change = %#v", telegramChange)
	}

	if check, err := catalog.CheckDelete("openai"); err != nil || !check.Allowed || len(check.Assignments) != 0 {
		t.Fatalf("CheckDelete(unassigned source) = %#v, %v", check, err)
	}
	if check, err := catalog.CheckDelete("obsolete"); err != nil || !check.Allowed || len(check.Assignments) != 0 {
		t.Fatalf("CheckDelete(unassigned effective preset) = %#v, %v", check, err)
	}
	if _, err := catalog.CheckDelete("missing"); !errors.Is(err, ErrPresetNotFound) {
		t.Fatalf("CheckDelete(missing) error = %v, want ErrPresetNotFound", err)
	}
}

func TestPresetCatalogInvalidManualEditLeavesPriorEffectiveGenerationActive(t *testing.T) {
	t.Parallel()

	telegramSource := catalogPresetSource("telegram", []model.Selector{
		{Kind: model.SelectorDomainSuffix, Value: "telegram.org"},
	})
	catalog, paths, stateStore := newPresetCatalogFixture(t, map[string][]byte{
		"telegram.yaml": telegramSource,
	}, []model.Preset{
		catalogEffectivePreset("telegram", telegramSource, []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "telegram.org"}}),
	}, true)
	stateBefore, err := stateStore.Load()
	if err != nil {
		t.Fatalf("Load() before edit error = %v", err)
	}
	stateBytesBefore, err := os.ReadFile(paths.StateFile)
	if err != nil {
		t.Fatalf("ReadFile(state) before edit error = %v", err)
	}

	invalidSource := []byte("schema_version: 1\nname: telegram\ninclude:\n  - type: domain-suffix\n    value: telegram.org\nexclude: []\naction: direct\n")
	writeCatalogPreset(t, paths, "telegram.yaml", invalidSource)
	validation, err := catalog.Validate()
	if err != nil {
		t.Fatalf("Validate() after invalid edit error = %v", err)
	}
	if validation.Valid || !hasPresetIssue(validation.Issues, "invalid_preset_document") || !hasPresetIssue(validation.Issues, "assigned_preset_invalid") {
		t.Fatalf("Validate() = %#v, want invalid document and assigned-invalid issues", validation)
	}
	diff, err := catalog.Diff()
	if err != nil {
		t.Fatalf("Diff() after invalid edit error = %v", err)
	}
	if diff.Valid || len(diff.Changes) != 0 || !hasPresetIssue(diff.Issues, "assigned_preset_invalid") {
		t.Fatalf("Diff() = %#v, want rejected whole-set candidate", diff)
	}
	shown, err := catalog.Show("telegram")
	if err != nil {
		t.Fatalf("Show() after invalid edit error = %v", err)
	}
	if shown.Source == nil || shown.Source.Valid || shown.Effective == nil || shown.Effective.Generation != 1 || !hasPresetIssue(shown.Issues, "assigned_preset_invalid") {
		t.Fatalf("Show() = %#v, want invalid source beside effective generation 1", shown)
	}
	check, err := catalog.CheckDelete("telegram")
	if !errors.Is(err, ErrPresetAssigned) || check.Allowed || len(check.Assignments) != 1 || check.Assignments[0].TargetID != catalogClientID {
		t.Fatalf("CheckDelete(assigned invalid source) = %#v, %v", check, err)
	}
	assertCatalogStateUnchanged(t, stateStore, paths, stateBefore, stateBytesBefore)

	if err := os.Remove(filepath.Join(paths.PresetsDir, "telegram.yaml")); err != nil {
		t.Fatalf("remove manually deleted preset fixture: %v", err)
	}
	validation, err = catalog.Validate()
	if err != nil {
		t.Fatalf("Validate() after manual deletion error = %v", err)
	}
	if validation.Valid || !hasPresetIssue(validation.Issues, "assigned_preset_missing") {
		t.Fatalf("Validate() = %#v, want assigned-preset deletion guard", validation)
	}
	check, err = catalog.CheckDelete("telegram")
	if !errors.Is(err, ErrPresetAssigned) || check.Allowed || len(check.Assignments) != 1 {
		t.Fatalf("CheckDelete(assigned deleted source) = %#v, %v", check, err)
	}
	assertCatalogStateUnchanged(t, stateStore, paths, stateBefore, stateBytesBefore)
}

func TestPresetCatalogWholeSetValidationRejectsMismatchAndSymlink(t *testing.T) {
	t.Parallel()

	catalog, paths, _ := newPresetCatalogFixture(t, nil, nil, false)
	writeCatalogPreset(t, paths, "telegram.yaml", catalogPresetSource("other", []model.Selector{
		{Kind: model.SelectorDomain, Value: "example.com"},
	}))
	target := filepath.Join(paths.PresetsDir, "target.txt")
	if err := os.WriteFile(target, catalogPresetSource("linked", []model.Selector{{Kind: model.SelectorDomain, Value: "linked.example.com"}}), 0o644); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(paths.PresetsDir, "linked.yaml")); err != nil {
		t.Fatalf("create source symlink: %v", err)
	}

	validation, err := catalog.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if validation.Valid || validation.SourceCount != 2 || !hasPresetIssue(validation.Issues, "preset_name_mismatch") || !hasPresetIssue(validation.Issues, "unsafe_preset_source") {
		t.Fatalf("Validate() = %#v, want whole-set mismatch and symlink rejection", validation)
	}
	if diff, err := catalog.Diff(); err != nil || diff.Valid || len(diff.Changes) != 0 {
		t.Fatalf("Diff() = %#v, %v, want no plan for invalid whole set", diff, err)
	}
}

func newPresetCatalogFixture(t *testing.T, sources map[string][]byte, presets []model.Preset, assigned bool) (*PresetCatalog, store.Paths, *store.StateStore) {
	t.Helper()

	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatalf("NewPaths() error = %v", err)
	}
	if err := os.MkdirAll(paths.PresetsDir, 0o755); err != nil {
		t.Fatalf("create preset directory: %v", err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatalf("create state directory: %v", err)
	}
	filenames := make([]string, 0, len(sources))
	for filename := range sources {
		filenames = append(filenames, filename)
	}
	sort.Strings(filenames)
	for _, filename := range filenames {
		writeCatalogPreset(t, paths, filename, sources[filename])
	}
	state := catalogGatewayState(presets, assigned)
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		t.Fatalf("NewStateStore() error = %v", err)
	}
	if err := stateStore.Save(0, state); err != nil {
		t.Fatalf("Save(initial state) error = %v", err)
	}
	catalog, err := NewPresetCatalog(paths, stateStore)
	if err != nil {
		t.Fatalf("NewPresetCatalog() error = %v", err)
	}
	return catalog, paths, stateStore
}

func catalogGatewayState(presets []model.Preset, assigned bool) model.State {
	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	state := model.State{
		SchemaVersion: model.StateSchemaVersion,
		Generation:    1,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Role: model.RoleGateway,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: now,
			PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", SSHPort: 22, ClientCIDR: "10.44.0.0/24", NodeCIDR: "10.45.0.0/24",
		},
		HandshakeHost: &model.HandshakeHost{
			SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: "microsoft",
			Hostname: "www.microsoft.com", SelectedAt: now,
		},
		Nodes: []model.Node{}, Clients: []model.Client{}, Presets: append(make([]model.Preset, 0, len(presets)), presets...), Policies: []model.Policy{},
		Transports: []model.Transport{}, Exposes: []model.Expose{}, Certificates: []model.Certificate{}, Operations: []model.Operation{},
		Logging: []model.LoggingSession{}, Backups: []model.Backup{},
		Components: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2.0.0-dev",
			ControlProtocols: []string{"1.0"}, StateSchemaMinimum: model.StateSchemaVersion, StateSchemaMaximum: model.StateSchemaVersion,
			TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1, MigrationReversible: true,
			Components: []model.ComponentPin{{Name: "vpnctl", Version: "v2.0.0-dev", Source: "bundle:vpnctl", Bundled: true, SHA256: strings.Repeat("a", 64), Capabilities: []string{"cli", "controller"}}},
		},
	}
	if !assigned {
		return state
	}
	state.Clients = []model.Client{{
		SchemaVersion: model.ResourceSchemaVersion, ID: catalogClientID, Name: "phone", Platform: "ios", Lifecycle: model.LifecycleActive,
		OverlayIPv4: "10.44.0.2", CredentialGeneration: 1, AssignedPresets: []string{"telegram"}, ActiveTransport: model.TransportStandard, CreatedAt: now,
	}}
	selectors := append([]model.Selector(nil), presets[0].Selectors...)
	state.Policies = []model.Policy{{
		SchemaVersion: model.ResourceSchemaVersion, TargetKind: model.TargetClient, TargetID: catalogClientID, PresetNames: []string{"telegram"},
		Selectors: selectors, EffectiveHash: strings.Repeat("b", 64), Generation: 1,
	}}
	state.Transports = []model.Transport{
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetClient, OwnerID: catalogClientID, Kind: model.TransportStandard,
			State: model.TransportActive, Provider: "wireguard", Protocol: model.ProtocolUDP, Port: 51820, CredentialGeneration: 1,
			CredentialRef: "client:standard", PublicKey: "catalog-test-public-key", ConfigHash: strings.Repeat("c", 64),
		},
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetClient, OwnerID: catalogClientID, Kind: model.TransportRestricted,
			State: model.TransportStandby, Provider: "mihomo", Protocol: model.ProtocolTCP, Port: 8443, CredentialGeneration: 1,
			CredentialRef: "client:restricted", HandshakeHost: "www.microsoft.com", ConfigHash: strings.Repeat("d", 64),
		},
	}
	return state
}

func catalogEffectivePreset(name string, source []byte, selectors []model.Selector) model.Preset {
	digest := sha256.Sum256(source)
	return model.Preset{
		SchemaVersion: model.ResourceSchemaVersion, Name: name, SourceHash: hex.EncodeToString(digest[:]), EffectiveHash: strings.Repeat("e", 64),
		Selectors: append([]model.Selector(nil), selectors...), Generation: 1, AppliedAt: time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC),
	}
}

func catalogPresetSource(name string, selectors []model.Selector) []byte {
	var source strings.Builder
	source.WriteString("schema_version: 1\nname: ")
	source.WriteString(name)
	source.WriteString("\ninclude:\n")
	for _, selector := range selectors {
		if selector.Exclude {
			continue
		}
		source.WriteString("  - type: ")
		source.WriteString(string(selector.Kind))
		source.WriteString("\n    value: ")
		source.WriteString(selector.Value)
		source.WriteByte('\n')
	}
	source.WriteString("exclude:")
	hasExclude := false
	for _, selector := range selectors {
		if !selector.Exclude {
			continue
		}
		if !hasExclude {
			source.WriteByte('\n')
			hasExclude = true
		}
		source.WriteString("  - type: ")
		source.WriteString(string(selector.Kind))
		source.WriteString("\n    value: ")
		source.WriteString(selector.Value)
		source.WriteByte('\n')
	}
	if !hasExclude {
		source.WriteString(" []\n")
	}
	return []byte(source.String())
}

func writeCatalogPreset(t *testing.T, paths store.Paths, filename string, source []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(paths.PresetsDir, filename), source, 0o644); err != nil {
		t.Fatalf("write preset %s: %v", filename, err)
	}
}

func catalogSummaryNames(items []PresetSummary) []string {
	result := make([]string, len(items))
	for index, item := range items {
		result[index] = item.Name
	}
	return result
}

func catalogChangeKinds(changes []PresetChange) []string {
	result := make([]string, len(changes))
	for index, change := range changes {
		result[index] = change.Name + ":" + string(change.Kind)
	}
	return result
}

func findPresetSummary(t *testing.T, items []PresetSummary, name string) PresetSummary {
	t.Helper()
	for _, item := range items {
		if item.Name == name {
			return item
		}
	}
	t.Fatalf("preset summary %q not found in %#v", name, items)
	return PresetSummary{}
}

func findPresetChange(t *testing.T, changes []PresetChange, name string) PresetChange {
	t.Helper()
	for _, change := range changes {
		if change.Name == name {
			return change
		}
	}
	t.Fatalf("preset change %q not found in %#v", name, changes)
	return PresetChange{}
}

func hasPresetIssue(issues []PresetIssue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func assertCatalogStateUnchanged(t *testing.T, stateStore *store.StateStore, paths store.Paths, wantState model.State, wantBytes []byte) {
	t.Helper()
	gotState, err := stateStore.Load()
	if err != nil {
		t.Fatalf("Load() after catalog inspection error = %v", err)
	}
	if !reflect.DeepEqual(gotState, wantState) {
		t.Fatalf("authoritative state changed\nwant: %#v\n got: %#v", wantState, gotState)
	}
	gotBytes, err := os.ReadFile(paths.StateFile)
	if err != nil {
		t.Fatalf("ReadFile(state) after catalog inspection error = %v", err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Fatal("authoritative state bytes changed during read-only preset inspection")
	}
}
