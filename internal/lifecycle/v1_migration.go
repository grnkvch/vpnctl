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
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	V1MigrationSchemaVersion       = 1
	v1MigrationJournalName         = "operation.json"
	v1MigrationStageName           = "v2-stage"
	v1MigrationSnapshotName        = "maintenance-snapshot"
	v1MigrationMaximumJournalBytes = 2 << 20
)

var (
	ErrV1MigrationBlocked    = errors.New("v1 migration is blocked")
	ErrV1MigrationConflict   = errors.New("v1 migration operation conflicts with its inputs")
	ErrV1MigrationRolledBack = errors.New("v1 migration network activation was rolled back")
)

type V1MigrationPhase string

const (
	V1MigrationBundleVerified   V1MigrationPhase = "signed_bundle_verified"
	V1MigrationSnapshotCreated  V1MigrationPhase = "maintenance_snapshot_created"
	V1MigrationConversionStaged V1MigrationPhase = "converted_state_staged"
	V1MigrationRoleSetup        V1MigrationPhase = "gateway_role_setup"
	V1MigrationNetworkActivated V1MigrationPhase = "network_activated"
	V1MigrationNetworkConfirmed V1MigrationPhase = "network_confirmed"
	V1MigrationUFWTranslated    V1MigrationPhase = "known_ufw_translated"
	V1MigrationClientsValidated V1MigrationPhase = "clients_validated"
)

var v1MigrationPhaseOrder = []V1MigrationPhase{
	V1MigrationBundleVerified,
	V1MigrationSnapshotCreated,
	V1MigrationConversionStaged,
	V1MigrationRoleSetup,
	V1MigrationNetworkActivated,
	V1MigrationNetworkConfirmed,
	V1MigrationUFWTranslated,
	V1MigrationClientsValidated,
}

type V1MigrationNetworkStatus string

const (
	V1MigrationNetworkPending    V1MigrationNetworkStatus = "pending"
	V1MigrationNetworkCommitted  V1MigrationNetworkStatus = "committed"
	V1MigrationNetworkRolledBack V1MigrationNetworkStatus = "rolled_back"
)

type V1MigrationInput struct {
	BundlePath      string
	MaintenanceRoot string
	PublicIPv4      string
	NodeCIDR        string
	SSHPort         int
	SSHConnection   string
	DryRun          bool
}

type V1MaintenanceSnapshot struct {
	SchemaVersion int      `json:"schema_version"`
	Files         int      `json:"files"`
	Bytes         int64    `json:"bytes"`
	LogicalRoots  []string `json:"logical_roots"`
	SHA256        string   `json:"sha256"`
}

type V1MigrationClientValidation struct {
	TargetClientID string `json:"target_client_id"`
	Status         string `json:"status"`
	AddressKept    bool   `json:"address_kept"`
	KeyPairKept    bool   `json:"key_pair_kept"`
	ProfileStatus  string `json:"profile_status"`
}

type V1MigrationPlan struct {
	SchemaVersion    int                     `json:"schema_version"`
	MigrationID      string                  `json:"migration_id"`
	Status           string                  `json:"status"`
	DryRun           bool                    `json:"dry_run"`
	DowntimeAccepted bool                    `json:"downtime_accepted"`
	ReleaseVersion   string                  `json:"release_version"`
	InspectionStatus V1InspectionStatus      `json:"inspection_status"`
	Impact           V1MigrationImpactReport `json:"impact"`
	Phases           []V1MigrationPhase      `json:"phases"`
	RequiresAction   []string                `json:"requires_action"`
}

type V1MigrationResult struct {
	SchemaVersion         int                           `json:"schema_version"`
	MigrationID           string                        `json:"migration_id"`
	Status                string                        `json:"status"`
	DryRun                bool                          `json:"dry_run"`
	DowntimeAccepted      bool                          `json:"downtime_accepted"`
	ReleaseVersion        string                        `json:"release_version"`
	CompletedPhases       []V1MigrationPhase            `json:"completed_phases"`
	NextPhase             V1MigrationPhase              `json:"next_phase,omitempty"`
	WatchdogTransactionID string                        `json:"watchdog_transaction_id,omitempty"`
	Snapshot              *V1MaintenanceSnapshot        `json:"snapshot,omitempty"`
	Conversion            *V1ConversionResult           `json:"conversion,omitempty"`
	Clients               []V1MigrationClientValidation `json:"clients"`
	RequiredReExports     []V1ClientReExport            `json:"required_re_exports"`
	RequiresAction        []string                      `json:"requires_action"`
}

func (result V1MigrationResult) String() string {
	data, err := json.Marshal(result)
	if err != nil {
		return "<v1-migration>"
	}
	return string(data)
}

func (result V1MigrationResult) GoString() string { return result.String() }
func (result V1MigrationResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, result.String())
}

type V1MigrationInspector interface {
	Inspect(context.Context) (V1Inspection, error)
}

// V1MigrationDriver owns the host-specific effects. Every mutating method is
// required to be idempotent for one maintenance root and input fingerprint:
// the orchestrator deliberately persists a phase only after its effect returns.
type V1MigrationDriver interface {
	VerifyBundle(context.Context, string) (ReleaseManifest, error)
	SelectHandshakeHost(context.Context, ReleaseManifest, time.Time) (model.HandshakeHost, error)
	CreateMaintenanceSnapshot(context.Context, string, *V1Inspection) (V1MaintenanceSnapshot, error)
	EnsureConvertedStage(context.Context, V1ConversionInput) (V1ConversionResult, error)
	SetupGatewayRole(context.Context, string, ReleaseManifest, *V1Inspection) error
	ActivateGatewayNetwork(context.Context, string, int, string) (string, error)
	GatewayNetworkStatus(context.Context, string) (V1MigrationNetworkStatus, error)
	TranslateKnownUFW(context.Context, *V1Inspection) error
	ValidateMigratedClients(context.Context, string, V1ConversionResult) ([]V1MigrationClientValidation, error)
}

type V1Migrator struct {
	inspector V1MigrationInspector
	driver    V1MigrationDriver
	now       func() time.Time
	hook      func(V1MigrationPhase) error
}

func NewV1Migrator(inspector V1MigrationInspector, driver V1MigrationDriver) (*V1Migrator, error) {
	if inspector == nil || driver == nil {
		return nil, fmt.Errorf("v1 migration inspector and driver are required")
	}
	return &V1Migrator{inspector: inspector, driver: driver, now: time.Now}, nil
}

type preparedV1Migration struct {
	input       V1MigrationInput
	inspection  V1Inspection
	manifest    ReleaseManifest
	handshake   model.HandshakeHost
	impact      V1MigrationImpactReport
	fingerprint string
	id          string
	convertedAt time.Time
	journal     *v1MigrationJournal
}

// Plan performs the same compatibility, bundle-signature, and target checks
// as Run while remaining read-only. In particular it never creates the
// maintenance root or a conversion stage.
func (migrator *V1Migrator) Plan(ctx context.Context, input V1MigrationInput) (V1MigrationPlan, error) {
	input.DryRun = true
	prepared, err := migrator.prepare(ctx, input)
	if err != nil {
		return V1MigrationPlan{}, err
	}
	defer prepared.inspection.Destroy()
	return prepared.plan(), nil
}

func (migrator *V1Migrator) Run(ctx context.Context, input V1MigrationInput) (V1MigrationResult, error) {
	prepared, err := migrator.prepare(ctx, input)
	if err != nil {
		return V1MigrationResult{}, err
	}
	defer prepared.inspection.Destroy()
	if input.DryRun {
		plan := prepared.plan()
		return V1MigrationResult{
			SchemaVersion: V1MigrationSchemaVersion, MigrationID: plan.MigrationID,
			Status: "planned", DryRun: true, DowntimeAccepted: true,
			ReleaseVersion: plan.ReleaseVersion, CompletedPhases: []V1MigrationPhase{},
			NextPhase: V1MigrationSnapshotCreated, Clients: []V1MigrationClientValidation{},
			RequiredReExports: cloneV1ReExports(plan.Impact.RequiredReExports),
			RequiresAction:    []string{"rerun without --dry-run during an accepted maintenance window"},
		}, nil
	}
	return migrator.apply(ctx, prepared)
}

func (migrator *V1Migrator) prepare(ctx context.Context, input V1MigrationInput) (preparedV1Migration, error) {
	if ctx == nil {
		return preparedV1Migration{}, fmt.Errorf("v1 migration context is required")
	}
	if migrator == nil || migrator.inspector == nil || migrator.driver == nil || migrator.now == nil {
		return preparedV1Migration{}, fmt.Errorf("v1 migrator is incomplete")
	}
	if err := validateV1MigrationInput(input); err != nil {
		return preparedV1Migration{}, err
	}
	inspection, err := migrator.inspector.Inspect(ctx)
	if err != nil {
		return preparedV1Migration{}, fmt.Errorf("inspect v1 installation: %w", err)
	}
	fail := func(err error) (preparedV1Migration, error) {
		inspection.Destroy()
		return preparedV1Migration{}, err
	}
	manifest, err := migrator.driver.VerifyBundle(ctx, input.BundlePath)
	if err != nil {
		return fail(fmt.Errorf("verify signed v2 release bundle: %w", err))
	}
	if err := manifest.Validate(); err != nil {
		return fail(fmt.Errorf("validate signed v2 release bundle: %w", err))
	}
	fingerprint, err := v1MigrationFingerprint(&inspection, input, manifest)
	if err != nil {
		return fail(err)
	}
	id := "mig-" + fingerprint[:16]

	var journal *v1MigrationJournal
	convertedAt := migrator.now().UTC().Truncate(time.Second)
	var handshake model.HandshakeHost
	if !input.DryRun {
		journal, err = loadV1MigrationJournal(input.MaintenanceRoot)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fail(err)
		}
		if journal != nil {
			if journal.MigrationID != id || journal.InputSHA256 != fingerprint || journal.ReleaseVersion != manifest.ComponentManifest.VPNCTLVersion {
				return fail(fmt.Errorf("%w: maintenance journal belongs to different source or target inputs", ErrV1MigrationConflict))
			}
			if err := validateV1MigrationSourceEvolution(*journal, inspection.Report.UFW); err != nil {
				return fail(err)
			}
			convertedAt = journal.StartedAt
			handshake = journal.HandshakeHost
			if handshake.ListVersion != manifest.ComponentManifest.HandshakeHostListVersion || handshake.Validate() != nil {
				return fail(fmt.Errorf("%w: retained handshake host is incompatible with the verified bundle", ErrV1MigrationConflict))
			}
		}
	}
	if journal == nil {
		handshake, err = migrator.driver.SelectHandshakeHost(ctx, manifest, convertedAt)
		if err != nil {
			return fail(fmt.Errorf("select v2 restricted handshake host: %w", err))
		}
	}
	conversion := V1ConversionInput{
		Inspection: &inspection, PublicIPv4: input.PublicIPv4, SSHPort: input.SSHPort,
		NodeCIDR: input.NodeCIDR, ConvertedAt: convertedAt,
		Components: manifest.ComponentManifest, HandshakeHost: handshake,
	}
	impact, err := InspectV1MigrationImpact(conversion)
	if err != nil {
		return fail(fmt.Errorf("inspect v1 migration impact: %w", err))
	}
	if !impact.ReadyForMigration {
		return fail(fmt.Errorf("%w: compatibility report contains a blocking impact", ErrV1MigrationBlocked))
	}
	return preparedV1Migration{
		input: input, inspection: inspection, manifest: manifest, handshake: handshake,
		impact: impact, fingerprint: fingerprint, id: id, convertedAt: convertedAt, journal: journal,
	}, nil
}

func (prepared preparedV1Migration) plan() V1MigrationPlan {
	return V1MigrationPlan{
		SchemaVersion: V1MigrationSchemaVersion, MigrationID: prepared.id, Status: "ready",
		DryRun: prepared.input.DryRun, DowntimeAccepted: true,
		ReleaseVersion: prepared.manifest.ComponentManifest.VPNCTLVersion, InspectionStatus: prepared.inspection.Report.Status,
		Impact: prepared.impact, Phases: append([]V1MigrationPhase(nil), v1MigrationPhaseOrder...),
		RequiresAction: []string{
			"schedule a maintenance window with accepted gateway downtime",
			"after network activation, reconnect over SSH and run vpnctl confirm <transaction-id>",
		},
	}
}

func (migrator *V1Migrator) apply(ctx context.Context, prepared preparedV1Migration) (V1MigrationResult, error) {
	journal := prepared.journal
	if journal == nil {
		journal = &v1MigrationJournal{
			SchemaVersion: V1MigrationSchemaVersion, MigrationID: prepared.id,
			InputSHA256: prepared.fingerprint, ReleaseVersion: prepared.manifest.ComponentManifest.VPNCTLVersion,
			StartedAt: prepared.convertedAt, HandshakeHost: prepared.handshake,
			SourceUFW:        cloneV1UFWReport(prepared.inspection.Report.UFW),
			CompletedPhases:  []V1MigrationPhase{V1MigrationBundleVerified},
			ClientValidation: []V1MigrationClientValidation{},
		}
		if err := createV1MigrationRoot(prepared.input.MaintenanceRoot); err != nil {
			return V1MigrationResult{}, err
		}
		if err := writeV1MigrationJournal(prepared.input.MaintenanceRoot, *journal); err != nil {
			return V1MigrationResult{}, err
		}
	}
	if err := validateV1MigrationJournal(*journal); err != nil {
		return V1MigrationResult{}, err
	}

	runPhase := func(phase V1MigrationPhase, effect func() error) error {
		if v1MigrationPhaseDone(journal.CompletedPhases, phase) {
			return nil
		}
		if err := effect(); err != nil {
			return err
		}
		if migrator.hook != nil {
			if err := migrator.hook(phase); err != nil {
				return err
			}
		}
		journal.CompletedPhases = append(journal.CompletedPhases, phase)
		return writeV1MigrationJournal(prepared.input.MaintenanceRoot, *journal)
	}

	snapshotRoot := filepath.Join(prepared.input.MaintenanceRoot, v1MigrationSnapshotName)
	if err := runPhase(V1MigrationSnapshotCreated, func() error {
		snapshot, err := migrator.driver.CreateMaintenanceSnapshot(ctx, snapshotRoot, &prepared.inspection)
		if err == nil {
			err = validateV1MaintenanceSnapshot(snapshot)
		}
		if err == nil {
			journal.Snapshot = &snapshot
		}
		return err
	}); err != nil {
		return v1MigrationResultFromJournal(*journal, prepared.impact, "failed"), fmt.Errorf("create v1 maintenance snapshot: %w", err)
	}

	stageRoot := filepath.Join(prepared.input.MaintenanceRoot, v1MigrationStageName)
	if err := runPhase(V1MigrationConversionStaged, func() error {
		result, err := migrator.driver.EnsureConvertedStage(ctx, V1ConversionInput{
			Inspection: &prepared.inspection, StageRoot: stageRoot,
			PublicIPv4: prepared.input.PublicIPv4, SSHPort: prepared.input.SSHPort,
			NodeCIDR: prepared.input.NodeCIDR, ConvertedAt: journal.StartedAt,
			Components: prepared.manifest.ComponentManifest, HandshakeHost: journal.HandshakeHost,
		})
		if err == nil {
			journal.Conversion = &result
		}
		return err
	}); err != nil {
		return v1MigrationResultFromJournal(*journal, prepared.impact, "failed"), fmt.Errorf("stage converted v2 state: %w", err)
	}
	if journal.Conversion == nil {
		return v1MigrationResultFromJournal(*journal, prepared.impact, "failed"), fmt.Errorf("%w: conversion phase has no retained result", ErrV1MigrationConflict)
	}

	if err := runPhase(V1MigrationRoleSetup, func() error {
		return migrator.driver.SetupGatewayRole(ctx, stageRoot, prepared.manifest, &prepared.inspection)
	}); err != nil {
		return v1MigrationResultFromJournal(*journal, prepared.impact, "failed"), fmt.Errorf("set up migrated gateway role: %w", err)
	}

	if !v1MigrationPhaseDone(journal.CompletedPhases, V1MigrationNetworkActivated) {
		transactionID, err := migrator.driver.ActivateGatewayNetwork(ctx, stageRoot, prepared.input.SSHPort, prepared.input.SSHConnection)
		if err != nil {
			return v1MigrationResultFromJournal(*journal, prepared.impact, "failed"), fmt.Errorf("activate migrated gateway network: %w", err)
		}
		journal.WatchdogTransactionID = transactionID
		if migrator.hook != nil {
			if err := migrator.hook(V1MigrationNetworkActivated); err != nil {
				return v1MigrationResultFromJournal(*journal, prepared.impact, "interrupted"), err
			}
		}
		journal.CompletedPhases = append(journal.CompletedPhases, V1MigrationNetworkActivated)
		if err := writeV1MigrationJournal(prepared.input.MaintenanceRoot, *journal); err != nil {
			return v1MigrationResultFromJournal(*journal, prepared.impact, "interrupted"), err
		}
	}

	if !v1MigrationPhaseDone(journal.CompletedPhases, V1MigrationNetworkConfirmed) {
		status, err := migrator.driver.GatewayNetworkStatus(ctx, journal.WatchdogTransactionID)
		if err != nil {
			return v1MigrationResultFromJournal(*journal, prepared.impact, "failed"), err
		}
		switch status {
		case V1MigrationNetworkPending:
			result := v1MigrationResultFromJournal(*journal, prepared.impact, "awaiting_network_confirmation")
			result.RequiresAction = append(result.RequiresAction, "open a new SSH session and run vpnctl confirm "+journal.WatchdogTransactionID+", then rerun this migration command")
			return result, nil
		case V1MigrationNetworkRolledBack:
			return v1MigrationResultFromJournal(*journal, prepared.impact, "network_rolled_back"), ErrV1MigrationRolledBack
		case V1MigrationNetworkCommitted:
			if err := runPhase(V1MigrationNetworkConfirmed, func() error { return nil }); err != nil {
				return v1MigrationResultFromJournal(*journal, prepared.impact, "interrupted"), err
			}
		default:
			return v1MigrationResultFromJournal(*journal, prepared.impact, "failed"), fmt.Errorf("invalid migration network status %q", status)
		}
	}

	if err := runPhase(V1MigrationUFWTranslated, func() error {
		return migrator.driver.TranslateKnownUFW(ctx, &prepared.inspection)
	}); err != nil {
		return v1MigrationResultFromJournal(*journal, prepared.impact, "failed"), fmt.Errorf("translate known v1 UFW ownership: %w", err)
	}

	if err := runPhase(V1MigrationClientsValidated, func() error {
		clients, err := migrator.driver.ValidateMigratedClients(ctx, stageRoot, *journal.Conversion)
		if err == nil {
			err = validateV1MigrationClients(clients, *journal.Conversion)
		}
		if err == nil {
			journal.ClientValidation = append([]V1MigrationClientValidation{}, clients...)
		}
		return err
	}); err != nil {
		return v1MigrationResultFromJournal(*journal, prepared.impact, "failed"), fmt.Errorf("validate migrated clients: %w", err)
	}
	return v1MigrationResultFromJournal(*journal, prepared.impact, "complete"), nil
}

type v1MigrationJournal struct {
	SchemaVersion         int                           `json:"schema_version"`
	MigrationID           string                        `json:"migration_id"`
	InputSHA256           string                        `json:"input_sha256"`
	ReleaseVersion        string                        `json:"release_version"`
	StartedAt             time.Time                     `json:"started_at"`
	HandshakeHost         model.HandshakeHost           `json:"handshake_host"`
	SourceUFW             V1UFWReport                   `json:"source_ufw"`
	CompletedPhases       []V1MigrationPhase            `json:"completed_phases"`
	WatchdogTransactionID string                        `json:"watchdog_transaction_id,omitempty"`
	Snapshot              *V1MaintenanceSnapshot        `json:"snapshot,omitempty"`
	Conversion            *V1ConversionResult           `json:"conversion,omitempty"`
	ClientValidation      []V1MigrationClientValidation `json:"client_validation"`
}

func validateV1MigrationInput(input V1MigrationInput) error {
	for label, value := range map[string]string{"bundle path": input.BundlePath, "maintenance root": input.MaintenanceRoot} {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == string(filepath.Separator) {
			return fmt.Errorf("v1 migration %s must be a clean absolute non-root path", label)
		}
	}
	if err := validateV1ConversionPublicIPv4(input.PublicIPv4); err != nil {
		return err
	}
	if input.SSHPort < 1 || input.SSHPort > 65535 {
		return fmt.Errorf("v1 migration SSH port must be between 1 and 65535")
	}
	if input.NodeCIDR == "" {
		input.NodeCIDR = model.DefaultNodeCIDR
	}
	return nil
}

func v1MigrationFingerprint(inspection *V1Inspection, input V1MigrationInput, manifest ReleaseManifest) (string, error) {
	if inspection == nil || inspection.destroyed {
		return "", fmt.Errorf("v1 migration fingerprint requires an inspection")
	}
	hash := sha256.New()
	write := func(label string, value []byte) {
		_, _ = fmt.Fprintf(hash, "%d:%s:%d:", len(label), label, len(value))
		_, _ = hash.Write(value)
	}
	reportForFingerprint := inspection.Report
	reportForFingerprint.UFW = cloneV1UFWReport(inspection.Report.UFW)
	reportForFingerprint.UFW.Enabled = nil
	report, err := json.Marshal(reportForFingerprint)
	if err != nil {
		return "", err
	}
	write("inspection", report)
	state, err := json.Marshal(inspection.state)
	if err != nil {
		return "", err
	}
	write("state", state)
	for _, name := range sortedStringKeys(inspection.rulesets) {
		value, err := json.Marshal(inspection.rulesets[name])
		if err != nil {
			return "", err
		}
		write("ruleset:"+name, value)
	}
	for _, name := range sortedStringKeys(inspection.privateKeys) {
		write("key:"+name, inspection.privateKeys[name])
	}
	for _, name := range sortedStringKeys(inspection.generated) {
		write("generated:"+name, inspection.generated[name])
	}
	write("wireguard", inspection.systemWireGuard)
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	write("manifest", manifestBytes)
	write("public-ip", []byte(input.PublicIPv4))
	write("node-cidr", []byte(defaultV1MigrationNodeCIDR(input.NodeCIDR)))
	write("ssh-port", []byte(fmt.Sprintf("%d", input.SSHPort)))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func defaultV1MigrationNodeCIDR(value string) string {
	if value == "" {
		return model.DefaultNodeCIDR
	}
	return value
}

func createV1MigrationRoot(root string) error {
	parent := filepath.Dir(root)
	info, err := os.Lstat(parent)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("v1 migration maintenance parent must be a real directory")
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return fmt.Errorf("v1 migration maintenance parent must not traverse symlinks")
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("create v1 migration maintenance root: %w", err)
		}
		entries, readErr := os.ReadDir(root)
		metadata, statErr := os.Lstat(root)
		if readErr != nil || statErr != nil || metadata.Mode()&os.ModeSymlink != 0 || !metadata.IsDir() || metadata.Mode().Perm() != 0o700 || len(entries) != 0 {
			return fmt.Errorf("%w: existing maintenance root has no valid journal", ErrV1MigrationConflict)
		}
		return nil
	}
	return syncLifecycleDirectory(parent)
}

func loadV1MigrationJournal(root string) (*v1MigrationJournal, error) {
	path := filepath.Join(root, v1MigrationJournalName)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if rootInfo, rootErr := os.Lstat(root); rootErr == nil {
			if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o700 {
				return nil, fmt.Errorf("%w: maintenance root is unsafe", ErrV1MigrationConflict)
			}
		} else if !errors.Is(rootErr, fs.ErrNotExist) {
			return nil, rootErr
		}
		return nil, fs.ErrNotExist
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > v1MigrationMaximumJournalBytes {
		return nil, fmt.Errorf("%w: migration journal is unsafe", ErrV1MigrationConflict)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var journal v1MigrationJournal
	if err := decoder.Decode(&journal); err != nil {
		return nil, fmt.Errorf("%w: decode migration journal", ErrV1MigrationConflict)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("%w: migration journal has trailing data", ErrV1MigrationConflict)
	}
	if err := validateV1MigrationJournal(journal); err != nil {
		return nil, err
	}
	return &journal, nil
}

func writeV1MigrationJournal(root string, journal v1MigrationJournal) error {
	if err := validateV1MigrationJournal(journal); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > v1MigrationMaximumJournalBytes {
		return fmt.Errorf("v1 migration journal exceeds %d bytes", v1MigrationMaximumJournalBytes)
	}
	path := filepath.Join(root, v1MigrationJournalName)
	temporary, err := os.CreateTemp(root, ".operation-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	keep = true
	return syncLifecycleDirectory(root)
}

func validateV1MigrationJournal(journal v1MigrationJournal) error {
	if journal.SchemaVersion != V1MigrationSchemaVersion || !strings.HasPrefix(journal.MigrationID, "mig-") || len(journal.MigrationID) != 20 ||
		len(journal.InputSHA256) != sha256.Size*2 || journal.ReleaseVersion == "" || journal.StartedAt.IsZero() || journal.StartedAt.Location() != time.UTC ||
		journal.CompletedPhases == nil || journal.ClientValidation == nil || journal.HandshakeHost.Validate() != nil {
		return fmt.Errorf("%w: migration journal metadata is invalid", ErrV1MigrationConflict)
	}
	if journal.SourceUFW.Enabled == nil || !journal.SourceUFW.ConfigPresent {
		return fmt.Errorf("%w: migration journal lacks the original UFW state", ErrV1MigrationConflict)
	}
	positions := make(map[V1MigrationPhase]int, len(v1MigrationPhaseOrder))
	for index, phase := range v1MigrationPhaseOrder {
		positions[phase] = index
	}
	previous := -1
	for _, phase := range journal.CompletedPhases {
		position, ok := positions[phase]
		if !ok || position <= previous {
			return fmt.Errorf("%w: migration journal phases are invalid", ErrV1MigrationConflict)
		}
		previous = position
	}
	if v1MigrationPhaseDone(journal.CompletedPhases, V1MigrationNetworkActivated) && journal.WatchdogTransactionID == "" {
		return fmt.Errorf("%w: activated migration has no watchdog transaction", ErrV1MigrationConflict)
	}
	if v1MigrationPhaseDone(journal.CompletedPhases, V1MigrationConversionStaged) && journal.Conversion == nil {
		return fmt.Errorf("%w: staged migration has no conversion result", ErrV1MigrationConflict)
	}
	return nil
}

func validateV1MigrationSourceEvolution(journal v1MigrationJournal, current V1UFWReport) error {
	if current.Enabled == nil || current.ConfigPresent != journal.SourceUFW.ConfigPresent || !reflect.DeepEqual(current.Rules, journal.SourceUFW.Rules) {
		return fmt.Errorf("%w: v1 UFW source changed after migration started", ErrV1MigrationConflict)
	}
	originalEnabled := *journal.SourceUFW.Enabled
	currentEnabled := *current.Enabled
	if currentEnabled == originalEnabled {
		return nil
	}
	if originalEnabled && !currentEnabled && v1MigrationPhaseDone(journal.CompletedPhases, V1MigrationNetworkConfirmed) {
		return nil
	}
	return fmt.Errorf("%w: v1 UFW enabled state changed outside its safe migration phase", ErrV1MigrationConflict)
}

func cloneV1UFWReport(source V1UFWReport) V1UFWReport {
	result := V1UFWReport{ConfigPresent: source.ConfigPresent, Rules: append([]V1UFWRule(nil), source.Rules...)}
	if source.Enabled != nil {
		enabled := *source.Enabled
		result.Enabled = &enabled
	}
	return result
}

func validateV1MaintenanceSnapshot(snapshot V1MaintenanceSnapshot) error {
	if snapshot.SchemaVersion != V1MigrationSchemaVersion || snapshot.Files <= 0 || snapshot.Bytes < 0 ||
		len(snapshot.SHA256) != sha256.Size*2 || !reflectStringSlices(snapshot.LogicalRoots, []string{"v1-system", "v1-workspace"}) {
		return fmt.Errorf("maintenance snapshot result is invalid")
	}
	if _, err := hex.DecodeString(snapshot.SHA256); err != nil {
		return fmt.Errorf("maintenance snapshot digest is invalid")
	}
	return nil
}

func validateV1MigrationClients(clients []V1MigrationClientValidation, conversion V1ConversionResult) error {
	if clients == nil || len(clients) != len(conversion.Clients) {
		return fmt.Errorf("migrated client validation result is incomplete")
	}
	want := make(map[string]struct{}, len(conversion.Clients))
	for _, client := range conversion.Clients {
		want[client.TargetID] = struct{}{}
	}
	for _, client := range clients {
		if _, found := want[client.TargetClientID]; !found || client.Status != "valid" || !client.AddressKept || !client.KeyPairKept ||
			(client.ProfileStatus != "preserved" && client.ProfileStatus != "not_present") {
			return fmt.Errorf("migrated client validation result is invalid")
		}
		delete(want, client.TargetClientID)
	}
	if len(want) != 0 {
		return fmt.Errorf("migrated client validation result omits an identity")
	}
	return nil
}

func reflectStringSlices(left, right []string) bool {
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

func v1MigrationPhaseDone(phases []V1MigrationPhase, target V1MigrationPhase) bool {
	for _, phase := range phases {
		if phase == target {
			return true
		}
	}
	return false
}

func v1MigrationResultFromJournal(journal v1MigrationJournal, impact V1MigrationImpactReport, status string) V1MigrationResult {
	result := V1MigrationResult{
		SchemaVersion: V1MigrationSchemaVersion, MigrationID: journal.MigrationID,
		Status: status, DowntimeAccepted: true, ReleaseVersion: journal.ReleaseVersion,
		CompletedPhases:       append([]V1MigrationPhase(nil), journal.CompletedPhases...),
		WatchdogTransactionID: journal.WatchdogTransactionID,
		Snapshot:              journal.Snapshot, Conversion: journal.Conversion,
		Clients:           append([]V1MigrationClientValidation{}, journal.ClientValidation...),
		RequiredReExports: cloneV1ReExports(impact.RequiredReExports), RequiresAction: []string{},
	}
	for _, phase := range v1MigrationPhaseOrder {
		if !v1MigrationPhaseDone(journal.CompletedPhases, phase) {
			result.NextPhase = phase
			break
		}
	}
	if status == "complete" {
		for _, action := range impact.RequiredReExports {
			result.RequiresAction = append(result.RequiresAction, action.Commands...)
		}
		result.RequiresAction = append(result.RequiresAction, "keep the migration maintenance snapshot until v2 is explicitly accepted")
	}
	return result
}

func cloneV1ReExports(values []V1ClientReExport) []V1ClientReExport {
	result := make([]V1ClientReExport, len(values))
	for index, value := range values {
		result[index] = V1ClientReExport{
			SourceClientID: value.SourceClientID, TargetClientID: value.TargetClientID,
			Formats: append([]string(nil), value.Formats...), Reasons: append([]string(nil), value.Reasons...),
			Commands: append([]string(nil), value.Commands...),
		}
	}
	return result
}
