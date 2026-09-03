package routing

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/render"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	ClientExportClash     ClientExportFormat = "clash"
	ClientExportWireGuard ClientExportFormat = "wireguard"

	clientExportDirectoryMode os.FileMode = 0o700
	clientExportFileMode      os.FileMode = 0o600
	clientExportMaximumBytes              = 16 << 20
	clientExportMetadataDir               = ".metadata"
	clientExportPlanMarker                = "<redacted-client-export-plan>"
)

var (
	ErrClientExportExists    = errors.New("client export already exists")
	ErrClientExportUnsafe    = errors.New("client export path is unsafe")
	ErrClientExportUncertain = errors.New("client export outcome is uncertain")
)

type ClientExportFormat string

type ClientExportRequest struct {
	ClientReference       string
	Format                ClientExportFormat
	OutputPath            string
	Force                 bool
	GatewayPublicKey      string
	WireGuardDNSServers   []string
	ClashDNSMode          ClashDNSMode
	ClashDirectDNSServers []string
}

type ClientExportResult struct {
	ClientID              string             `json:"client_id"`
	ClientName            string             `json:"client_name"`
	Format                ClientExportFormat `json:"format"`
	OutputPath            string             `json:"output_path"`
	ManagedPath           bool               `json:"managed_path"`
	FileMode              string             `json:"file_mode"`
	SourceStateGeneration uint64             `json:"source_state_generation"`
	PolicyGeneration      uint64             `json:"policy_generation"`
	CredentialGeneration  uint64             `json:"credential_generation"`
	SCPHint               string             `json:"scp_hint"`
	metadataPath          string
}

// ClientExportPlan is a read-only, secret-free review of one export. The
// rendered profile and normalized request remain private so JSON/logging cannot
// accidentally turn --dry-run into a profile-delivery mechanism.
type ClientExportPlan struct {
	ClientID              string             `json:"client_id"`
	ClientName            string             `json:"client_name"`
	Format                ClientExportFormat `json:"format"`
	OutputPath            string             `json:"output_path"`
	ManagedPath           bool               `json:"managed_path"`
	FileMode              string             `json:"file_mode"`
	SourceStateGeneration uint64             `json:"source_state_generation"`
	PolicyGeneration      uint64             `json:"policy_generation"`
	CredentialGeneration  uint64             `json:"credential_generation"`

	request      ClientExportRequest
	rendered     renderedClientExport
	publicIPv4   string
	metadataPath string
	metadata     []byte
}

func (ClientExportPlan) String() string   { return clientExportPlanMarker }
func (ClientExportPlan) GoString() string { return clientExportPlanMarker }

// OutputResult returns an export-v1-compatible dry-run result. There is no copy
// action because the reviewed file does not exist yet.
func (plan ClientExportPlan) OutputResult() output.Result {
	public := output.NewResult("client.export", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"output_path": plan.OutputPath,
		"file_mode":   plan.FileMode,
		"generation":  plan.SourceStateGeneration,
	})
	public.ResourceIDs = map[string]string{"client_id": plan.ClientID}
	return public
}

// OutputResult returns the safe public command result. Profile bytes,
// content hashes, and the internal metadata sidecar never enter stdout.
func (result ClientExportResult) OutputResult() output.Result {
	public := output.NewResult("client.export", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"output_path": result.OutputPath,
		"file_mode":   result.FileMode,
		"generation":  result.SourceStateGeneration,
	})
	public.ResourceIDs = map[string]string{"client_id": result.ClientID}
	public.RequiresAction = []output.Action{{
		Code: "copy_client_profile", Message: "Copy the exported profile to the client device.",
		Command: result.SCPHint, ResourceIDs: map[string]string{"client_id": result.ClientID},
	}}
	return public
}

type ClientExporter struct {
	paths     store.Paths
	state     ClientStateStore
	wireguard *WireGuardProfileRenderer
	clash     *ClashProfileRenderer
}

func NewClientExporter(paths store.Paths, state ClientStateStore, credentials ClientCredentialReader) (*ClientExporter, error) {
	if state == nil || credentials == nil {
		return nil, fmt.Errorf("client exporter state and credential reader are required")
	}
	want, err := store.NewPaths(paths.Root)
	if err != nil || want != paths {
		return nil, fmt.Errorf("client exporter paths do not match the system root")
	}
	wireguardRenderer, err := NewWireGuardProfileRenderer(state, credentials)
	if err != nil {
		return nil, err
	}
	clashRenderer, err := NewClashProfileRenderer(state, credentials)
	if err != nil {
		return nil, err
	}
	return &ClientExporter{paths: paths, state: state, wireguard: wireguardRenderer, clash: clashRenderer}, nil
}

func (exporter *ClientExporter) Export(request ClientExportRequest) (ClientExportResult, error) {
	plan, err := exporter.Plan(request)
	if err != nil {
		return ClientExportResult{}, err
	}
	return exporter.Commit(plan)
}

// Plan validates and renders an export without creating directories, files, or
// authoritative state. It is the domain boundary used by --dry-run.
func (exporter *ClientExporter) Plan(request ClientExportRequest) (ClientExportPlan, error) {
	if exporter == nil {
		return ClientExportPlan{}, fmt.Errorf("client exporter is required")
	}
	if err := validateClientExportRequest(request); err != nil {
		return ClientExportPlan{}, err
	}
	rendered, err := exporter.render(request)
	if err != nil {
		return ClientExportPlan{}, err
	}
	state, err := exporter.state.Load()
	if err != nil {
		return ClientExportPlan{}, fmt.Errorf("reload client export state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return ClientExportPlan{}, fmt.Errorf("validate reloaded client export state: %w", err)
	}
	if state.Generation != rendered.stateGeneration {
		return ClientExportPlan{}, fmt.Errorf("client export state changed during rendering; retry the export")
	}
	client, err := resolveVisibleClient(state.Clients, rendered.clientID)
	if err != nil || client.Name != rendered.clientName || client.Lifecycle != model.LifecycleActive {
		return ClientExportPlan{}, fmt.Errorf("client export identity changed during rendering; retry the export")
	}

	outputPath, managed, err := exporter.outputPath(request, rendered.clientName)
	if err != nil {
		return ClientExportPlan{}, err
	}
	metadataPath := exporter.metadataPath(rendered.clientID, request.Format)
	manifest, err := buildClientExportManifest(outputPath, rendered)
	if err != nil {
		return ClientExportPlan{}, err
	}
	metadata, err := render.EncodeManifest(manifest)
	if err != nil {
		return ClientExportPlan{}, fmt.Errorf("encode client export metadata: %w", err)
	}
	if err := exporter.preflightPublication(outputPath, managed, request.Force, metadataPath); err != nil {
		return ClientExportPlan{}, err
	}
	return ClientExportPlan{
		ClientID: rendered.clientID, ClientName: rendered.clientName, Format: request.Format,
		OutputPath: outputPath, ManagedPath: managed, FileMode: "0600",
		SourceStateGeneration: rendered.stateGeneration, PolicyGeneration: rendered.policyGeneration,
		CredentialGeneration: rendered.credentialGeneration,
		request:              cloneClientExportRequest(request), rendered: rendered,
		publicIPv4: state.Host.PublicIPv4, metadataPath: metadataPath, metadata: append([]byte(nil), metadata...),
	}, nil
}

// Commit re-plans immediately before publication, refusing stale or tampered
// review data and destination drift. The actual activation remains file-only;
// export metadata is not authoritative gateway state.
func (exporter *ClientExporter) Commit(plan ClientExportPlan) (ClientExportResult, error) {
	if exporter == nil {
		return ClientExportResult{}, fmt.Errorf("client exporter is required")
	}
	fresh, err := exporter.Plan(plan.request)
	if err != nil {
		return ClientExportResult{}, err
	}
	if !sameClientExportReview(plan, fresh) {
		return ClientExportResult{}, fmt.Errorf("client export plan changed or was modified; review it again")
	}
	if err := exporter.ensureDirectories(fresh.OutputPath, fresh.ManagedPath); err != nil {
		return ClientExportResult{}, err
	}
	replaceOutput := fresh.ManagedPath || fresh.request.Force
	if err := publishClientExport(fresh.OutputPath, fresh.rendered.content, replaceOutput, fresh.metadataPath, fresh.metadata); err != nil {
		return ClientExportResult{}, err
	}
	return ClientExportResult{
		ClientID: fresh.ClientID, ClientName: fresh.ClientName, Format: fresh.Format,
		OutputPath: fresh.OutputPath, ManagedPath: fresh.ManagedPath, FileMode: fresh.FileMode,
		SourceStateGeneration: fresh.SourceStateGeneration, PolicyGeneration: fresh.PolicyGeneration,
		CredentialGeneration: fresh.CredentialGeneration,
		SCPHint:              scpClientExportHint(fresh.publicIPv4, fresh.OutputPath), metadataPath: fresh.metadataPath,
	}, nil
}

func cloneClientExportRequest(request ClientExportRequest) ClientExportRequest {
	clone := request
	clone.WireGuardDNSServers = append([]string(nil), request.WireGuardDNSServers...)
	clone.ClashDirectDNSServers = append([]string(nil), request.ClashDirectDNSServers...)
	return clone
}

func sameClientExportReview(left, right ClientExportPlan) bool {
	return left.ClientID == right.ClientID && left.ClientName == right.ClientName && left.Format == right.Format &&
		left.OutputPath == right.OutputPath && left.ManagedPath == right.ManagedPath && left.FileMode == right.FileMode &&
		left.SourceStateGeneration == right.SourceStateGeneration && left.PolicyGeneration == right.PolicyGeneration &&
		left.CredentialGeneration == right.CredentialGeneration
}

type renderedClientExport struct {
	clientID             string
	clientName           string
	stateGeneration      uint64
	policyGeneration     uint64
	credentialGeneration uint64
	content              []byte
}

func (exporter *ClientExporter) render(request ClientExportRequest) (renderedClientExport, error) {
	switch request.Format {
	case ClientExportWireGuard:
		profile, err := exporter.wireguard.Render(WireGuardProfileRequest{
			ClientReference: request.ClientReference, GatewayPublicKey: request.GatewayPublicKey,
			DNSServers: request.WireGuardDNSServers,
		})
		if err != nil {
			return renderedClientExport{}, err
		}
		return renderedClientExport{
			clientID: profile.ClientID, clientName: profile.ClientName,
			stateGeneration: profile.SourceStateGeneration, credentialGeneration: profile.CredentialGeneration,
			content: profile.Bytes(),
		}, nil
	case ClientExportClash:
		profile, err := exporter.clash.Render(ClashProfileRequest{
			ClientReference: request.ClientReference, GatewayPublicKey: request.GatewayPublicKey,
			DNSMode: request.ClashDNSMode, DirectDNSServers: request.ClashDirectDNSServers,
		})
		if err != nil {
			return renderedClientExport{}, err
		}
		return renderedClientExport{
			clientID: profile.ClientID, clientName: profile.ClientName,
			stateGeneration: profile.SourceStateGeneration, policyGeneration: profile.PolicyGeneration,
			credentialGeneration: profile.CredentialGeneration, content: profile.Bytes(),
		}, nil
	default:
		return renderedClientExport{}, fmt.Errorf("unsupported client export format %q", request.Format)
	}
}

func validateClientExportRequest(request ClientExportRequest) error {
	if strings.TrimSpace(request.ClientReference) == "" {
		return fmt.Errorf("client export requires an explicit client")
	}
	if request.Format != ClientExportClash && request.Format != ClientExportWireGuard {
		return fmt.Errorf("unsupported client export format %q", request.Format)
	}
	if strings.ContainsAny(request.OutputPath, "\x00\r\n") {
		return fmt.Errorf("client export output path must be a single filesystem path")
	}
	if request.Format == ClientExportWireGuard && (request.ClashDNSMode != "" || request.ClashDirectDNSServers != nil) {
		return fmt.Errorf("Clash DNS settings cannot be used for a WireGuard export")
	}
	if request.Format == ClientExportClash && request.WireGuardDNSServers != nil {
		return fmt.Errorf("WireGuard DNS settings cannot be used for a Clash export")
	}
	return nil
}

func (exporter *ClientExporter) outputPath(request ClientExportRequest, clientName string) (string, bool, error) {
	extension := ".clash.yaml"
	if request.Format == ClientExportWireGuard {
		extension = ".wireguard.conf"
	}
	managedPath := filepath.Join(exporter.paths.ClientExportsDir, clientName+extension)
	if request.OutputPath == "" {
		return managedPath, true, nil
	}
	absolute, err := filepath.Abs(request.OutputPath)
	if err != nil {
		return "", false, fmt.Errorf("resolve custom client export path: %w", err)
	}
	if len(absolute) > 4096 || absolute == string(filepath.Separator) || filepath.Clean(absolute) != absolute {
		return "", false, fmt.Errorf("%w: custom output path must be a clean non-root path", ErrClientExportUnsafe)
	}
	if absolute == managedPath {
		return managedPath, true, nil
	}
	resolved, err := resolveFutureExportPath(absolute)
	if err != nil {
		return "", false, err
	}
	for _, reserved := range []string{exporter.paths.ConfigDir, exporter.paths.StateDir, exporter.paths.RuntimeDir} {
		resolvedReserved, resolveErr := resolveFutureExportPath(reserved)
		if resolveErr != nil {
			return "", false, resolveErr
		}
		if exportPathWithin(resolvedReserved, resolved) {
			return "", false, fmt.Errorf("%w: custom output cannot replace vpnctl-managed files", ErrClientExportUnsafe)
		}
	}
	return absolute, false, nil
}

// resolveFutureExportPath resolves symlinks in the longest existing ancestor,
// then appends the missing suffix. It lets preflight detect an alias into a
// reserved vpnctl namespace before MkdirAll can create anything there.
func resolveFutureExportPath(value string) (string, error) {
	cursor := filepath.Clean(value)
	missing := make([]string, 0)
	for {
		_, err := os.Lstat(cursor)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect export path ancestor %s: %w", cursor, err)
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return "", fmt.Errorf("resolve export path %s: no existing ancestor", value)
		}
		missing = append(missing, filepath.Base(cursor))
		cursor = parent
	}
	resolved, err := filepath.EvalSymlinks(cursor)
	if err != nil {
		return "", fmt.Errorf("resolve export path ancestor %s: %w", cursor, err)
	}
	for index := len(missing) - 1; index >= 0; index-- {
		resolved = filepath.Join(resolved, missing[index])
	}
	return filepath.Clean(resolved), nil
}

func exportPathWithin(parent, candidate string) bool {
	relative, err := filepath.Rel(parent, candidate)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func (exporter *ClientExporter) metadataPath(clientID string, format ClientExportFormat) string {
	return filepath.Join(exporter.paths.ClientExportsDir, clientExportMetadataDir, clientID+"."+string(format)+".json")
}

func buildClientExportManifest(outputPath string, profile renderedClientExport) (render.ArtifactManifest, error) {
	policies := []render.SourceGeneration{}
	if profile.policyGeneration != 0 {
		policies = append(policies, render.SourceGeneration{
			Kind: "client-policy", ID: profile.clientID, Generation: profile.policyGeneration,
		})
	}
	manifest, err := render.BuildManifest(profile.stateGeneration, []render.ArtifactInput{{
		Path: outputPath, Mode: clientExportFileMode, Content: profile.content,
		PolicyGenerations: policies,
		CredentialGenerations: []render.SourceGeneration{{
			Kind: "client-credential", ID: profile.clientID, Generation: profile.credentialGeneration,
		}},
	}})
	if err != nil {
		return render.ArtifactManifest{}, fmt.Errorf("build client export metadata: %w", err)
	}
	return manifest, nil
}

func (exporter *ClientExporter) preflightPublication(outputPath string, managed, force bool, metadataPath string) error {
	for _, directory := range []string{
		exporter.paths.ExportsDir,
		exporter.paths.ClientExportsDir,
		filepath.Join(exporter.paths.ClientExportsDir, clientExportMetadataDir),
	} {
		if err := validateExistingExportDirectory(directory); err != nil {
			return err
		}
	}
	if !managed {
		parent := filepath.Dir(outputPath)
		info, err := os.Lstat(parent)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect custom export directory: %w", err)
		}
		if err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
			return fmt.Errorf("%w: custom output parent must be a real directory", ErrClientExportUnsafe)
		}
	}
	output, err := snapshotExportFile(outputPath)
	if err != nil {
		return err
	}
	if output.exists && !managed && !force {
		return fmt.Errorf("%w: %s; use --force to replace a custom output", ErrClientExportExists, outputPath)
	}
	if _, err := snapshotExportFile(metadataPath); err != nil {
		return err
	}
	return nil
}

func validateExistingExportDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect managed export directory %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: managed export path %s must be a real directory", ErrClientExportUnsafe, path)
	}
	return nil
}

func (exporter *ClientExporter) ensureDirectories(outputPath string, managed bool) error {
	if err := ensureOwnedExportDirectory(exporter.paths.StateDir, exporter.paths.ExportsDir); err != nil {
		return err
	}
	if err := ensureOwnedExportDirectory(exporter.paths.ExportsDir, exporter.paths.ClientExportsDir); err != nil {
		return err
	}
	metadataDirectory := filepath.Join(exporter.paths.ClientExportsDir, clientExportMetadataDir)
	if err := ensureOwnedExportDirectory(exporter.paths.ClientExportsDir, metadataDirectory); err != nil {
		return err
	}
	if managed {
		return nil
	}
	parent := filepath.Dir(outputPath)
	_, statErr := os.Lstat(parent)
	created := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !created {
		return fmt.Errorf("inspect custom export directory: %w", statErr)
	}
	if created {
		if err := os.MkdirAll(parent, clientExportDirectoryMode); err != nil {
			return fmt.Errorf("create custom export directory: %w", err)
		}
		if err := os.Chmod(parent, clientExportDirectoryMode); err != nil {
			return fmt.Errorf("set custom export directory mode: %w", err)
		}
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect custom export directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: custom output parent must be a real directory", ErrClientExportUnsafe)
	}
	return nil
}

func ensureOwnedExportDirectory(parent, path string) error {
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect managed export parent %s: %w", parent, err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return fmt.Errorf("%w: managed export parent %s must be a real directory", ErrClientExportUnsafe, parent)
	}
	if err := os.Mkdir(path, clientExportDirectoryMode); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create managed export directory %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect managed export directory %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: managed export path %s must be a real directory", ErrClientExportUnsafe, path)
	}
	if err := os.Chmod(path, clientExportDirectoryMode); err != nil {
		return fmt.Errorf("set managed export directory mode %s: %w", path, err)
	}
	return syncExportDirectory(parent)
}

type exportFileSnapshot struct {
	exists bool
	mode   os.FileMode
	data   []byte
}

func publishClientExport(outputPath string, content []byte, replaceOutput bool, metadataPath string, metadata []byte) error {
	if len(content) == 0 || len(content) > clientExportMaximumBytes || len(metadata) == 0 || len(metadata) > clientExportMaximumBytes {
		return fmt.Errorf("client export content or metadata is outside the supported size")
	}
	outputBefore, err := snapshotExportFile(outputPath)
	if err != nil {
		return err
	}
	if outputBefore.exists && !replaceOutput {
		return fmt.Errorf("%w: %s; use --force to replace a custom output", ErrClientExportExists, outputPath)
	}
	if _, err := snapshotExportFile(metadataPath); err != nil {
		return err
	}
	profileTemporary, err := stageExportFile(filepath.Dir(outputPath), ".client-profile-", content)
	if err != nil {
		return err
	}
	defer os.Remove(profileTemporary)
	metadataTemporary, err := stageExportFile(filepath.Dir(metadataPath), ".client-metadata-", metadata)
	if err != nil {
		return err
	}
	defer os.Remove(metadataTemporary)

	if replaceOutput {
		if err := os.Rename(profileTemporary, outputPath); err != nil {
			return fmt.Errorf("activate client export: %w", err)
		}
	} else {
		if err := os.Link(profileTemporary, outputPath); err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("%w: %s; use --force to replace a custom output", ErrClientExportExists, outputPath)
			}
			return fmt.Errorf("activate new custom client export: %w", err)
		}
	}
	if err := syncExportDirectory(filepath.Dir(outputPath)); err != nil {
		return rollbackPublishedProfile(outputPath, content, outputBefore, err)
	}
	if err := os.Rename(metadataTemporary, metadataPath); err != nil {
		return rollbackPublishedProfile(outputPath, content, outputBefore, fmt.Errorf("activate client export metadata: %w", err))
	}
	if err := syncExportDirectory(filepath.Dir(metadataPath)); err != nil {
		return fmt.Errorf("%w: profile and metadata are active but metadata durability is unknown: %v", ErrClientExportUncertain, err)
	}
	return nil
}

func snapshotExportFile(path string) (exportFileSnapshot, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return exportFileSnapshot{}, nil
	}
	if err != nil {
		return exportFileSnapshot{}, fmt.Errorf("inspect client export %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return exportFileSnapshot{}, fmt.Errorf("%w: %s must be a regular file", ErrClientExportUnsafe, path)
	}
	if info.Size() > clientExportMaximumBytes {
		return exportFileSnapshot{}, fmt.Errorf("%w: %s exceeds the supported size", ErrClientExportUnsafe, path)
	}
	file, err := os.Open(path)
	if err != nil {
		return exportFileSnapshot{}, fmt.Errorf("open client export %s: %w", path, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return exportFileSnapshot{}, fmt.Errorf("inspect opened client export %s: %w", path, err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return exportFileSnapshot{}, fmt.Errorf("%w: %s changed while it was inspected", ErrClientExportUnsafe, path)
	}
	data, err := io.ReadAll(io.LimitReader(file, clientExportMaximumBytes+1))
	if err != nil {
		return exportFileSnapshot{}, fmt.Errorf("read client export %s: %w", path, err)
	}
	if len(data) > clientExportMaximumBytes {
		return exportFileSnapshot{}, fmt.Errorf("%w: %s exceeds the supported size", ErrClientExportUnsafe, path)
	}
	return exportFileSnapshot{exists: true, mode: openedInfo.Mode().Perm(), data: data}, nil
}

func stageExportFile(directory, pattern string, data []byte) (string, error) {
	file, err := os.CreateTemp(directory, pattern+"*.tmp")
	if err != nil {
		return "", fmt.Errorf("create client export temporary file: %w", err)
	}
	path := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(clientExportFileMode); err != nil {
		return "", fmt.Errorf("set client export temporary mode: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return "", fmt.Errorf("write client export temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync client export temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close client export temporary file: %w", err)
	}
	keep = true
	return path, nil
}

func rollbackPublishedProfile(path string, published []byte, before exportFileSnapshot, cause error) error {
	current, err := snapshotExportFile(path)
	if err != nil || !current.exists || sha256.Sum256(current.data) != sha256.Sum256(published) {
		return errors.Join(fmt.Errorf("%w: cannot safely restore profile after metadata failure", ErrClientExportUncertain), cause, err)
	}
	if !before.exists {
		if err := os.Remove(path); err != nil {
			return errors.Join(fmt.Errorf("%w: remove newly published profile: %v", ErrClientExportUncertain, err), cause)
		}
	} else {
		temporary, err := stageExportFile(filepath.Dir(path), ".client-rollback-", before.data)
		if err != nil {
			return errors.Join(fmt.Errorf("%w: stage prior profile: %v", ErrClientExportUncertain, err), cause)
		}
		defer os.Remove(temporary)
		if err := os.Chmod(temporary, before.mode); err != nil {
			return errors.Join(fmt.Errorf("%w: restore prior profile mode: %v", ErrClientExportUncertain, err), cause)
		}
		if err := os.Rename(temporary, path); err != nil {
			return errors.Join(fmt.Errorf("%w: restore prior profile: %v", ErrClientExportUncertain, err), cause)
		}
	}
	if err := syncExportDirectory(filepath.Dir(path)); err != nil {
		return errors.Join(fmt.Errorf("%w: sync restored profile: %v", ErrClientExportUncertain, err), cause)
	}
	return cause
}

func syncExportDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open client export directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync client export directory: %w", err)
	}
	return nil
}

func scpClientExportHint(publicIPv4, path string) string {
	remote := "root@" + publicIPv4 + ":" + path
	return "scp " + shellQuoteIfNeeded(remote) + " ."
}

func shellQuoteIfNeeded(value string) string {
	if value != "" && strings.IndexFunc(value, func(character rune) bool {
		return !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("/._:@+-", character))
	}) == -1 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
