package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/render"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var ErrClientExportDrift = errors.New("client export has unsafe or modified artifacts")

type clientArtifactRemoval struct {
	path           string
	expectedSHA256 string
	publicPath     bool
}

func managedClientExportPath(paths store.Paths, clientName string, format ClientExportFormat) string {
	extension := ".clash.yaml"
	if format == ClientExportWireGuard {
		extension = ".wireguard.conf"
	}
	return filepath.Join(paths.ClientExportsDir, clientName+extension)
}

func clientExportMetadataPath(paths store.Paths, clientID string, format ClientExportFormat) string {
	return filepath.Join(paths.ClientExportsDir, clientExportMetadataDir, clientID+"."+string(format)+".json")
}

// inspectClientExportState reduces both independently tracked formats to the
// intentionally compact public state. Any malformed, missing, drifted, or
// generation-mismatched tracked artifact is stale rather than trusted.
func inspectClientExportState(paths store.Paths, state model.State, client model.Client) ClientExportState {
	found := false
	stale := false
	for _, format := range []ClientExportFormat{ClientExportClash, ClientExportWireGuard} {
		formatFound, current := inspectClientExportFormat(paths, state, client, format)
		found = found || formatFound
		stale = stale || (formatFound && !current)
	}
	if !found {
		return ClientExportNotCreated
	}
	if stale {
		return ClientExportStale
	}
	return ClientExportCurrent
}

func inspectClientExportFormat(paths store.Paths, state model.State, client model.Client, format ClientExportFormat) (bool, bool) {
	metadataPath := clientExportMetadataPath(paths, client.ID, format)
	metadataInfo, err := os.Lstat(metadataPath)
	if errors.Is(err, os.ErrNotExist) {
		return inspectUntrackedManagedExport(paths, client.Name, format)
	}
	if err != nil || metadataInfo.Mode()&os.ModeSymlink != 0 || !metadataInfo.Mode().IsRegular() || metadataInfo.Mode().Perm() != clientExportFileMode {
		return true, false
	}
	metadata, err := snapshotExportFile(metadataPath)
	if err != nil || !metadata.exists {
		return true, false
	}
	manifest, err := render.DecodeManifest(metadata.data)
	if err != nil || len(manifest.Artifacts) != 1 || manifest.SourceStateGeneration > state.Generation {
		return true, false
	}
	record := manifest.Artifacts[0]
	if record.Mode != "0600" || !clientExportDependenciesCurrent(record, state, client, format) {
		return true, false
	}
	profile, err := snapshotExportFile(record.Path)
	if err != nil || !profile.exists || profile.mode != clientExportFileMode {
		return true, false
	}
	digest := sha256.Sum256(profile.data)
	if record.ContentSHA256 != hex.EncodeToString(digest[:]) || client.Lifecycle != model.LifecycleActive {
		return true, false
	}
	return true, true
}

func inspectUntrackedManagedExport(paths store.Paths, clientName string, format ClientExportFormat) (bool, bool) {
	_, err := os.Lstat(managedClientExportPath(paths, clientName, format))
	if errors.Is(err, os.ErrNotExist) {
		return false, false
	}
	// Any object without its generation sidecar is visible drift. The inspector
	// never guesses that profile bytes are current.
	return true, false
}

func clientExportDependenciesCurrent(record render.ArtifactRecord, state model.State, client model.Client, format ClientExportFormat) bool {
	wantCredential := []render.SourceGeneration{{
		Kind: "client-credential", ID: client.ID, Generation: client.CredentialGeneration,
	}}
	if !reflect.DeepEqual(record.CredentialGenerations, wantCredential) {
		return false
	}
	wantPolicy := []render.SourceGeneration{}
	if format == ClientExportClash {
		if generation := clientPolicyGeneration(state, client.ID); generation != 0 {
			wantPolicy = append(wantPolicy, render.SourceGeneration{
				Kind: "client-policy", ID: client.ID, Generation: generation,
			})
		}
	}
	return reflect.DeepEqual(record.PolicyGenerations, wantPolicy)
}

func clientPolicyGeneration(state model.State, clientID string) uint64 {
	if policy, found := findTargetPolicy(state.Policies, model.TargetClient, clientID); found {
		return policy.Generation
	}
	return 0
}

func knownClientExportPaths(paths store.Paths, client model.Client) []string {
	known := make(map[string]struct{})
	for _, format := range []ClientExportFormat{ClientExportClash, ClientExportWireGuard} {
		managedPath := managedClientExportPath(paths, client.Name, format)
		if _, err := os.Lstat(managedPath); err == nil {
			known[managedPath] = struct{}{}
		}
		metadata, err := snapshotExportFile(clientExportMetadataPath(paths, client.ID, format))
		if err != nil || !metadata.exists {
			continue
		}
		manifest, err := render.DecodeManifest(metadata.data)
		if err == nil && len(manifest.Artifacts) == 1 {
			known[manifest.Artifacts[0].Path] = struct{}{}
		}
	}
	result := make([]string, 0, len(known))
	for path := range known {
		result = append(result, path)
	}
	sort.Strings(result)
	return result
}

func planClientArtifactRemoval(paths store.Paths, client model.Client) ([]clientArtifactRemoval, []string, error) {
	profiles := make(map[string]clientArtifactRemoval)
	metadata := make(map[string]clientArtifactRemoval)
	for _, format := range []ClientExportFormat{ClientExportClash, ClientExportWireGuard} {
		managedPath := managedClientExportPath(paths, client.Name, format)
		managed, err := snapshotExportFile(managedPath)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: inspect managed %s artifact: %v", ErrClientExportDrift, format, err)
		}
		if managed.exists {
			profiles[managedPath] = removalForSnapshot(managedPath, managed, true)
		}

		metadataPath := clientExportMetadataPath(paths, client.ID, format)
		metadataSnapshot, err := snapshotExportFile(metadataPath)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: inspect %s metadata: %v", ErrClientExportDrift, format, err)
		}
		if !metadataSnapshot.exists {
			continue
		}
		if metadataSnapshot.mode != clientExportFileMode {
			return nil, nil, fmt.Errorf("%w: %s metadata mode is not 0600", ErrClientExportDrift, format)
		}
		manifest, err := render.DecodeManifest(metadataSnapshot.data)
		if err != nil || len(manifest.Artifacts) != 1 {
			return nil, nil, fmt.Errorf("%w: invalid %s metadata", ErrClientExportDrift, format)
		}
		record := manifest.Artifacts[0]
		if record.Mode != "0600" || !clientExportRecordBelongsToClient(record, client.ID, format) {
			return nil, nil, fmt.Errorf("%w: %s metadata does not belong to client", ErrClientExportDrift, format)
		}
		if record.Path != managedPath {
			if err := rejectReservedRecordedExportPath(paths, record.Path); err != nil {
				return nil, nil, err
			}
			custom, snapshotErr := snapshotExportFile(record.Path)
			if snapshotErr != nil {
				return nil, nil, fmt.Errorf("%w: inspect custom %s artifact: %v", ErrClientExportDrift, format, snapshotErr)
			}
			if custom.exists {
				digest := sha256.Sum256(custom.data)
				if custom.mode != clientExportFileMode || record.ContentSHA256 != hex.EncodeToString(digest[:]) {
					return nil, nil, fmt.Errorf("%w: custom %s artifact changed after export", ErrClientExportDrift, format)
				}
				profiles[record.Path] = removalForSnapshot(record.Path, custom, true)
			}
		}
		metadata[metadataPath] = removalForSnapshot(metadataPath, metadataSnapshot, false)
	}

	profilePaths := sortedRemovalPaths(profiles)
	metadataPaths := sortedRemovalPaths(metadata)
	removals := make([]clientArtifactRemoval, 0, len(profilePaths)+len(metadataPaths))
	publicPaths := make([]string, 0, len(profilePaths))
	for _, path := range profilePaths {
		removals = append(removals, profiles[path])
		publicPaths = append(publicPaths, path)
	}
	for _, path := range metadataPaths {
		removals = append(removals, metadata[path])
	}
	return removals, publicPaths, nil
}

func removalForSnapshot(path string, snapshot exportFileSnapshot, publicPath bool) clientArtifactRemoval {
	digest := sha256.Sum256(snapshot.data)
	return clientArtifactRemoval{path: path, expectedSHA256: hex.EncodeToString(digest[:]), publicPath: publicPath}
}

func sortedRemovalPaths(values map[string]clientArtifactRemoval) []string {
	result := make([]string, 0, len(values))
	for path := range values {
		result = append(result, path)
	}
	sort.Strings(result)
	return result
}

func clientExportRecordBelongsToClient(record render.ArtifactRecord, clientID string, format ClientExportFormat) bool {
	if len(record.CredentialGenerations) != 1 || record.CredentialGenerations[0].Kind != "client-credential" ||
		record.CredentialGenerations[0].ID != clientID {
		return false
	}
	if format == ClientExportWireGuard {
		return len(record.PolicyGenerations) == 0
	}
	return len(record.PolicyGenerations) == 0 || (len(record.PolicyGenerations) == 1 &&
		record.PolicyGenerations[0].Kind == "client-policy" && record.PolicyGenerations[0].ID == clientID)
}

func rejectReservedRecordedExportPath(paths store.Paths, path string) error {
	resolved, err := resolveFutureExportPath(path)
	if err != nil {
		return fmt.Errorf("%w: resolve recorded custom artifact: %v", ErrClientExportDrift, err)
	}
	for _, reserved := range []string{paths.ConfigDir, paths.StateDir, paths.RuntimeDir} {
		resolvedReserved, resolveErr := resolveFutureExportPath(reserved)
		if resolveErr != nil {
			return fmt.Errorf("%w: resolve reserved path: %v", ErrClientExportDrift, resolveErr)
		}
		if exportPathWithin(resolvedReserved, resolved) {
			return fmt.Errorf("%w: custom artifact points into vpnctl-managed state", ErrClientExportDrift)
		}
	}
	return nil
}

func removePlannedClientArtifacts(removals []clientArtifactRemoval) ([]string, bool, error) {
	pending := make([]string, 0)
	internalPending := false
	for _, removal := range removals {
		snapshot, err := snapshotExportFile(removal.path)
		if err != nil {
			pending, internalPending = recordPendingRemoval(pending, internalPending, removal)
			continue
		}
		if !snapshot.exists {
			continue
		}
		digest := sha256.Sum256(snapshot.data)
		if snapshot.mode != clientExportFileMode || removal.expectedSHA256 != hex.EncodeToString(digest[:]) {
			pending, internalPending = recordPendingRemoval(pending, internalPending, removal)
			continue
		}
		if err := os.Remove(removal.path); err != nil {
			pending, internalPending = recordPendingRemoval(pending, internalPending, removal)
			continue
		}
		if err := syncExportDirectory(filepath.Dir(removal.path)); err != nil {
			pending, internalPending = recordPendingRemoval(pending, internalPending, removal)
		}
	}
	if len(pending) != 0 || internalPending {
		sort.Strings(pending)
		return pending, internalPending, fmt.Errorf("failed to remove all client export artifacts")
	}
	return []string{}, false, nil
}

func recordPendingRemoval(paths []string, internal bool, removal clientArtifactRemoval) ([]string, bool) {
	if removal.publicPath {
		return append(paths, removal.path), internal
	}
	return paths, true
}
