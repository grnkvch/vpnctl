package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

var managedUnitTokenPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,127}$`)

type ManagedUnitRuntime struct {
	FileType      string `json:"file_type"`
	Mode          string `json:"mode"`
	ContentSHA256 string `json:"content_sha256"`
	LoadState     string `json:"load_state"`
	ActiveState   string `json:"active_state"`
	SubState      string `json:"sub_state"`
	Enablement    string `json:"enablement"`
}

func ManagedUnitRuntimeFingerprint(runtime ManagedUnitRuntime) (string, error) {
	if runtime.FileType != "regular" && runtime.FileType != "symlink" && runtime.FileType != "hardlink" && runtime.FileType != "directory" && runtime.FileType != "other" {
		return "", fmt.Errorf("managed unit file type is invalid")
	}
	if len(runtime.Mode) != 4 || runtime.Mode[0] != '0' {
		return "", fmt.Errorf("managed unit mode is invalid")
	}
	for _, digit := range runtime.Mode[1:] {
		if digit < '0' || digit > '7' {
			return "", fmt.Errorf("managed unit mode is invalid")
		}
	}
	if runtime.FileType == "regular" {
		if validateFingerprint(runtime.ContentSHA256) != nil {
			return "", fmt.Errorf("managed unit content fingerprint is invalid")
		}
		for _, value := range []string{runtime.LoadState, runtime.ActiveState, runtime.SubState, runtime.Enablement} {
			if !managedUnitTokenPattern.MatchString(value) {
				return "", fmt.Errorf("managed unit state token is invalid")
			}
		}
	} else if runtime.ContentSHA256 != "" || runtime.LoadState != "" || runtime.ActiveState != "" || runtime.SubState != "" || runtime.Enablement != "" {
		return "", fmt.Errorf("non-regular managed unit cannot carry content or systemd state")
	}
	encoded, err := json.Marshal(runtime)
	if err != nil {
		return "", err
	}
	return ManagedFingerprint(encoded), nil
}

type SystemOwnedResourceDiscoverer struct {
	files  *FilesystemOwnedResourceDiscoverer
	runner linuxplatform.ProbeRunner
}

func NewSystemOwnedResourceDiscoverer(root string, runner linuxplatform.ProbeRunner) (*SystemOwnedResourceDiscoverer, error) {
	if runner == nil {
		return nil, fmt.Errorf("system owned-resource runner is required")
	}
	files, err := NewFilesystemOwnedResourceDiscoverer(root)
	if err != nil {
		return nil, err
	}
	return &SystemOwnedResourceDiscoverer{files: files, runner: runner}, nil
}

func (discoverer *SystemOwnedResourceDiscoverer) DiscoverOwnedResources(ctx context.Context, applied ConvergenceManifest) ([]OwnedResourceObservation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if discoverer == nil || discoverer.files == nil || discoverer.runner == nil {
		return nil, fmt.Errorf("system owned-resource discoverer is incomplete")
	}
	if err := applied.Validate(); err != nil {
		return nil, fmt.Errorf("validate applied convergence manifest: %w", err)
	}
	observations := make([]OwnedResourceObservation, 0, len(applied.Resources))
	for _, resource := range applied.Resources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var observation OwnedResourceObservation
		var present bool
		var err error
		switch resource.Key.Kind {
		case ManagedResourceFile:
			observation, present, err = discoverer.files.observeFile(ctx, resource)
		case ManagedResourceUnit:
			observation, present, err = discoverer.observeUnit(ctx, resource)
		default:
			err = fmt.Errorf("%w: %s resource %s", ErrOwnedResourceDiscoveryUnsupported, resource.Key.Kind, resourceOrder(resource.Key))
		}
		if err != nil {
			return nil, err
		}
		if present {
			observations = append(observations, observation)
		}
	}
	return observations, nil
}

func (discoverer *SystemOwnedResourceDiscoverer) observeUnit(ctx context.Context, resource ManagedResource) (OwnedResourceObservation, bool, error) {
	if !knownManagedUnit(resource.Key.ID) {
		return OwnedResourceObservation{}, false, fmt.Errorf("%w: unknown unit %q", ErrOwnedResourceDiscoveryUnsupported, resource.Key.ID)
	}
	logicalPath := filepath.Join("/etc/systemd/system", resource.Key.ID)
	actualPath := logicalPath
	if discoverer.files.root != "/" {
		actualPath = filepath.Join(discoverer.files.root, strings.TrimPrefix(logicalPath, "/"))
	}
	info, err := os.Lstat(actualPath)
	if errors.Is(err, fs.ErrNotExist) {
		return OwnedResourceObservation{}, false, nil
	}
	if err != nil {
		return OwnedResourceObservation{}, false, fmt.Errorf("observe owned unit %s: %w", resource.Key.ID, err)
	}
	runtime := ManagedUnitRuntime{FileType: managedObservedFileType(info.Mode()), Mode: fmt.Sprintf("%04o", info.Mode().Perm())}
	if runtime.FileType == "regular" {
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
			runtime.FileType = "hardlink"
		}
	}
	if runtime.FileType == "regular" {
		runtime.ContentSHA256, err = readManagedFileSHA256(ctx, actualPath, info)
		if errors.Is(err, fs.ErrNotExist) {
			return OwnedResourceObservation{}, false, nil
		}
		if err != nil {
			return OwnedResourceObservation{}, false, fmt.Errorf("observe owned unit %s: %w", resource.Key.ID, err)
		}
		properties, probeErr := discoverer.runner.Run(ctx, linuxplatform.ProbeCommand{
			Name: "systemctl", Args: []string{
				"show", "--no-pager", "--property=LoadState", "--property=ActiveState", "--property=SubState", resource.Key.ID,
			},
		})
		if probeErr != nil || properties.ExitCode != 0 {
			return OwnedResourceObservation{}, false, fmt.Errorf("observe owned unit %s properties", resource.Key.ID)
		}
		runtime.LoadState, runtime.ActiveState, runtime.SubState, err = parseManagedUnitProperties(properties.Stdout)
		if err != nil {
			return OwnedResourceObservation{}, false, fmt.Errorf("observe owned unit %s properties: %w", resource.Key.ID, err)
		}
		enablement, probeErr := discoverer.runner.Run(ctx, linuxplatform.ProbeCommand{
			Name: "systemctl", Args: []string{"is-enabled", resource.Key.ID},
		})
		if probeErr != nil {
			return OwnedResourceObservation{}, false, fmt.Errorf("observe owned unit %s enablement", resource.Key.ID)
		}
		runtime.Enablement = strings.TrimSpace(string(enablement.Stdout))
		if runtime.Enablement == "" || len(runtime.Enablement) > 128 || strings.ContainsAny(runtime.Enablement, "\x00\r\n\t ") {
			return OwnedResourceObservation{}, false, fmt.Errorf("observe owned unit %s enablement response", resource.Key.ID)
		}
	}
	runtimeSHA256, err := ManagedUnitRuntimeFingerprint(runtime)
	if err != nil {
		return OwnedResourceObservation{}, false, fmt.Errorf("fingerprint owned unit %s: %w", resource.Key.ID, err)
	}
	return OwnedResourceObservation{Key: resource.Key, RuntimeSHA256: runtimeSHA256, RemoveImpact: resource.RemoveImpact}, true, nil
}

func parseManagedUnitProperties(data []byte) (loadState, activeState, subState string, err error) {
	values := make(map[string]string, 3)
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || value == "" {
			return "", "", "", fmt.Errorf("invalid systemd property")
		}
		switch key {
		case "LoadState", "ActiveState", "SubState":
			if _, duplicate := values[key]; duplicate {
				return "", "", "", fmt.Errorf("duplicate systemd property")
			}
			values[key] = value
		default:
			return "", "", "", fmt.Errorf("unexpected systemd property")
		}
	}
	if values["LoadState"] == "" || values["ActiveState"] == "" || values["SubState"] == "" {
		return "", "", "", fmt.Errorf("missing systemd property")
	}
	return values["LoadState"], values["ActiveState"], values["SubState"], nil
}

func knownManagedUnit(name string) bool {
	for _, candidate := range managedUnitNames() {
		if candidate == name {
			return true
		}
	}
	return false
}

func managedUnitNames() []string {
	seen := make(map[string]struct{})
	for _, role := range []model.Role{model.RoleGateway, model.RoleNode} {
		for _, name := range linuxplatform.RoleUnitNames(role) {
			seen[name] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}
