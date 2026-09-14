package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	GatewayBootstrapReadinessSchemaVersion = 1
	gatewayBootstrapReadinessTimeout       = 5 * time.Second
)

type GatewayReadinessCondition string

const (
	GatewayReadinessHealthy     GatewayReadinessCondition = "healthy"
	GatewayReadinessMissing     GatewayReadinessCondition = "missing"
	GatewayReadinessDrifted     GatewayReadinessCondition = "drifted"
	GatewayReadinessConflict    GatewayReadinessCondition = "conflict"
	GatewayReadinessUnavailable GatewayReadinessCondition = "unavailable"
)

// GatewayBootstrapReadinessCheck is deliberately metadata-only. It contains
// no package-manager transcript, certificate path, expose path or credential.
type GatewayBootstrapReadinessCheck struct {
	Kind           string                    `json:"kind"`
	ID             string                    `json:"id"`
	Condition      GatewayReadinessCondition `json:"condition"`
	Code           string                    `json:"code"`
	Expected       string                    `json:"expected,omitempty"`
	Observed       string                    `json:"observed,omitempty"`
	ExpectedSHA256 string                    `json:"expected_sha256,omitempty"`
	ObservedSHA256 string                    `json:"observed_sha256,omitempty"`
}

type GatewayBootstrapReadinessReport struct {
	SchemaVersion   int                              `json:"schema_version"`
	Generation      uint64                           `json:"generation"`
	Ready           bool                             `json:"ready"`
	CandidateSHA256 string                           `json:"candidate_sha256"`
	Checks          []GatewayBootstrapReadinessCheck `json:"checks"`
}

type GatewayBootstrapReadinessInspector struct {
	paths    store.Paths
	packages RolePackageManager
	runner   linuxplatform.ProbeRunner
}

func NewGatewayBootstrapReadinessInspector(paths store.Paths, packages RolePackageManager, runner linuxplatform.ProbeRunner) (*GatewayBootstrapReadinessInspector, error) {
	want, err := store.NewPaths(paths.Root)
	if err != nil || paths != want || packages == nil || runner == nil {
		return nil, fmt.Errorf("gateway readiness dependencies are incomplete")
	}
	return &GatewayBootstrapReadinessInspector{paths: paths, packages: packages, runner: runner}, nil
}

// Inspect is a bounded, read-only projection. It does not refresh apt
// metadata, contact the public network, control services or alter files.
func (inspector *GatewayBootstrapReadinessInspector) Inspect(ctx context.Context, state model.State, manifest ReleaseManifest) (GatewayBootstrapReadinessReport, error) {
	if ctx == nil || inspector == nil || inspector.packages == nil || inspector.runner == nil {
		return GatewayBootstrapReadinessReport{}, fmt.Errorf("gateway readiness inspector is incomplete")
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return GatewayBootstrapReadinessReport{}, errors.Join(fmt.Errorf("gateway readiness requires valid Gateway state"), err)
	}
	if err := manifest.Validate(); err != nil || manifest.ComponentManifest.VPNCTLVersion != state.Components.VPNCTLVersion {
		return GatewayBootstrapReadinessReport{}, errors.Join(fmt.Errorf("gateway readiness release manifest does not match state"), err)
	}
	bounded, cancel := context.WithTimeout(ctx, gatewayBootstrapReadinessTimeout)
	defer cancel()

	report := GatewayBootstrapReadinessReport{
		SchemaVersion: GatewayBootstrapReadinessSchemaVersion, Generation: state.Generation,
		Checks: []GatewayBootstrapReadinessCheck{},
	}
	inspector.inspectPackages(bounded, manifest, &report)
	candidate, treeCheck, err := inspector.inspectTree(state)
	if err != nil {
		return GatewayBootstrapReadinessReport{}, err
	}
	report.CandidateSHA256 = candidate.ConfigHash()
	inspector.inspectDropIn(&report)
	report.Checks = append(report.Checks, treeCheck)
	inspector.inspectService(bounded, &report)
	inspector.inspectRuntime(bounded, &report)
	inspector.inspectListener(bounded, "public_https", ingress.NginxPublicHTTPSPort, "0.0.0.0", "nginx", &report)
	inspector.inspectListener(bounded, "enrollment_loopback", ingress.NginxEnrollmentLoopbackPort, "127.0.0.1", "vpnctl", &report)
	sort.Slice(report.Checks, func(left, right int) bool {
		return report.Checks[left].Kind+"\x00"+report.Checks[left].ID < report.Checks[right].Kind+"\x00"+report.Checks[right].ID
	})
	report.Ready = true
	for _, check := range report.Checks {
		if check.Condition != GatewayReadinessHealthy {
			report.Ready = false
			break
		}
	}
	return report, report.Validate()
}

func (report GatewayBootstrapReadinessReport) Validate() error {
	if report.SchemaVersion != GatewayBootstrapReadinessSchemaVersion || report.Generation == 0 || !validReleaseSHA256(report.CandidateSHA256) || report.Checks == nil {
		return fmt.Errorf("gateway readiness report is invalid")
	}
	previous := ""
	ready := true
	for _, check := range report.Checks {
		key := check.Kind + "\x00" + check.ID
		if check.Kind == "" || check.ID == "" || check.Code == "" || key <= previous || strings.ContainsAny(check.Kind+check.ID+check.Code+check.Expected+check.Observed, "\r\n\x00") {
			return fmt.Errorf("gateway readiness check is invalid")
		}
		switch check.Condition {
		case GatewayReadinessHealthy:
		case GatewayReadinessMissing, GatewayReadinessDrifted, GatewayReadinessConflict, GatewayReadinessUnavailable:
			ready = false
		default:
			return fmt.Errorf("gateway readiness condition is invalid")
		}
		for _, fingerprint := range []string{check.ExpectedSHA256, check.ObservedSHA256} {
			if fingerprint != "" && !validReleaseSHA256(fingerprint) {
				return fmt.Errorf("gateway readiness fingerprint is invalid")
			}
		}
		previous = key
	}
	if report.Ready != ready {
		return fmt.Errorf("gateway readiness aggregate is invalid")
	}
	return nil
}

func (inspector *GatewayBootstrapReadinessInspector) inspectPackages(ctx context.Context, manifest ReleaseManifest, report *GatewayBootstrapReadinessReport) {
	plan, err := inspector.packages.Plan(ctx, manifest, model.RoleGateway)
	if err != nil {
		condition, code := GatewayReadinessUnavailable, "package_observation_unavailable"
		if errors.Is(err, ErrRolePackageConflict) {
			condition, code = GatewayReadinessConflict, "package_incompatible"
		}
		report.Checks = append(report.Checks, GatewayBootstrapReadinessCheck{
			Kind: "package", ID: "gateway_manifest", Condition: condition, Code: code,
		})
		return
	}
	for _, item := range plan.Packages {
		check := GatewayBootstrapReadinessCheck{
			Kind: "package", ID: item.Package, Condition: GatewayReadinessHealthy, Code: "package_compatible",
			Expected: item.MinimumVersion + "..<" + item.MaximumVersionExclusive, Observed: item.InstalledVersion,
		}
		if item.Action == RolePackageInstall {
			check.Condition, check.Code, check.Observed = GatewayReadinessMissing, "package_missing", "absent"
		}
		report.Checks = append(report.Checks, check)
	}
}

func (inspector *GatewayBootstrapReadinessInspector) expectedCandidate(state model.State, generation uint64) (ingress.NginxCandidate, error) {
	var certificate model.Certificate
	found := false
	for _, item := range state.Certificates {
		if item.Kind != model.CertificatePublicIngress {
			continue
		}
		if found {
			return ingress.NginxCandidate{}, fmt.Errorf("multiple public ingress certificates are active")
		}
		certificate, found = item, true
	}
	if !found {
		return ingress.NginxCandidate{}, ingress.ErrPublicCertificateNotFound
	}
	certificatePath, err := gatewayInitSecretPath(inspector.paths, model.SecretRef(certificate.CertificateRef))
	if err != nil {
		return ingress.NginxCandidate{}, err
	}
	privateKeyPath, err := gatewayInitSecretPath(inspector.paths, certificate.PrivateKeyRef)
	if err != nil {
		return ingress.NginxCandidate{}, err
	}
	return ingress.RenderNginxConfig(ingress.NginxRenderRequest{
		StateGeneration: generation, PublicIPv4: state.Host.PublicIPv4,
		CertificatePath: certificatePath, PrivateKeyPath: privateKeyPath,
		RuntimeDirectory: ingress.NginxRuntimeDirectory(inspector.paths), Limits: ingress.DefaultGatewayHardLimits(),
		Exposes: state.Exposes,
	})
}

func (inspector *GatewayBootstrapReadinessInspector) inspectDropIn(report *GatewayBootstrapReadinessReport) {
	expected := ingress.RenderNginxServiceDropIn(inspector.paths)
	check := GatewayBootstrapReadinessCheck{
		Kind: "file", ID: ingress.NginxServiceDropInPath(inspector.paths), Condition: GatewayReadinessHealthy,
		Code: "nginx_drop_in_current", ExpectedSHA256: readinessSHA256(expected),
	}
	manager, err := ingress.NewNginxServiceManager(inspector.paths, inspector.runner)
	if err != nil {
		check.Condition, check.Code = GatewayReadinessUnavailable, "nginx_drop_in_observation_unavailable"
		report.Checks = append(report.Checks, check)
		return
	}
	plan, err := manager.Plan()
	if err != nil {
		check.Condition, check.Code = GatewayReadinessDrifted, "nginx_drop_in_drifted"
	} else if plan.Changed {
		check.Condition, check.Code = GatewayReadinessMissing, "nginx_drop_in_missing"
	} else {
		check.ObservedSHA256 = check.ExpectedSHA256
	}
	report.Checks = append(report.Checks, check)
}

func (inspector *GatewayBootstrapReadinessInspector) inspectTree(state model.State) (ingress.NginxCandidate, GatewayBootstrapReadinessCheck, error) {
	check := GatewayBootstrapReadinessCheck{Kind: "tree", ID: ingress.NginxActiveRoot(inspector.paths)}
	observed, present, err := ingress.InspectNginxActiveTree(inspector.paths)
	candidateGeneration := state.Generation
	if err == nil && present && observed.Generation <= state.Generation {
		candidateGeneration = observed.Generation
	}
	candidate, candidateErr := inspector.expectedCandidate(state, candidateGeneration)
	if candidateErr != nil {
		return ingress.NginxCandidate{}, GatewayBootstrapReadinessCheck{}, candidateErr
	}
	check.Condition = GatewayReadinessHealthy
	check.Code = "nginx_tree_current"
	check.Expected = fmt.Sprintf("generation-%d", candidateGeneration)
	check.ExpectedSHA256 = candidate.ConfigHash()
	if err != nil {
		check.Condition, check.Code = GatewayReadinessDrifted, "nginx_tree_drifted"
	} else if !present {
		check.Condition, check.Code = GatewayReadinessMissing, "nginx_tree_missing"
	} else {
		check.Observed, check.ObservedSHA256 = fmt.Sprintf("generation-%d", observed.Generation), observed.ConfigHash
		if observed.Generation > state.Generation || observed.ConfigHash != candidate.ConfigHash() {
			check.Condition, check.Code = GatewayReadinessDrifted, "nginx_tree_generation_mismatch"
			candidate, candidateErr = inspector.expectedCandidate(state, state.Generation)
			if candidateErr != nil {
				return ingress.NginxCandidate{}, GatewayBootstrapReadinessCheck{}, candidateErr
			}
			check.Expected = fmt.Sprintf("generation-%d", state.Generation)
			check.ExpectedSHA256 = candidate.ConfigHash()
		}
	}
	return candidate, check, nil
}

func (inspector *GatewayBootstrapReadinessInspector) inspectService(ctx context.Context, report *GatewayBootstrapReadinessReport) {
	check := GatewayBootstrapReadinessCheck{
		Kind: "unit", ID: ingress.NginxServiceUnit, Condition: GatewayReadinessHealthy,
		Code: "nginx_service_active", Expected: "loaded/active/running/enabled",
	}
	properties, err := inspector.runner.Run(ctx, linuxplatform.ProbeCommand{
		Name: "systemctl", Args: []string{"show", "--no-pager", "--property=LoadState", "--property=ActiveState", "--property=SubState", ingress.NginxServiceUnit},
	})
	if err != nil || properties.ExitCode != 0 {
		check.Condition, check.Code = GatewayReadinessUnavailable, "nginx_service_unavailable"
		report.Checks = append(report.Checks, check)
		return
	}
	values, valid := readinessSystemdProperties(properties.Stdout)
	if !valid {
		check.Condition, check.Code = GatewayReadinessUnavailable, "nginx_service_observation_invalid"
		report.Checks = append(report.Checks, check)
		return
	}
	enablement, enableErr := inspector.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"is-enabled", ingress.NginxServiceUnit}})
	observedEnablement := strings.TrimSpace(string(enablement.Stdout))
	check.Observed = values["LoadState"] + "/" + values["ActiveState"] + "/" + values["SubState"] + "/" + observedEnablement
	if enableErr != nil || enablement.ExitCode != 0 || observedEnablement != "enabled" {
		check.Condition, check.Code = GatewayReadinessDrifted, "nginx_service_not_enabled"
	} else if values["LoadState"] != "loaded" || values["ActiveState"] != "active" || values["SubState"] != "running" {
		check.Condition, check.Code = GatewayReadinessUnavailable, "nginx_service_not_active"
	}
	report.Checks = append(report.Checks, check)
}

func (inspector *GatewayBootstrapReadinessInspector) inspectRuntime(ctx context.Context, report *GatewayBootstrapReadinessReport) {
	check := GatewayBootstrapReadinessCheck{
		Kind: "runtime", ID: "nginx", Condition: GatewayReadinessHealthy, Code: "nginx_runtime_compatible",
		Expected: ingress.NginxProviderRuntimeVersion,
	}
	result, err := inspector.runner.Run(ctx, linuxplatform.ProbeCommand{Name: ingress.NginxBinaryPath(inspector.paths), Args: []string{"-v"}})
	if err != nil || result.ExitCode != 0 {
		check.Condition, check.Code = GatewayReadinessUnavailable, "nginx_runtime_unavailable"
	} else if !ingress.HasExactNginxVersion(string(result.Stdout) + " " + string(result.Stderr)) {
		check.Condition, check.Code = GatewayReadinessConflict, "nginx_runtime_incompatible"
	}
	report.Checks = append(report.Checks, check)
}

func (inspector *GatewayBootstrapReadinessInspector) inspectListener(ctx context.Context, id string, port int, address, owner string, report *GatewayBootstrapReadinessReport) {
	check := GatewayBootstrapReadinessCheck{
		Kind: "listener", ID: id, Condition: GatewayReadinessHealthy, Code: id + "_ready",
		Expected: fmt.Sprintf("tcp/%s:%d/%s", address, port, owner),
	}
	result, err := inspector.runner.Run(ctx, linuxplatform.ProbeCommand{
		Name: "ss", Args: []string{"-H", "-ltnp", fmt.Sprintf("sport = :%d", port)},
	})
	if err != nil || result.ExitCode != 0 {
		check.Condition, check.Code = GatewayReadinessUnavailable, id+"_observation_unavailable"
		report.Checks = append(report.Checks, check)
		return
	}
	line := strings.TrimSpace(string(result.Stdout))
	if line == "" {
		check.Condition, check.Code = GatewayReadinessMissing, id+"_missing"
	} else if strings.Count(line, "\n") != 0 || !strings.Contains(line, address+":"+fmt.Sprint(port)) || !strings.Contains(line, `(("`+owner+`",pid=`) {
		check.Condition, check.Code = GatewayReadinessConflict, id+"_foreign"
	} else {
		check.Observed = check.Expected
	}
	report.Checks = append(report.Checks, check)
}

func readinessSystemdProperties(data []byte) (map[string]string, bool) {
	values := make(map[string]string, 3)
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || value == "" || values[key] != "" || key != "LoadState" && key != "ActiveState" && key != "SubState" {
			return nil, false
		}
		values[key] = value
	}
	return values, values["LoadState"] != "" && values["ActiveState"] != "" && values["SubState"] != ""
}

func readinessSHA256(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func InstalledReleaseBundlePath(paths store.Paths) string {
	return filepath.Join(paths.Root, strings.TrimPrefix(ReleaseInstalledBundlePath, "/"))
}
