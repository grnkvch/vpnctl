package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const GatewayBootstrapRepairPlanSchemaVersion = 1

var ErrGatewayBootstrapRepairConflict = errors.New("gateway bootstrap repair conflicts with host state")

// GatewayBootstrapRepairPlan binds confirmation to package, tree and passive
// readiness metadata without serializing nginx configuration or credentials.
type GatewayBootstrapRepairPlan struct {
	SchemaVersion          int                       `json:"schema_version"`
	Generation             uint64                    `json:"generation"`
	Required               bool                      `json:"required"`
	PackagePlan            lifecycle.RolePackagePlan `json:"package_plan"`
	IngressCandidateSHA256 string                    `json:"ingress_candidate_sha256"`
	DropInSHA256           string                    `json:"drop_in_sha256"`
	ReadinessSHA256        string                    `json:"readiness_sha256"`
}

func (plan GatewayBootstrapRepairPlan) Validate() error {
	if plan.SchemaVersion != GatewayBootstrapRepairPlanSchemaVersion {
		return fmt.Errorf("%w: bootstrap schema_version must be %d", ErrGatewayRepairInvalid, GatewayBootstrapRepairPlanSchemaVersion)
	}
	if plan.Generation == 0 {
		return fmt.Errorf("%w: bootstrap generation is required", ErrGatewayRepairInvalid)
	}
	if plan.PackagePlan.Role != model.RoleGateway {
		return fmt.Errorf("%w: bootstrap package role must be gateway", ErrGatewayRepairInvalid)
	}
	if err := plan.PackagePlan.Validate(); err != nil {
		return fmt.Errorf("%w: bootstrap package plan: %v", ErrGatewayRepairInvalid, err)
	}
	if !validGatewayRepairHash(plan.IngressCandidateSHA256) {
		return fmt.Errorf("%w: bootstrap ingress candidate hash is invalid", ErrGatewayRepairInvalid)
	}
	if !validGatewayRepairHash(plan.DropInSHA256) {
		return fmt.Errorf("%w: bootstrap service drop-in hash is invalid", ErrGatewayRepairInvalid)
	}
	if !validGatewayRepairHash(plan.ReadinessSHA256) {
		return fmt.Errorf("%w: bootstrap readiness hash is invalid", ErrGatewayRepairInvalid)
	}
	return nil
}

type gatewayBootstrapRepairPreparation interface {
	Activate(context.Context) error
	Verify(context.Context) error
	Commit(context.Context) error
	Rollback(context.Context) error
}

type gatewayBootstrapRepairRuntime interface {
	Plan(context.Context, model.State) (GatewayBootstrapRepairPlan, error)
	Prepare(context.Context, model.State, GatewayBootstrapRepairPlan) (gatewayBootstrapRepairPreparation, error)
}

type systemGatewayBootstrapRepair struct {
	paths      store.Paths
	release    lifecycle.InitReleaseSource
	packages   lifecycle.RolePackageManager
	rediscover lifecycle.InitHostDiscoverer
	ingress    *ingress.NginxBaselineManager
	readiness  *lifecycle.GatewayBootstrapReadinessInspector
}

type systemGatewayBootstrapPreparation struct {
	mu                  sync.Mutex
	runtime             *systemGatewayBootstrapRepair
	state               model.State
	manifest            lifecycle.ReleaseManifest
	packageInstallation lifecycle.RolePackageInstallation
	ingressPlan         ingress.NginxBaselinePlan
	ingressRequest      ingress.NginxBaselineRequest
	ingressInstallation *ingress.NginxBaselineInstallation
	required            bool
	finished            bool
}

func newSystemGatewayBootstrapRepair(paths store.Paths) (*systemGatewayBootstrapRepair, error) {
	runner := linuxplatform.OSProbeRunner{}
	installer, err := lifecycle.NewReleaseBundleInstaller(paths.Root, lifecycle.ReleasePlatform{
		OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64",
	})
	if err != nil {
		return nil, err
	}
	release, err := lifecycle.NewLocalInitReleaseSource(installer, lifecycle.InstalledReleaseBundlePath(paths))
	if err != nil {
		return nil, err
	}
	packages, err := lifecycle.NewSystemRolePackageManager(paths.Root, runner)
	if err != nil {
		return nil, err
	}
	rediscover, err := linuxplatform.NewDiscoverer(paths.Root)
	if err != nil {
		return nil, err
	}
	ingressManager, err := ingress.NewSystemNginxBaselineManager(paths)
	if err != nil {
		return nil, err
	}
	readiness, err := lifecycle.NewGatewayBootstrapReadinessInspector(paths, packages, runner)
	if err != nil {
		return nil, err
	}
	return &systemGatewayBootstrapRepair{
		paths: paths, release: release, packages: packages, rediscover: rediscover,
		ingress: ingressManager, readiness: readiness,
	}, nil
}

func (runtime *systemGatewayBootstrapRepair) Plan(ctx context.Context, state model.State) (GatewayBootstrapRepairPlan, error) {
	if ctx == nil || runtime == nil || runtime.release == nil || runtime.packages == nil || runtime.readiness == nil || runtime.ingress == nil {
		return GatewayBootstrapRepairPlan{}, ErrGatewayRepairInvalid
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return GatewayBootstrapRepairPlan{}, errors.Join(ErrGatewayRepairInvalid, err)
	}
	manifest, err := runtime.release.Inspect(ctx)
	if err != nil {
		return GatewayBootstrapRepairPlan{}, fmt.Errorf("inspect installed Gateway release for repair: %w", err)
	}
	if !reflect.DeepEqual(manifest.ComponentManifest, state.Components) {
		return GatewayBootstrapRepairPlan{}, fmt.Errorf("%w: installed release differs from authoritative state", ErrGatewayBootstrapRepairConflict)
	}
	packagePlan, err := runtime.packages.Plan(ctx, manifest, model.RoleGateway)
	if err != nil {
		return GatewayBootstrapRepairPlan{}, err
	}
	readiness, err := runtime.readiness.Inspect(ctx, state, manifest)
	if err != nil {
		return GatewayBootstrapRepairPlan{}, err
	}
	for _, check := range readiness.Checks {
		if check.Condition == lifecycle.GatewayReadinessConflict {
			return GatewayBootstrapRepairPlan{}, fmt.Errorf("%w: %s/%s", ErrGatewayBootstrapRepairConflict, check.Kind, check.ID)
		}
	}
	if _, err := runtime.ingress.Plan(); err != nil {
		return GatewayBootstrapRepairPlan{}, err
	}
	readinessEncoded, err := json.Marshal(readiness)
	if err != nil {
		return GatewayBootstrapRepairPlan{}, err
	}
	plan := GatewayBootstrapRepairPlan{
		SchemaVersion: GatewayBootstrapRepairPlanSchemaVersion, Generation: state.Generation, Required: !readiness.Ready,
		PackagePlan: packagePlan, IngressCandidateSHA256: readiness.CandidateSHA256,
		DropInSHA256:    gatewayBootstrapSHA256(ingress.RenderNginxServiceDropIn(runtime.paths)),
		ReadinessSHA256: gatewayBootstrapSHA256(readinessEncoded),
	}
	if err := plan.Validate(); err != nil {
		return GatewayBootstrapRepairPlan{}, err
	}
	return plan, nil
}

func (runtime *systemGatewayBootstrapRepair) Prepare(ctx context.Context, state model.State, approved GatewayBootstrapRepairPlan) (gatewayBootstrapRepairPreparation, error) {
	if err := approved.Validate(); err != nil {
		return nil, err
	}
	fresh, err := runtime.Plan(ctx, state)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(fresh, approved) {
		return nil, ErrGatewayRepairStale
	}
	manifest, err := runtime.release.Inspect(ctx)
	if err != nil {
		return nil, err
	}
	preparation := &systemGatewayBootstrapPreparation{
		runtime: runtime, state: state, manifest: manifest, required: approved.Required,
	}
	if !approved.Required {
		return preparation, nil
	}
	preparation.packageInstallation, err = runtime.packages.Apply(ctx, manifest, approved.PackagePlan)
	if err != nil {
		return nil, fmt.Errorf("repair Gateway packages: %w", err)
	}
	fail := func(cause error) (gatewayBootstrapRepairPreparation, error) {
		return nil, errors.Join(cause, runtime.packages.Rollback(context.Background(), preparation.packageInstallation))
	}
	snapshot, err := runtime.rediscover.Discover(ctx)
	if err != nil {
		return fail(fmt.Errorf("rediscover Gateway after package repair: %w", err))
	}
	if err := snapshot.ValidateMandatoryCapabilities(); err != nil {
		return fail(err)
	}
	preparation.ingressPlan, err = runtime.ingress.Plan()
	if err != nil {
		return fail(err)
	}
	certificatePath, privateKeyPath, err := gatewayBootstrapCertificatePaths(runtime.paths, state)
	if err != nil {
		return fail(err)
	}
	preparation.ingressRequest = ingress.NginxBaselineRequest{
		StateGeneration: state.Generation, PublicIPv4: state.Host.PublicIPv4,
		CertificatePath: certificatePath, PrivateKeyPath: privateKeyPath, Exposes: append([]model.Expose(nil), state.Exposes...),
	}
	return preparation, nil
}

func (preparation *systemGatewayBootstrapPreparation) Activate(ctx context.Context) error {
	if ctx == nil || preparation == nil || preparation.runtime == nil {
		return ErrGatewayRepairInvalid
	}
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	if preparation.finished || preparation.ingressInstallation != nil {
		return ErrGatewayRepairInvalid
	}
	if !preparation.required {
		return nil
	}
	result, installation, err := preparation.runtime.ingress.Apply(ctx, preparation.ingressPlan, preparation.ingressRequest)
	if err != nil {
		return fmt.Errorf("repair Gateway ingress: %w", err)
	}
	if installation == nil || result.ConfigHash == "" {
		return ErrGatewayRepairInvalid
	}
	preparation.ingressInstallation = installation
	return nil
}

func (preparation *systemGatewayBootstrapPreparation) Verify(ctx context.Context) error {
	if ctx == nil || preparation == nil || preparation.runtime == nil || preparation.finished {
		return ErrGatewayRepairInvalid
	}
	report, err := preparation.runtime.readiness.Inspect(ctx, preparation.state, preparation.manifest)
	if err != nil {
		return err
	}
	if !report.Ready {
		return fmt.Errorf("Gateway bootstrap remains incomplete after repair")
	}
	return nil
}

func (preparation *systemGatewayBootstrapPreparation) Commit(ctx context.Context) error {
	if ctx == nil || preparation == nil || preparation.runtime == nil {
		return ErrGatewayRepairInvalid
	}
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	if preparation.finished {
		return ErrGatewayRepairInvalid
	}
	// Finalize the package journal first. Package rollback remains possible if
	// the retained nginx activation cannot be committed; the inverse ordering
	// could make a package commit failure impossible to compensate after nginx
	// has discarded its prior generation.
	if preparation.packageInstallation.TransactionID != "" {
		if err := preparation.runtime.packages.Commit(ctx, preparation.packageInstallation); err != nil {
			return err
		}
	}
	if preparation.ingressInstallation != nil {
		if err := preparation.runtime.ingress.Commit(ctx, preparation.ingressInstallation); err != nil {
			return err
		}
	}
	preparation.finished = true
	return nil
}

func (preparation *systemGatewayBootstrapPreparation) Rollback(ctx context.Context) error {
	if ctx == nil || preparation == nil || preparation.runtime == nil {
		return ErrGatewayRepairInvalid
	}
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	if preparation.finished {
		return nil
	}
	var result error
	if preparation.ingressInstallation != nil {
		result = errors.Join(result, preparation.runtime.ingress.Rollback(ctx, preparation.ingressInstallation))
	}
	if preparation.packageInstallation.TransactionID != "" {
		result = errors.Join(result, preparation.runtime.packages.Rollback(ctx, preparation.packageInstallation))
	}
	if result == nil {
		preparation.finished = true
	}
	return result
}

func gatewayBootstrapCertificatePaths(paths store.Paths, state model.State) (string, string, error) {
	var certificate model.Certificate
	found := false
	for _, item := range state.Certificates {
		if item.Kind != model.CertificatePublicIngress {
			continue
		}
		if found {
			return "", "", fmt.Errorf("multiple public ingress certificates are active")
		}
		certificate, found = item, true
	}
	if !found {
		return "", "", ingress.ErrPublicCertificateNotFound
	}
	resolve := func(reference model.SecretRef) (string, error) {
		kind, id, err := reference.Parts()
		if err != nil || strings.ContainsAny(kind+id, `/\\`) {
			return "", fmt.Errorf("invalid ingress secret reference")
		}
		return filepath.Join(paths.SecretsDir, kind, id), nil
	}
	certificatePath, err := resolve(model.SecretRef(certificate.CertificateRef))
	if err != nil {
		return "", "", err
	}
	privateKeyPath, err := resolve(certificate.PrivateKeyRef)
	return certificatePath, privateKeyPath, err
}

func gatewayBootstrapSHA256(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

var _ gatewayBootstrapRepairRuntime = (*systemGatewayBootstrapRepair)(nil)
