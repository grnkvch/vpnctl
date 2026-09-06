package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestNodeConfigurationReplacerPreflightsAndActivatesCompleteGeneration(t *testing.T) {
	configuration := compiledNodeActivationFixture(t)
	host := &nodeReplacementHost{}
	readiness := &nodeReplacementReadiness{}
	replacer, err := NewNodeConfigurationReplacer(host, readiness)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := replacer.Prepare(context.Background(), configuration)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if host.planCalls != 1 || host.applyCalls != 0 {
		t.Fatalf("host calls after prepare = plan:%d apply:%d", host.planCalls, host.applyCalls)
	}
	if !reflect.DeepEqual(host.request.RestartUnits, nodeActivationOrder) {
		t.Fatalf("restart order = %v, want %v", host.request.RestartUnits, nodeActivationOrder)
	}
	files := configuration.ConfigFiles()
	if len(host.request.Resources) != len(files) {
		t.Fatalf("replacement resource count = %d, want %d", len(host.request.Resources), len(files))
	}
	for index, resource := range host.request.Resources {
		digest := sha256.Sum256(files[index].Content)
		if resource.Kind != linuxplatform.RoleRepairConfig || resource.Name != files[index].Name ||
			resource.ContentSHA256 != hex.EncodeToString(digest[:]) || !reflect.DeepEqual(resource.Content, files[index].Content) {
			t.Fatalf("replacement resource %d = %+v", index, resource)
		}
	}
	if err := replacer.Activate(context.Background(), prepared); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if host.applyCalls != 1 || readiness.calls != 1 || readiness.generation != configuration.StateGeneration() {
		t.Fatalf("activation calls = apply:%d readiness:%d generation:%d", host.applyCalls, readiness.calls, readiness.generation)
	}
	if err := replacer.Activate(context.Background(), prepared); err == nil || !strings.Contains(err.Error(), "already consumed") {
		t.Fatalf("second Activate() error = %v", err)
	}
}

func TestNodeConfigurationReplacerLeavesReadinessFailureForOuterCompensation(t *testing.T) {
	configuration := compiledNodeActivationFixture(t)
	readinessErr := errors.New("target tunnel is unavailable")
	host := &nodeReplacementHost{}
	replacer, err := NewNodeConfigurationReplacer(host, &nodeReplacementReadiness{err: readinessErr})
	if err != nil {
		t.Fatal(err)
	}
	err = replacer.Replace(context.Background(), configuration)
	if !errors.Is(err, ErrNodeConfigurationReplacementPending) || !errors.Is(err, readinessErr) {
		t.Fatalf("Replace() readiness error = %v", err)
	}
	if host.planCalls != 1 || host.applyCalls != 1 {
		t.Fatalf("host calls = plan:%d apply:%d", host.planCalls, host.applyCalls)
	}
}

func TestNodeConfigurationReplacerDoesNotProbeAfterTransactionalHostFailure(t *testing.T) {
	configuration := compiledNodeActivationFixture(t)
	hostErr := errors.New("restart failed and rolled back")
	host := &nodeReplacementHost{applyErr: hostErr}
	readiness := &nodeReplacementReadiness{}
	replacer, err := NewNodeConfigurationReplacer(host, readiness)
	if err != nil {
		t.Fatal(err)
	}
	err = replacer.Replace(context.Background(), configuration)
	if !errors.Is(err, hostErr) || errors.Is(err, ErrNodeConfigurationReplacementPending) {
		t.Fatalf("Replace() host error = %v", err)
	}
	if readiness.calls != 0 {
		t.Fatalf("readiness calls after rolled-back host failure = %d", readiness.calls)
	}
}

func TestPreparedNodeConfigurationReplacementCanBeDiscardedBeforeMutation(t *testing.T) {
	host := &nodeReplacementHost{}
	replacer, err := NewNodeConfigurationReplacer(host, &nodeReplacementReadiness{})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := replacer.Prepare(context.Background(), compiledNodeActivationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	prepared.Destroy()
	prepared.Destroy()
	if host.applyCalls != 0 {
		t.Fatalf("discarded plan mutated host %d times", host.applyCalls)
	}
	if err := replacer.Activate(context.Background(), prepared); err == nil || !strings.Contains(err.Error(), "already consumed") {
		t.Fatalf("Activate() after Destroy error = %v", err)
	}
}

type nodeReplacementHost struct {
	request    linuxplatform.RoleRepairRequest
	planCalls  int
	applyCalls int
	planErr    error
	applyErr   error
	plan       *linuxplatform.RoleRepairPlan
}

func (host *nodeReplacementHost) PlanRepair(
	_ context.Context,
	request linuxplatform.RoleRepairRequest,
) (*linuxplatform.RoleRepairPlan, error) {
	host.planCalls++
	host.request = cloneNodeReplacementRequest(request)
	if host.planErr != nil {
		return nil, host.planErr
	}
	host.plan = &linuxplatform.RoleRepairPlan{}
	return host.plan, nil
}

func (host *nodeReplacementHost) ApplyRepair(
	_ context.Context,
	plan *linuxplatform.RoleRepairPlan,
) (linuxplatform.RoleRepairResult, error) {
	host.applyCalls++
	if plan != host.plan {
		return linuxplatform.RoleRepairResult{}, errors.New("different replacement plan")
	}
	return linuxplatform.RoleRepairResult{}, host.applyErr
}

func cloneNodeReplacementRequest(request linuxplatform.RoleRepairRequest) linuxplatform.RoleRepairRequest {
	result := linuxplatform.RoleRepairRequest{
		Role: request.Role, Resources: make([]linuxplatform.RoleRepairResource, len(request.Resources)),
		RestartUnits: append([]string(nil), request.RestartUnits...),
	}
	for index, resource := range request.Resources {
		result.Resources[index] = resource
		result.Resources[index].Content = append([]byte(nil), resource.Content...)
	}
	return result
}

type nodeReplacementReadiness struct {
	calls      int
	generation uint64
	err        error
}

func (readiness *nodeReplacementReadiness) Check(_ context.Context, configuration NodeConfiguration) error {
	readiness.calls++
	readiness.generation = configuration.StateGeneration()
	return readiness.err
}
