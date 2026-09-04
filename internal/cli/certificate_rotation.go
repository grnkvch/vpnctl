package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

type PublicCertificateRotator interface {
	Plan(context.Context) (operations.PublicCertificateRotationPlan, error)
	Apply(context.Context, operations.PublicCertificateRotationPlan) (operations.PublicCertificateRotationResult, error)
}

type PublicCertificateRotationWorkflow struct {
	rotator PublicCertificateRotator

	mu      sync.Mutex
	planned *operations.PublicCertificateRotationPlan
}

func NewPublicCertificateRotationWorkflow(rotator PublicCertificateRotator) (*PublicCertificateRotationWorkflow, error) {
	if rotator == nil {
		return nil, fmt.Errorf("public certificate rotator is required")
	}
	return &PublicCertificateRotationWorkflow{rotator: rotator}, nil
}

func (workflow *PublicCertificateRotationWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if ctx == nil || workflow == nil || workflow.rotator == nil {
		return MutationPlan{}, fmt.Errorf("public certificate rotation workflow is incomplete")
	}
	plan, err := workflow.rotator.Plan(ctx)
	if err != nil {
		return MutationPlan{}, err
	}
	result, err := publicCertificateRotationPlanOutput(plan)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.mu.Lock()
	retained := plan
	workflow.planned = &retained
	workflow.mu.Unlock()
	return MutationPlan{Impact: ImpactAvailability, Result: result}, nil
}

func (workflow *PublicCertificateRotationWorkflow) Apply(
	ctx context.Context,
	publicPlan MutationPlan,
	_ *InteractionInputs,
) (AppliedMutation, error) {
	domainPlan, err := workflow.retainedPlan(publicPlan)
	if err != nil {
		return AppliedMutation{}, err
	}
	rotated, err := workflow.rotator.Apply(ctx, domainPlan)
	if err != nil {
		return AppliedMutation{}, err
	}
	result, err := publicCertificateRotationResultOutput(rotated)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: result}, nil
}

func (workflow *PublicCertificateRotationWorkflow) retainedPlan(publicPlan MutationPlan) (operations.PublicCertificateRotationPlan, error) {
	if workflow == nil || workflow.rotator == nil {
		return operations.PublicCertificateRotationPlan{}, fmt.Errorf("public certificate rotation workflow is incomplete")
	}
	workflow.mu.Lock()
	defer workflow.mu.Unlock()
	if workflow.planned == nil || publicPlan.Impact != ImpactAvailability || publicPlan.Result.Command != "cert.rotate" ||
		publicPlan.Result.ResourceIDs["certificate_id"] != workflow.planned.CurrentCertificate.ID {
		return operations.PublicCertificateRotationPlan{}, fmt.Errorf("%w: public certificate plan does not match retained domain plan", ErrInvalidMutationPlan)
	}
	return *workflow.planned, nil
}

func publicCertificateRotationPlanOutput(plan operations.PublicCertificateRotationPlan) (output.Result, error) {
	if err := plan.Validate(); err != nil {
		return output.Result{}, err
	}
	result := output.NewResult("cert.rotate", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": false, "impact": "availability", "generation": plan.NextStateGeneration,
		"current_fingerprint":         plan.CurrentCertificate.Fingerprint,
		"next_certificate_generation": plan.NextCertificateGeneration,
		"affected_exposes":            publicCertificateAffectedOutput(plan.AffectedExposes),
		"output_path":                 plan.CertificateExportPath,
	})
	result.ResourceIDs["certificate_id"] = plan.CurrentCertificate.ID
	addCertificateReregistrationActions(&result, plan.AffectedExposes, true)
	return result, result.Validate()
}

func publicCertificateRotationResultOutput(result operations.PublicCertificateRotationResult) (output.Result, error) {
	if result.StateGeneration == 0 || result.CertificateGeneration == 0 || result.CertificateID == "" ||
		result.CurrentFingerprint == "" || result.CertificateExportPath == "" || result.PublicIPv4 == "" {
		return output.Result{}, fmt.Errorf("public certificate rotation result is incomplete")
	}
	commandResult := output.NewResult("cert.rotate", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": true, "generation": result.StateGeneration,
		"certificate_generation":          result.CertificateGeneration,
		"previous_certificate_generation": result.PreviousCertificateGeneration,
		"previous_fingerprint":            result.PreviousFingerprint, "fingerprint": result.CurrentFingerprint,
		"affected_exposes": publicCertificateAffectedOutput(result.AffectedExposes),
		"output_path":      result.CertificateExportPath,
		"scp_command":      "scp root@" + result.PublicIPv4 + ":" + result.CertificateExportPath + " ./" + filepath.Base(result.CertificateExportPath),
	})
	commandResult.ResourceIDs["certificate_id"] = result.CertificateID
	addCertificateReregistrationActions(&commandResult, result.AffectedExposes, false)
	return commandResult, commandResult.Validate()
}

func publicCertificateAffectedOutput(exposes []operations.PublicCertificateAffectedExpose) output.SafeList {
	items := make(output.SafeList, 0, len(exposes))
	for _, expose := range exposes {
		items = append(items, output.SafeObject{
			"id": expose.ID, "node_id": expose.NodeID, "name": expose.Name, "state": string(expose.State),
		})
	}
	return items
}

func addCertificateReregistrationActions(
	result *output.Result,
	exposes []operations.PublicCertificateAffectedExpose,
	afterRotation bool,
) {
	for _, expose := range exposes {
		message := "Re-register this external webhook with the new public certificate."
		if afterRotation {
			message = "After rotation, re-register this external webhook with the new public certificate."
		}
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "reregister_external_webhook", Message: message,
			ResourceIDs: map[string]string{"expose_id": expose.ID, "node_id": expose.NodeID},
		})
	}
}

var _ MutationWorkflow = (*PublicCertificateRotationWorkflow)(nil)
