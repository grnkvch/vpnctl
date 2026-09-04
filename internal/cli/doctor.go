package cli

import (
	"context"
	"fmt"
	"strconv"

	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func RunDoctor(ctx context.Context, role HostRole, scope operations.DoctorScope, doctor *operations.Doctor) (output.Result, error) {
	if ctx == nil {
		return output.Result{}, fmt.Errorf("context is required")
	}
	if doctor == nil {
		return output.Result{}, fmt.Errorf("doctor is required")
	}
	var result output.Result
	err := V2CommandRegistry().Dispatch("doctor", role, func(CommandSpec) error {
		report, err := doctor.Run(ctx, scope)
		if err != nil {
			return err
		}
		expectedRole, ok := convergenceApplyModelRole(role)
		if !ok || report.Role != expectedRole {
			return fmt.Errorf("doctor report role %q differs from command host role %q", report.Role, role)
		}
		result, err = doctorResult(report)
		return err
	})
	return result, err
}

func doctorResult(report operations.DoctorReport) (output.Result, error) {
	if err := report.Validate(); err != nil {
		return output.Result{}, fmt.Errorf("validate doctor report: %w", err)
	}
	status, category := output.StatusOK, output.CategorySuccess
	if report.Overall == operations.StatusOverallDegraded {
		status, category = output.StatusDegraded, output.CategoryUnavailable
	}
	checks := make([]output.SafeObject, len(report.Checks))
	rows := make([][]string, len(report.Checks))
	for index, check := range report.Checks {
		checks[index] = output.SafeObject{
			"name": check.Name, "scope": string(check.Scope), "kind": string(check.Kind), "protocol": string(check.Protocol),
			"resource_kind": check.ResourceKind, "resource_id": check.ResourceID, "status": string(check.Status),
			"code": check.Code, "elapsed_ms": check.ElapsedMS,
		}
		rows[index] = []string{
			check.Name, string(check.Protocol), string(check.Status), check.Code, strconv.FormatInt(check.ElapsedMS, 10),
		}
	}
	result := output.NewResult("doctor", status, category, output.SafeObject{
		"role": string(report.Role), "scope": string(report.Scope), "run_id": report.RunID,
		"overall": string(report.Overall), "checks": checks,
	})
	for _, check := range report.Checks {
		if check.Status != operations.DoctorCheckFailed {
			continue
		}
		result.Warnings = append(result.Warnings, output.Message{
			Code: "doctor_check_failed", Message: fmt.Sprintf("Doctor check %s failed with code %s.", check.Name, check.Code),
			ResourceIDs: map[string]string{check.ResourceKind + "_id": check.ResourceID},
		})
	}
	if err := result.AddHumanTable("checks", []string{"name", "protocol", "status", "code", "elapsed_ms"}, rows); err != nil {
		return output.Result{}, err
	}
	return result, result.Validate()
}
