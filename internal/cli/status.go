package cli

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

// RunStatus uses the concrete passive collector so the command cannot be
// wired to an active doctor/probe implementation by satisfying a broad
// interface accidentally. The all flag affects human tables only; JSON data
// is complete in both modes.
func RunStatus(ctx context.Context, role HostRole, all bool, collector *operations.StatusCollector) (output.Result, error) {
	if ctx == nil {
		return output.Result{}, fmt.Errorf("context is required")
	}
	if collector == nil {
		return output.Result{}, fmt.Errorf("status collector is required")
	}
	var result output.Result
	err := V2CommandRegistry().Dispatch("status", role, func(CommandSpec) error {
		report, err := collector.Collect(ctx)
		if err != nil {
			return err
		}
		expectedRole, ok := convergenceApplyModelRole(role)
		if !ok || report.Role != expectedRole {
			return fmt.Errorf("status report role %q differs from command host role %q", report.Role, role)
		}
		result, err = statusResult(report, all)
		return err
	})
	return result, err
}

func statusResult(report operations.StatusReport, all bool) (output.Result, error) {
	if err := report.Validate(); err != nil {
		return output.Result{}, fmt.Errorf("validate status report: %w", err)
	}
	status, category, err := statusOutputState(report)
	if err != nil {
		return output.Result{}, err
	}
	result := output.NewResult("status", status, category, output.SafeObject{
		"role":                    string(report.Role),
		"overall":                 string(report.Overall),
		"generation":              report.Generation,
		"desired_generation":      report.DesiredGeneration,
		"applied_generation":      report.AppliedGeneration,
		"binary_version":          report.BinaryVersion,
		"manifest_binary_version": report.ManifestBinaryVersion,
		"control_protocols":       append([]string{}, report.ControlProtocols...),
		"components":              statusComponentsOutput(report.Components),
		"counts":                  statusCountsOutput(report.Counts),
		"resources":               statusResourcesOutput(report.Resources),
		"runtime":                 statusRuntimeOutput(report.Runtime),
		"pending":                 statusPendingOutput(report.Pending),
		"drift":                   statusDriftOutput(report.Drift),
		"active_invites":          statusInvitesOutput(report.ActiveInvites),
		"log_opt_ins":             statusLoggingOutput(report.LogOptIns),
		"certificates":            statusCertificatesOutput(report.Certificates),
		"backups":                 statusBackupsOutput(report.Backups),
		"problems":                statusProblemsOutput(report.Problems),
	})
	for _, warning := range report.Warnings {
		result.Warnings = append(result.Warnings, output.Message{
			Code: warning.Code, Message: warning.Message, ResourceIDs: statusNoticeResourceIDs(warning),
		})
	}
	for _, action := range report.RequiredActions {
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: action.Code, Message: action.Message, Command: action.Command, ResourceIDs: statusNoticeResourceIDs(action),
		})
	}
	if err := addStatusHumanTables(&result, report, all); err != nil {
		return output.Result{}, err
	}
	return result, result.Validate()
}

func statusOutputState(report operations.StatusReport) (output.Status, output.ExitCategory, error) {
	switch report.Category {
	case operations.StatusCategorySuccess:
		return output.StatusOK, output.CategorySuccess, nil
	case operations.StatusCategoryValidation:
		return output.StatusFailed, output.CategoryValidation, nil
	case operations.StatusCategoryConflict:
		return output.StatusDegraded, output.CategoryConflict, nil
	case operations.StatusCategoryUnavailable:
		return output.StatusDegraded, output.CategoryUnavailable, nil
	default:
		return "", "", fmt.Errorf("unsupported status category %q", report.Category)
	}
}

func statusComponentsOutput(values []operations.StatusComponent) []output.SafeObject {
	items := make([]output.SafeObject, len(values))
	for index, value := range values {
		items[index] = output.SafeObject{
			"name": value.Name, "version": value.Version, "bundled": value.Bundled,
			"sha256": value.SHA256, "capabilities": append([]string{}, value.Capabilities...),
		}
	}
	return items
}

func statusCountsOutput(values map[string]int) output.SafeObject {
	counts := make(output.SafeObject, len(values))
	for key, value := range values {
		counts[key] = value
	}
	return counts
}

func statusResourcesOutput(values []operations.StatusResource) []output.SafeObject {
	items := make([]output.SafeObject, len(values))
	for index, value := range values {
		item := output.SafeObject{"kind": value.Kind, "id": value.ID}
		statusAddString(item, "name", value.Name)
		statusAddString(item, "owner_kind", value.OwnerKind)
		statusAddString(item, "owner_id", value.OwnerID)
		statusAddString(item, "state", value.State)
		statusAddString(item, "active_transport", value.ActiveTransport)
		statusAddString(item, "provider", value.Provider)
		statusAddString(item, "operation_type", value.OperationType)
		statusAddString(item, "protocol", value.Protocol)
		statusAddString(item, "sha256", value.SHA256)
		statusAddInt(item, "port", value.Port)
		statusAddUint(item, "generation", value.Generation)
		statusAddUint(item, "expected_generation", value.ExpectedGeneration)
		statusAddUint(item, "desired_generation", value.DesiredGeneration)
		if value.Presets != nil {
			item["presets"] = append([]string{}, value.Presets...)
		}
		items[index] = item
	}
	return items
}

func statusRuntimeOutput(values []operations.PassiveStatusResource) []output.SafeObject {
	items := make([]output.SafeObject, len(values))
	for index, value := range values {
		item := output.SafeObject{
			"class": string(value.Class), "component": value.Resource.Component,
			"resource_kind": string(value.Resource.Kind), "resource_id": value.Resource.ID,
			"condition": string(value.Condition), "mandatory": value.Mandatory, "active": value.Active, "code": value.Code,
		}
		statusAddString(item, "version", value.Version)
		statusAddString(item, "protocol", value.Protocol)
		statusAddString(item, "runtime_sha256", value.RuntimeSHA256)
		statusAddUint(item, "generation", value.Generation)
		items[index] = item
	}
	return items
}

func statusPendingOutput(values []operations.StatusPendingChange) []output.SafeObject {
	items := make([]output.SafeObject, len(values))
	for index, value := range values {
		item := output.SafeObject{
			"operation_id": value.OperationID, "operation_type": value.OperationType,
			"operation_expected_generation": value.OperationExpectedGeneration,
			"operation_desired_generation":  value.OperationDesiredGeneration,
			"component":                     value.Resource.Component, "resource_kind": string(value.Resource.Kind),
			"resource_id": value.Resource.ID, "kind": string(value.Kind), "impact": string(value.Impact),
		}
		statusAddString(item, "target_kind", value.TargetKind)
		statusAddString(item, "target_id", value.TargetID)
		statusAddString(item, "from_sha256", value.FromSHA256)
		statusAddString(item, "to_sha256", value.ToSHA256)
		items[index] = item
	}
	return items
}

func statusDriftOutput(values []operations.StatusDrift) []output.SafeObject {
	items := make([]output.SafeObject, len(values))
	for index, value := range values {
		item := output.SafeObject{
			"component": value.Resource.Component, "resource_kind": string(value.Resource.Kind),
			"resource_id": value.Resource.ID, "kind": string(value.Kind), "impact": string(value.Impact),
		}
		statusAddString(item, "expected_sha256", value.ExpectedSHA256)
		statusAddString(item, "actual_sha256", value.ActualSHA256)
		items[index] = item
	}
	return items
}

func statusInvitesOutput(values []operations.StatusInvite) []output.SafeObject {
	items := make([]output.SafeObject, len(values))
	for index, value := range values {
		item := output.SafeObject{
			"id": value.ID, "node_name": value.NodeName,
			"issued_at": value.IssuedAt.UTC().Format(time.RFC3339), "expires_at": value.ExpiresAt.UTC().Format(time.RFC3339),
		}
		statusAddString(item, "purpose", value.Purpose)
		statusAddString(item, "node_id", value.NodeID)
		items[index] = item
	}
	return items
}

func statusLoggingOutput(values []operations.StatusLogOptIn) []output.SafeObject {
	items := make([]output.SafeObject, len(values))
	for index, value := range values {
		items[index] = output.SafeObject{
			"id": value.ID, "scope": string(value.Scope), "level": string(value.Level), "destination": string(value.Destination),
			"started_at": value.StartedAt.UTC().Format(time.RFC3339), "expires_at": value.ExpiresAt.UTC().Format(time.RFC3339),
		}
	}
	return items
}

func statusCertificatesOutput(values []operations.StatusCertificate) []output.SafeObject {
	items := make([]output.SafeObject, len(values))
	for index, value := range values {
		items[index] = output.SafeObject{
			"id": value.ID, "kind": string(value.Kind), "owner_kind": value.OwnerKind, "owner_id": value.OwnerID,
			"fingerprint": value.Fingerprint, "generation": value.Generation,
			"credential_generation": value.CredentialGeneration,
			"not_after":             value.NotAfter.UTC().Format(time.RFC3339),
			"warning_starts_at":     value.WarningStartsAt.UTC().Format(time.RFC3339), "condition": string(value.Condition),
		}
	}
	return items
}

func statusBackupsOutput(values []operations.StatusBackup) []output.SafeObject {
	items := make([]output.SafeObject, len(values))
	for index, value := range values {
		items[index] = output.SafeObject{
			"id": value.ID, "state": string(value.State), "format": value.Format, "sha256": value.SHA256,
			"size_bytes": value.SizeBytes, "state_generation": value.StateGeneration,
			"created_at": value.CreatedAt.UTC().Format(time.RFC3339),
		}
	}
	return items
}

func statusProblemsOutput(values []operations.StatusProblem) []output.SafeObject {
	items := make([]output.SafeObject, len(values))
	for index, value := range values {
		items[index] = output.SafeObject{
			"kind": value.Kind, "id": value.ID, "condition": string(value.Condition), "code": value.Code,
		}
	}
	return items
}

func statusNoticeResourceIDs(notice operations.StatusNotice) map[string]string {
	if notice.ResourceKind == "" || notice.ResourceID == "" {
		return nil
	}
	return map[string]string{notice.ResourceKind + "_id": notice.ResourceID}
}

func addStatusHumanTables(result *output.Result, report operations.StatusReport, all bool) error {
	problemRows := make([][]string, len(report.Problems))
	for index, problem := range report.Problems {
		problemRows[index] = []string{problem.Kind, problem.ID, string(problem.Condition), problem.Code}
	}
	if err := result.AddHumanTable("problems", []string{"kind", "id", "condition", "code"}, problemRows); err != nil {
		return err
	}
	if !all {
		return nil
	}
	componentRows := make([][]string, len(report.Components))
	for index, component := range report.Components {
		componentRows[index] = []string{component.Name, component.Version, component.SHA256}
	}
	if err := result.AddHumanTable("components", []string{"name", "version", "sha256"}, componentRows); err != nil {
		return err
	}
	runtimeRows := make([][]string, len(report.Runtime))
	for index, item := range report.Runtime {
		runtimeRows[index] = []string{string(item.Class), item.Resource.Component, item.Resource.ID, string(item.Condition), item.Code, statusGeneration(item.Generation), item.RuntimeSHA256}
	}
	if err := result.AddHumanTable("runtime", []string{"class", "component", "id", "condition", "code", "generation", "sha256"}, runtimeRows); err != nil {
		return err
	}
	resourceRows := make([][]string, len(report.Resources))
	for index, item := range report.Resources {
		resourceRows[index] = []string{item.Kind, item.ID, item.Name, item.State, statusGeneration(item.Generation), item.SHA256}
	}
	if err := result.AddHumanTable("resources", []string{"kind", "id", "name", "state", "generation", "sha256"}, resourceRows); err != nil {
		return err
	}
	pendingRows := make([][]string, len(report.Pending))
	for index, item := range report.Pending {
		pendingRows[index] = []string{item.OperationID, item.OperationType, item.Resource.Component, item.Resource.ID, string(item.Kind), string(item.Impact)}
	}
	if err := result.AddHumanTable("pending", []string{"operation_id", "operation_type", "component", "id", "kind", "impact"}, pendingRows); err != nil {
		return err
	}
	driftRows := make([][]string, len(report.Drift))
	for index, item := range report.Drift {
		driftRows[index] = []string{item.Resource.Component, string(item.Resource.Kind), item.Resource.ID, string(item.Kind), string(item.Impact)}
	}
	if err := result.AddHumanTable("drift", []string{"component", "resource_kind", "id", "kind", "impact"}, driftRows); err != nil {
		return err
	}
	inviteRows := make([][]string, len(report.ActiveInvites))
	for index, item := range report.ActiveInvites {
		inviteRows[index] = []string{item.ID, item.Purpose, item.NodeName, item.ExpiresAt.UTC().Format(time.RFC3339)}
	}
	if err := result.AddHumanTable("active_invites", []string{"id", "purpose", "node_name", "expires_at"}, inviteRows); err != nil {
		return err
	}
	loggingRows := make([][]string, len(report.LogOptIns))
	for index, item := range report.LogOptIns {
		loggingRows[index] = []string{item.ID, string(item.Scope), string(item.Level), string(item.Destination), item.ExpiresAt.UTC().Format(time.RFC3339)}
	}
	if err := result.AddHumanTable("log_opt_ins", []string{"id", "scope", "level", "destination", "expires_at"}, loggingRows); err != nil {
		return err
	}
	certificateRows := make([][]string, len(report.Certificates))
	for index, item := range report.Certificates {
		certificateRows[index] = []string{item.ID, string(item.Kind), string(item.Condition), item.NotAfter.UTC().Format(time.RFC3339), item.Fingerprint}
	}
	if err := result.AddHumanTable("certificates", []string{"id", "kind", "condition", "not_after", "fingerprint"}, certificateRows); err != nil {
		return err
	}
	backupRows := make([][]string, len(report.Backups))
	for index, item := range report.Backups {
		backupRows[index] = []string{item.ID, item.CreatedAt.UTC().Format(time.RFC3339), statusGeneration(item.StateGeneration), item.SHA256}
	}
	return result.AddHumanTable("backups", []string{"id", "created_at", "state_generation", "sha256"}, backupRows)
}

func statusAddString(item output.SafeObject, key, value string) {
	if value != "" {
		item[key] = value
	}
}

func statusAddUint(item output.SafeObject, key string, value uint64) {
	if value != 0 {
		item[key] = value
	}
}

func statusAddInt(item output.SafeObject, key string, value int) {
	if value != 0 {
		item[key] = value
	}
}

func statusGeneration(value uint64) string {
	if value == 0 {
		return "-"
	}
	return strconv.FormatUint(value, 10)
}
