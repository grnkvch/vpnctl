package cli

import (
	"fmt"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

// NodeCertificateStatusOutput is the task-9.8 certificate slice of status.
// The full status assembler in task 13.6 can merge its resources, warnings,
// and actions without reimplementing certificate lifetime semantics.
func NodeCertificateStatusOutput(report enrollment.NodeCertificateReport) output.Result {
	status, category, overall := certificateResultState(report)
	resources := make([]output.SafeObject, 0, len(report.Items))
	result := output.NewResult("status", status, category, output.SafeObject{
		"role": string(report.Role), "overall": overall, "generation": report.StateGeneration,
		"resources": resources,
	})
	for _, item := range report.Items {
		resources = append(resources, nodeCertificateResource(item))
		appendNodeCertificateMessages(&result, report.Role, item)
	}
	result.Data["resources"] = resources
	return result
}

// NodeCertificateDoctorOutput contributes the non-network control-certificate
// prerequisite to doctor. Expiry is a failed check; an in-window certificate
// still passes because mTLS remains usable, but carries the required action.
func NodeCertificateDoctorOutput(report enrollment.NodeCertificateReport) output.Result {
	status, category, _ := certificateResultState(report)
	checks := make([]output.SafeObject, 0, len(report.Items))
	result := output.NewResult("doctor", status, category, output.SafeObject{
		"scope": "default", "checks": checks,
	})
	for _, item := range report.Items {
		checkStatus := "passed"
		if item.Condition == enrollment.NodeCertificateExpired {
			checkStatus = "failed"
		}
		checks = append(checks, output.SafeObject{
			"name": "node_control_certificate:" + item.NodeID, "status": checkStatus,
			"detail": nodeCertificateDetail(item),
		})
		appendNodeCertificateMessages(&result, report.Role, item)
	}
	result.Data["checks"] = checks
	return result
}

func certificateResultState(report enrollment.NodeCertificateReport) (output.Status, output.ExitCategory, string) {
	for _, item := range report.Items {
		if item.Condition == enrollment.NodeCertificateExpired {
			return output.StatusDegraded, output.CategoryUnavailable, "degraded"
		}
	}
	return output.StatusOK, output.CategorySuccess, "healthy"
}

func nodeCertificateResource(item enrollment.NodeCertificateHealth) output.SafeObject {
	return output.SafeObject{
		"kind": "node_control_certificate", "node_id": item.NodeID, "node_name": item.NodeName,
		"certificate_id": item.CertificateID, "fingerprint": item.Fingerprint,
		"credential_generation": item.CredentialGeneration, "condition": string(item.Condition),
		"not_after":         item.NotAfter.UTC().Format(time.RFC3339),
		"warning_starts_at": item.WarningStartsAt.UTC().Format(time.RFC3339), "warning_days": item.WarningDays,
	}
}

func nodeCertificateDetail(item enrollment.NodeCertificateHealth) string {
	switch item.Condition {
	case enrollment.NodeCertificateExpired:
		return fmt.Sprintf("Node %s control certificate expired at %s; ordinary rotation is unavailable.", item.NodeName, item.NotAfter.UTC().Format(time.RFC3339))
	case enrollment.NodeCertificateExpiring:
		return fmt.Sprintf("Node %s control certificate is valid until %s; credential rotation is required before expiry.", item.NodeName, item.NotAfter.UTC().Format(time.RFC3339))
	default:
		return fmt.Sprintf("Node %s control certificate is valid until %s.", item.NodeName, item.NotAfter.UTC().Format(time.RFC3339))
	}
}

func appendNodeCertificateMessages(result *output.Result, role model.Role, item enrollment.NodeCertificateHealth) {
	if result == nil || item.Condition == enrollment.NodeCertificateHealthy {
		return
	}
	resourceIDs := map[string]string{"node_id": item.NodeID, "certificate_id": item.CertificateID}
	if item.Condition == enrollment.NodeCertificateExpiring {
		result.Warnings = append(result.Warnings, output.Message{
			Code:        "node_certificate_expiring",
			Message:     fmt.Sprintf("Node %s control certificate expires at %s.", item.NodeName, item.NotAfter.UTC().Format(time.RFC3339)),
			ResourceIDs: resourceIDs,
		})
		action := output.Action{
			Code:        "rotate_node_credentials",
			Message:     "Rotate the complete node credential set before the control certificate expires.",
			Command:     "sudo vpnctl node rotate",
			ResourceIDs: resourceIDs,
		}
		if role == model.RoleGateway {
			action.Message = fmt.Sprintf("On private node %s, rotate the complete credential set before the control certificate expires.", item.NodeName)
		}
		result.RequiresAction = append(result.RequiresAction, action)
		return
	}

	result.Warnings = append(result.Warnings, output.Message{
		Code:        "node_certificate_expired",
		Message:     fmt.Sprintf("Node %s control certificate expired at %s; ordinary rotation is unavailable.", item.NodeName, item.NotAfter.UTC().Format(time.RFC3339)),
		ResourceIDs: resourceIDs,
	})
	if role == model.RoleGateway {
		result.RequiresAction = append(result.RequiresAction,
			output.Action{
				Code: "issue_node_recovery", Message: "Issue a one-time recovery token for the existing immutable node identity.",
				Command: "sudo vpnctl node recover " + item.NodeID, ResourceIDs: resourceIDs,
			},
			output.Action{
				Code: "recover_node_credentials", Message: "Then enter the one-time recovery token on the original private node.",
				Command: "sudo vpnctl node recover", ResourceIDs: resourceIDs,
			},
		)
		return
	}
	result.RequiresAction = append(result.RequiresAction,
		output.Action{
			Code: "request_node_recovery", Message: "On the gateway, issue a one-time recovery token for this immutable node identity.",
			Command: "sudo vpnctl node recover " + item.NodeID, ResourceIDs: resourceIDs,
		},
		output.Action{
			Code: "recover_node_credentials", Message: "Enter the one-time recovery token on this original private node.",
			Command: "sudo vpnctl node recover", ResourceIDs: resourceIDs,
		},
	)
}
