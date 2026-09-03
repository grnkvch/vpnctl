package cli

import (
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/routing"
)

// ClassificationStatusOutput is the task-10.10 status slice. The complete
// status assembler in task 13.6 can merge its resource and warnings without
// reinterpreting or overstating the fail-closed boundary.
func ClassificationStatusOutput(role model.Role, generation uint64, report routing.ClassificationBoundary) output.Result {
	result := output.NewResult("status", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"role": string(role), "overall": "healthy", "generation": generation,
		"resources": []output.SafeObject{{
			"kind": "classification_boundary", "condition": "bounded", "details": report.SafeObject(),
		}},
	})
	result.Warnings = append(result.Warnings, report.Warnings()...)
	return result
}

// ClassificationDoctorOutput contributes a non-network informational check.
// No probe, endpoint lookup, provider list, or firewall mutation is performed.
func ClassificationDoctorOutput(report routing.ClassificationBoundary) output.Result {
	result := output.NewResult("doctor", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"scope": "default",
		"checks": []output.SafeObject{{
			"name": "policy_classification_boundary", "status": "passed",
			"detail":                  "Fail-closed starts after a selector match; independent DoH or DoT and unmatched hardcoded IP destinations remain direct.",
			"classification_boundary": report.SafeObject(),
		}},
	})
	result.Warnings = append(result.Warnings, report.Warnings()...)
	return result
}
