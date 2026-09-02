package cli

import "github.com/vgrinkevich/vpnctl/internal/output"

// ResultCategory is the stable v2 process-result category used by every public command.
type ResultCategory = output.ExitCategory

const (
	ResultSuccess     ResultCategory = output.CategorySuccess
	ResultValidation  ResultCategory = output.CategoryValidation
	ResultConflict    ResultCategory = output.CategoryConflict
	ResultUnavailable ResultCategory = output.CategoryUnavailable
	ResultInternal    ResultCategory = output.CategoryInternal
)

const (
	ExitSuccess     = 0
	ExitInternal    = 1
	ExitValidation  = 2
	ExitConflict    = 3
	ExitUnavailable = 4
)

// ExitCode returns the frozen v2 process exit code for a result category.
// Unknown categories are internal contract errors and therefore fail with ExitInternal.
func ExitCode(category ResultCategory) int {
	switch category {
	case ResultSuccess:
		return ExitSuccess
	case ResultValidation:
		return ExitValidation
	case ResultConflict:
		return ExitConflict
	case ResultUnavailable:
		return ExitUnavailable
	case ResultInternal:
		return ExitInternal
	default:
		return ExitInternal
	}
}
