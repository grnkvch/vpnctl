package cli

// ResultCategory is the stable v2 process-result category used by every public command.
type ResultCategory string

const (
	ResultSuccess     ResultCategory = "success"
	ResultValidation  ResultCategory = "validation"
	ResultConflict    ResultCategory = "conflict"
	ResultUnavailable ResultCategory = "unavailable"
	ResultInternal    ResultCategory = "internal"
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
