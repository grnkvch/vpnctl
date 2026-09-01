package cli

import "testing"

func TestExitCodeForEveryResultCategory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		category ResultCategory
		want     int
	}{
		{category: ResultSuccess, want: 0},
		{category: ResultValidation, want: 2},
		{category: ResultConflict, want: 3},
		{category: ResultUnavailable, want: 4},
		{category: ResultInternal, want: 1},
	}
	for _, test := range tests {
		t.Run(string(test.category), func(t *testing.T) {
			if got := ExitCode(test.category); got != test.want {
				t.Fatalf("ExitCode(%q) = %d, want %d", test.category, got, test.want)
			}
		})
	}
}

func TestUnknownResultCategoryUsesInternalExitCode(t *testing.T) {
	t.Parallel()

	if got := ExitCode(ResultCategory("unknown")); got != ExitInternal {
		t.Fatalf("unknown result category exit code = %d, want %d", got, ExitInternal)
	}
}
