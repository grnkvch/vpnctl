package operations

import (
	"context"
	"path/filepath"
	"testing"
)

type recordingAppliedMaterialEnsurer struct {
	calls        int
	discardCalls int
	err          error
}

func (ensurer *recordingAppliedMaterialEnsurer) Discard(
	_ context.Context,
	_ ConvergenceManifest,
) (bool, error) {
	ensurer.discardCalls++
	return true, ensurer.err
}

func (ensurer *recordingAppliedMaterialEnsurer) Ensure(
	_ context.Context,
	applied ConvergenceManifest,
	material *AppliedMaterialSet,
) (AppliedMaterialID, error) {
	ensurer.calls++
	if ensurer.err != nil {
		return "", ensurer.err
	}
	want, err := AppliedMaterialIDFor(applied)
	if err != nil || material == nil || material.ID() != want {
		return "", ErrAppliedMaterialInvalid
	}
	return want, nil
}

func newConvergenceAppliedMaterialArchive(t *testing.T, convergencePath string) *FileAppliedMaterialArchive {
	t.Helper()
	archive, err := NewFileAppliedMaterialArchive(filepath.Join(filepath.Dir(convergencePath), "applied-material"))
	if err != nil {
		t.Fatal(err)
	}
	return archive
}
