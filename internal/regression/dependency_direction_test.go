package regression

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestV2PackageDependencyDirection(t *testing.T) {
	t.Parallel()

	const module = "github.com/vgrinkevich/vpnctl"
	tiers := map[string]int{
		module + "/internal/model":          0,
		module + "/internal/store":          1,
		module + "/internal/platform/linux": 1,
		module + "/internal/render":         1,
		module + "/internal/output":         1,
		module + "/internal/observability":  1,
		module + "/internal/restricted":     1,
		module + "/internal/control":        2,
		module + "/internal/transport":      2,
		module + "/internal/routing":        2,
		module + "/internal/ingress":        2,
		module + "/internal/tunnel":         2,
		module + "/internal/enrollment":     3,
		module + "/internal/operations":     3,
		module + "/internal/lifecycle":      3,
		module + "/internal/controller":     4,
		module + "/internal/cli":            5,
	}

	repositoryRoot := filepath.Join("..", "..")
	for packagePath := range tiers {
		relative := strings.TrimPrefix(packagePath, module+"/")
		if info, err := os.Stat(filepath.Join(repositoryRoot, filepath.FromSlash(relative))); err != nil || !info.IsDir() {
			t.Errorf("v2 package boundary is missing: %s", packagePath)
		}
	}

	internalRoot := filepath.Join(repositoryRoot, "internal")
	err := filepath.WalkDir(internalRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		relativeDir, err := filepath.Rel(repositoryRoot, filepath.Dir(path))
		if err != nil {
			return err
		}
		source := module + "/" + filepath.ToSlash(relativeDir)
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range parsed.Imports {
			target, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if target == module+"/internal/cli" && source != target {
				t.Errorf("%s imports outer CLI package %s", source, target)
			}
			if strings.HasPrefix(target, module+"/cmd/") {
				t.Errorf("internal package %s imports command package %s", source, target)
			}
			sourceTier, sourceIsV2 := tiers[source]
			targetTier, targetIsV2 := tiers[target]
			firstImportSegment := strings.Split(target, "/")[0]
			if source == module+"/internal/model" && strings.Contains(firstImportSegment, ".") {
				t.Errorf("model package imports non-standard package %s", target)
			}
			if sourceIsV2 && targetIsV2 && targetTier >= sourceTier {
				t.Errorf("invalid v2 dependency %s (tier %d) -> %s (tier %d)", source, sourceTier, target, targetTier)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("inspect Go dependency direction: %v", err)
	}
}
