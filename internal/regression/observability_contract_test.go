package regression

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestOperationalLoggingIsConnectedAtEverySourceBoundary(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	files := []string{
		"internal/controller/process.go",
		"internal/transport/standard_service.go",
		"internal/transport/restricted_service.go",
		"internal/routing/node_service.go",
		"internal/routing/gateway_dns_service.go",
		"internal/tunnel/service.go",
		"internal/tunnel/authorization.go",
		"internal/ingress/nginx_activation.go",
	}
	for _, relative := range files {
		source, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)
		if !strings.Contains(text, "internal/observability") || !strings.Contains(text, "observability.") {
			t.Errorf("%s bypasses the shared source-redacted event boundary", relative)
		}
	}
}

func TestProviderAndServerRawLogsCannotBypassRedaction(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	for _, relative := range []string{
		"internal/transport/restricted_service.go",
		"internal/routing/node_service.go",
		"internal/tunnel/service.go",
		"internal/tunnel/configuration.go",
		"internal/ingress/nginx_activation.go",
	} {
		requireSourceFragments(t, root, relative, "command.Stdout = io.Discard", "command.Stderr = io.Discard")
	}
	for _, relative := range []string{
		"internal/transport/restricted_config.go",
		"internal/routing/node_config.go",
	} {
		requireSourceFragments(t, root, relative, "log-level: silent", "geo-auto-update: false")
	}
	requireSourceFragments(t, root, "internal/ingress/nginx.go", "error_log /dev/null crit;", "access_log off;")
	requireSourceFragments(t, root, "internal/control/rpc_server.go", "log.New(io.Discard")
	requireSourceFragments(t, root, "internal/tunnel/authorization.go", "log.New(io.Discard")
}

func TestOperationalLoggingHasNoNetworkCapabilityOrBakedExternalEndpoint(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	for _, relative := range []string{"internal/observability/event.go", "internal/operations/component_logging.go"} {
		parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, relative), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range parsed.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			switch path {
			case "net", "net/http", "net/url", "os/exec":
				t.Errorf("%s has forbidden logging-side network/process capability %q", relative, path)
			}
		}
	}

	for _, directory := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(parsed, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					return true
				}
				lower := strings.ToLower(value)
				if hasLiteralURLHost(lower) {
					t.Errorf("%s contains baked network endpoint %q", path, value)
				}
				if strings.Contains(lower, "analytics endpoint") || strings.Contains(lower, "telemetry endpoint") || strings.Contains(lower, "update-check endpoint") {
					t.Errorf("%s contains hidden-call endpoint marker", path)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func requireSourceFragments(t *testing.T, root, relative string, fragments ...string) {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range fragments {
		if !strings.Contains(string(source), fragment) {
			t.Errorf("%s omits safeguard %q", relative, fragment)
		}
	}
}

func hasLiteralURLHost(value string) bool {
	for _, prefix := range []string{"http://", "https://"} {
		index := strings.Index(value, prefix)
		if index < 0 {
			continue
		}
		remainder := value[index+len(prefix):]
		if remainder != "" && remainder[0] != '%' && remainder[0] != '"' &&
			!strings.HasPrefix(remainder, "127.0.0.1:") && !strings.HasPrefix(remainder, "localhost:") &&
			!strings.HasPrefix(remainder, "[::1]:") {
			return true
		}
	}
	return false
}
