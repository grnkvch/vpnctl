package ingress

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

const (
	nginxTestExposeA = "10000000-0000-4000-8000-000000000001"
	nginxTestExposeB = "10000000-0000-4000-8000-000000000002"
	nginxTestExposeC = "10000000-0000-4000-8000-000000000003"
	nginxTestNodeA   = "20000000-0000-4000-8000-000000000001"
)

func TestNginxRendererEmitsBoundedStreamingLoopbackProxyTree(t *testing.T) {
	t.Parallel()
	request := nginxRenderFixture()
	request.Exposes = []model.Expose{
		nginxExposeFixture(nginxTestExposeB, "/api", model.RoutePrefix, 20001, model.ExposeDegraded),
		nginxExposeFixture(nginxTestExposeA, "/telegram/webhook", model.RouteExact, 20000, model.ExposeReady),
		nginxExposeFixture(nginxTestExposeC, "/disabled", model.RouteExact, 20002, model.ExposeDisabled),
		nginxExposeFixture("10000000-0000-4000-8000-000000000004", "/pending", model.RouteExact, 20003, model.ExposePending),
	}
	request.Exposes[0].Upstream = "192.0.2.50:4100"
	request.Exposes[0].BodyLimitBytes = 2 * 1024 * 1024
	request.Exposes[0].UpstreamTimeoutSeconds = 60

	candidate, err := RenderNginxConfig(request)
	if err != nil {
		t.Fatalf("RenderNginxConfig() error = %v", err)
	}
	if candidate.StateGeneration() != 7 || candidate.PublicIPv4() != "192.0.2.10" || candidate.ActiveExposeCount() != 2 || len(candidate.ConfigHash()) != 64 {
		t.Fatalf("candidate descriptor = generation %d, IP %q, active %d, hash %q", candidate.StateGeneration(), candidate.PublicIPv4(), candidate.ActiveExposeCount(), candidate.ConfigHash())
	}
	files := nginxArtifactContents(candidate)
	main := files[NginxMainConfigPath]
	routes := files[NginxRoutesConfigPath]
	common := files[NginxProxyCommonPath]

	for _, directive := range []string{
		"listen 0.0.0.0:443 ssl http2;", "ssl_protocols TLSv1.2 TLSv1.3;",
		"http2_max_concurrent_streams 64;", "worker_connections 256;",
		"limit_conn_zone $server_name zone=vpnctl_gateway:64k;",
		"limit_conn_zone $vpnctl_expose_key zone=vpnctl_expose:64k;",
		"map $host $vpnctl_expose_key { default \"\"; }",
		"large_client_header_buffers 4 8192;", "client_max_body_size 8388608;",
		"worker_shutdown_timeout 10s;", "access_log off;", "error_log /dev/null crit;",
		"error_page 502 =503 @vpnctl_unavailable;", "error_page 504 =504 @vpnctl_timeout;",
		"location @vpnctl_unavailable {", `return 503 '{"error":"service_unavailable"}';`,
		"location @vpnctl_timeout {", `return 504 '{"error":"gateway_timeout"}';`,
	} {
		if !strings.Contains(main, directive) {
			t.Errorf("main config lacks %q:\n%s", directive, main)
		}
	}
	for _, directive := range []string{
		`location = "/api"`, `location ^~ "/api/"`, `location = "/telegram/webhook"`,
		"proxy_pass http://127.0.0.1:20000;", "proxy_pass http://127.0.0.1:20001;",
		"client_max_body_size 2097152;", "proxy_read_timeout 60s;", "proxy_send_timeout 60s;",
		"limit_conn vpnctl_gateway 64;", "limit_conn vpnctl_expose 40;", "location / {\n    return 404;",
	} {
		if !strings.Contains(routes, directive) {
			t.Errorf("routes config lacks %q:\n%s", directive, routes)
		}
	}
	if strings.Contains(routes, "/disabled") || strings.Contains(routes, "/pending") || strings.Contains(routes, "127.0.0.1:20002") ||
		strings.Contains(routes, "127.0.0.1:20003") || strings.Contains(routes, "192.0.2.50") || strings.Contains(routes, ":4100") {
		t.Fatalf("routes exposed a disabled/pending route or node application endpoint:\n%s", routes)
	}
	if strings.Count(routes, "limit_conn vpnctl_gateway 64;") != 5 || strings.Count(routes, "limit_conn vpnctl_expose 40;") != 3 {
		t.Fatalf("every reserved/user proxy location must carry its applicable limits:\n%s", routes)
	}
	for _, directive := range []string{
		"proxy_http_version 1.1;", "proxy_request_buffering off;", "proxy_buffering off;",
		"proxy_max_temp_file_size 0;", "proxy_store off;", "proxy_cache off;",
		"proxy_next_upstream off;", "proxy_next_upstream_tries 1;", "proxy_intercept_errors off;",
		"proxy_redirect off;", "proxy_pass_request_body on;",
		`proxy_set_header Host "192.0.2.10";`, "proxy_set_header Authorization $http_authorization;", "proxy_set_header Forwarded \"\";",
		"proxy_set_header X-Forwarded-For $remote_addr;", `proxy_set_header X-Forwarded-Host "192.0.2.10";`,
		"proxy_set_header X-Forwarded-Port $server_port;", "proxy_set_header X-Forwarded-Proto $scheme;",
		"proxy_set_header X-Forwarded-Client-Cert \"\";", "proxy_set_header X-Real-IP $remote_addr;",
		"proxy_set_header Client-IP \"\";", "proxy_set_header X-Client-IP \"\";", "proxy_set_header Via \"\";", "proxy_set_header Connection \"\";",
		"proxy_set_header Upgrade \"\";", "proxy_set_header TE \"\";",
	} {
		if !strings.Contains(common, directive) {
			t.Errorf("proxy config lacks %q:\n%s", directive, common)
		}
	}
	combined := strings.ToLower(main + routes + common)
	for _, forbidden := range []string{"quic", "http3", "listen 0.0.0.0:443 udp", "$http_upgrade", "proxy_request_buffering on", "proxy_buffering on", "proxy_next_upstream on", "proxy_intercept_errors on", "proxy_pass https://"} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("configuration contains forbidden %q", forbidden)
		}
	}
	// A proxy_pass without a URI suffix is the nginx form that preserves the
	// original normalized path and query string.
	if strings.Contains(routes, "proxy_pass http://127.0.0.1:20000/") || strings.Contains(routes, "proxy_pass http://127.0.0.1:20001/") {
		t.Fatalf("proxy_pass rewrites the application URI:\n%s", routes)
	}
	for _, handler := range []string{"vpnctl_unavailable", "vpnctl_timeout"} {
		start := strings.Index(main, "location @"+handler+" {")
		if start < 0 {
			t.Fatalf("failure handler %s is absent:\n%s", handler, main)
		}
		end := strings.Index(main[start:], "        }\n")
		if end < 0 || strings.Contains(main[start:start+end], "proxy_pass") {
			t.Fatalf("failure handler %s can replay an upstream request:\n%s", handler, main[start:])
		}
	}
	if strings.Count(combined, "proxy_pass ") != strings.Count(routes, "proxy_pass ") {
		t.Fatalf("a proxy attempt escaped the route tree")
	}
	if strings.Contains(routes, "limit_req ") && strings.Count(routes, "limit_req ") != strings.Count(routes, "nodelay;") {
		t.Fatalf("a request-rate limit can queue instead of reject immediately:\n%s", routes)
	}
}

func TestNginxRendererIsDeterministicAndArtifactsAreImmutable(t *testing.T) {
	t.Parallel()
	request := nginxRenderFixture()
	request.Exposes = []model.Expose{
		nginxExposeFixture(nginxTestExposeB, "/second", model.RouteExact, 20001, model.ExposeReady),
		nginxExposeFixture(nginxTestExposeA, "/first", model.RouteExact, 20000, model.ExposeReady),
	}
	first, err := RenderNginxConfig(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Exposes[0], request.Exposes[1] = request.Exposes[1], request.Exposes[0]
	second, err := RenderNginxConfig(request)
	if err != nil {
		t.Fatal(err)
	}
	if first.ConfigHash() != second.ConfigHash() || !reflect.DeepEqual(first.Artifacts(), second.Artifacts()) {
		t.Fatal("renderer output depends on expose input order")
	}
	artifacts := first.Artifacts()
	if got := []string{artifacts[0].RelativePath(), artifacts[1].RelativePath(), artifacts[2].RelativePath()}; !reflect.DeepEqual(got, []string{NginxProxyCommonPath, NginxRoutesConfigPath, NginxMainConfigPath}) {
		t.Fatalf("artifact order = %#v", got)
	}
	for _, artifact := range artifacts {
		if artifact.Mode().Perm() != 0o600 {
			t.Fatalf("artifact %s mode = %o", artifact.RelativePath(), artifact.Mode().Perm())
		}
	}
	content := artifacts[0].Bytes()
	content[0] ^= 0xff
	if err := first.Validate(); err != nil {
		t.Fatalf("copied artifact mutated candidate: %v", err)
	}
	if _, err := json.Marshal(first); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("json.Marshal(candidate) error = %v", err)
	}
	first.artifacts[0].content[0] ^= 0xff
	if err := first.Validate(); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("tampered candidate validation error = %v", err)
	}
}

func TestNginxRendererQuotesPathsAndHandlesRootPrefix(t *testing.T) {
	t.Parallel()
	request := nginxRenderFixture()
	request.CertificatePath = `/etc/vpnctl/cert $public.pem`
	request.PrivateKeyPath = `/etc/vpnctl/key $private.pem`
	request.Exposes = []model.Expose{nginxExposeFixture(nginxTestExposeA, "/", model.RoutePrefix, 20000, model.ExposeReady)}
	candidate, err := RenderNginxConfig(request)
	if err != nil {
		t.Fatal(err)
	}
	files := nginxArtifactContents(candidate)
	if !strings.Contains(files[NginxMainConfigPath], `ssl_certificate "/etc/vpnctl/cert \$public.pem";`) ||
		!strings.Contains(files[NginxMainConfigPath], `ssl_certificate_key "/etc/vpnctl/key \$private.pem";`) {
		t.Fatalf("opaque paths are not safely quoted:\n%s", files[NginxMainConfigPath])
	}
	if strings.Count(files[NginxRoutesConfigPath], `location "/" {`) != 1 || strings.Contains(files[NginxRoutesConfigPath], "location / {\n    return 404;") {
		t.Fatalf("root prefix produced a duplicate fallback:\n%s", files[NginxRoutesConfigPath])
	}
}

func TestNginxReservedRoutesPrecedeAndCannotBeShadowedByUserRoot(t *testing.T) {
	t.Parallel()
	request := nginxRenderFixture()
	request.Exposes = []model.Expose{nginxExposeFixture(nginxTestExposeA, "/", model.RoutePrefix, 20000, model.ExposeReady)}
	candidate, err := RenderNginxConfig(request)
	if err != nil {
		t.Fatal(err)
	}
	routes := nginxArtifactContents(candidate)[NginxRoutesConfigPath]
	userRoot := strings.Index(routes, `location "/" {`)
	if userRoot < 0 {
		t.Fatalf("root expose is absent:\n%s", routes)
	}
	for _, path := range []string{model.ReservedEnrollmentPath, model.ReservedRecoveryPath, model.ReservedHealthPath} {
		location := `location = "` + path + `" {`
		index := strings.Index(routes, location)
		if index < 0 || index >= userRoot || strings.Count(routes, location) != 1 {
			t.Errorf("reserved location %q does not uniquely precede root expose:\n%s", path, routes)
		}
	}
	for _, directive := range []string{
		`location = "/.well-known/vpnctl" {`,
		`location ^~ "/.well-known/vpnctl/" {`,
		`return 404 '{"error":"not_found"}';`,
		"proxy_pass http://127.0.0.1:19092;",
		"client_max_body_size 65536;",
		"limit_req zone=vpnctl_enrollment burst=4 nodelay;",
		"proxy_read_timeout 5s;",
	} {
		if !strings.Contains(routes, directive) {
			t.Errorf("reserved route contract lacks %q:\n%s", directive, routes)
		}
	}
	if strings.Count(routes, "proxy_pass http://"+NginxEnrollmentUpstream+";") != 2 {
		t.Fatalf("enrollment and recovery do not share the exact private handler upstream:\n%s", routes)
	}
	healthStart := strings.Index(routes, `location = "`+model.ReservedHealthPath+`" {`)
	if healthStart < 0 {
		t.Fatalf("health route is absent:\n%s", routes)
	}
	healthEnd := strings.Index(routes[healthStart:], "}\n") + healthStart
	if healthEnd < healthStart || strings.Contains(routes[healthStart:healthEnd], "proxy_pass") ||
		!strings.Contains(routes[healthStart:healthEnd], "return 204;") {
		t.Fatalf("health route is not a detail-free edge response:\n%s", routes)
	}
}

func TestNginxRendererRejectsReservedEnrollmentPortCollision(t *testing.T) {
	t.Parallel()
	request := nginxRenderFixture()
	request.Exposes = []model.Expose{nginxExposeFixture(nginxTestExposeA, "/hook", model.RouteExact, NginxEnrollmentLoopbackPort, model.ExposeReady)}
	if _, err := RenderNginxConfig(request); err == nil || !strings.Contains(err.Error(), "reserved enrollment upstream") {
		t.Fatalf("reserved upstream collision error = %v", err)
	}
}

func TestNginxRendererRejectsInvalidOrAmbiguousInput(t *testing.T) {
	t.Parallel()
	base := nginxRenderFixture()
	base.Exposes = []model.Expose{nginxExposeFixture(nginxTestExposeA, "/first", model.RouteExact, 20000, model.ExposeReady)}
	for name, mutate := range map[string]func(*NginxRenderRequest){
		"zero generation":      func(value *NginxRenderRequest) { value.StateGeneration = 0 },
		"local public IP":      func(value *NginxRenderRequest) { value.PublicIPv4 = "127.0.0.1" },
		"relative certificate": func(value *NginxRenderRequest) { value.CertificatePath = "certificate.pem" },
		"dirty key path":       func(value *NginxRenderRequest) { value.PrivateKeyPath = "/etc/vpnctl/../key.pem" },
		"injected runtime":     func(value *NginxRenderRequest) { value.RuntimeDirectory = "/run/vpnctl\nuser root;" },
		"root runtime":         func(value *NginxRenderRequest) { value.RuntimeDirectory = "/" },
		"shared cert and key":  func(value *NginxRenderRequest) { value.PrivateKeyPath = value.CertificatePath },
		"changed hard limits":  func(value *NginxRenderRequest) { value.Limits.ConnectionLimit++ },
		"absent exposes":       func(value *NginxRenderRequest) { value.Exposes = nil },
		"invalid expose":       func(value *NginxRenderRequest) { value.Exposes[0].Path = "relative" },
		"weakened concurrency": func(value *NginxRenderRequest) { value.Exposes[0].ConcurrentRequests-- },
		"duplicate identity": func(value *NginxRenderRequest) {
			duplicate := value.Exposes[0]
			duplicate.Path, duplicate.TunnelPort = "/second", 20001
			value.Exposes = append(value.Exposes, duplicate)
		},
		"duplicate tunnel port": func(value *NginxRenderRequest) {
			duplicate := nginxExposeFixture(nginxTestExposeB, "/second", model.RouteExact, 20000, model.ExposeReady)
			value.Exposes = append(value.Exposes, duplicate)
		},
		"overlapping route": func(value *NginxRenderRequest) {
			value.Exposes[0].RouteMode = model.RoutePrefix
			value.Exposes = append(value.Exposes, nginxExposeFixture(nginxTestExposeB, "/first/child", model.RouteExact, 20001, model.ExposeReady))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := base
			request.Exposes = append([]model.Expose(nil), base.Exposes...)
			mutate(&request)
			if _, err := RenderNginxConfig(request); err == nil {
				t.Fatal("unsafe nginx input rendered")
			}
		})
	}
}

func TestValidatePinnedNginxConfigUsesExactBoundedCommand(t *testing.T) {
	t.Parallel()
	runner := &nginxProbeRunner{results: []linuxplatform.ProbeResult{
		{Stderr: []byte("nginx version: nginx/1.24.0\n")}, {},
	}}
	if err := ValidatePinnedNginxConfig(context.Background(), runner, "/usr/sbin/nginx", "/etc/vpnctl/generated/ingress/candidate"); err != nil {
		t.Fatalf("ValidatePinnedNginxConfig() error = %v", err)
	}
	want := []linuxplatform.ProbeCommand{
		{Name: "/usr/sbin/nginx", Args: []string{"-v"}},
		{Name: "/usr/sbin/nginx", Args: []string{"-t", "-p", "/etc/vpnctl/generated/ingress/candidate/", "-c", NginxMainConfigPath}},
	}
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("commands = %#v, want %#v", runner.commands, want)
	}

	for name, testCase := range map[string]struct {
		ctx    context.Context
		runner linuxplatform.ProbeRunner
		binary string
		root   string
	}{
		"nil context":     {nil, runner, "/usr/sbin/nginx", "/candidate"},
		"nil runner":      {context.Background(), nil, "/usr/sbin/nginx", "/candidate"},
		"relative binary": {context.Background(), runner, "nginx", "/candidate"},
		"dirty root":      {context.Background(), runner, "/usr/sbin/nginx", "/candidate/../tree"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePinnedNginxConfig(testCase.ctx, testCase.runner, testCase.binary, testCase.root); err == nil {
				t.Fatal("invalid validation request accepted")
			}
		})
	}
	wrongVersion := &nginxProbeRunner{results: []linuxplatform.ProbeResult{{Stderr: []byte("nginx version: nginx/1.24.1")}}}
	if err := ValidatePinnedNginxConfig(context.Background(), wrongVersion, "/usr/sbin/nginx", "/candidate"); err == nil || len(wrongVersion.commands) != 1 {
		t.Fatalf("wrong version result = %v, commands = %#v", err, wrongVersion.commands)
	}
	rejected := &nginxProbeRunner{results: []linuxplatform.ProbeResult{{Stderr: []byte("nginx version: nginx/1.24.0")}, {ExitCode: 1}}}
	if err := ValidatePinnedNginxConfig(context.Background(), rejected, "/usr/sbin/nginx", "/candidate"); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("rejected config error = %v", err)
	}
}

func TestNginxConstantsMatchAcceptedIngressManifest(t *testing.T) {
	t.Parallel()
	content, err := os.ReadFile(filepath.Join("..", "..", "test", "v2lab", "ingress", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Nginx struct {
			Version     string `json:"version"`
			SHA256      string `json:"package_sha256"`
			HTTP2Syntax string `json:"http2_syntax"`
		} `json:"nginx"`
		Listeners struct {
			Port int  `json:"public_https_tcp"`
			UDP  bool `json:"public_https_udp"`
		} `json:"listeners"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	if NginxProviderName != "nginx" || manifest.Nginx.Version != NginxProviderPackageVersion ||
		manifest.Nginx.SHA256 != NginxProviderPackageSHA256 || manifest.Nginx.HTTP2Syntax != "listen-parameter" ||
		manifest.Listeners.Port != NginxPublicHTTPSPort || manifest.Listeners.UDP {
		t.Fatalf("nginx provider constants differ from accepted manifest: %#v", manifest)
	}
}

func TestNginxConfigParsesWithPinnedNginx(t *testing.T) {
	binary := os.Getenv("VPNCTL_PINNED_NGINX")
	if binary == "" {
		t.Skip("set VPNCTL_PINNED_NGINX to the pinned Ubuntu nginx 1.24.0 binary")
	}
	root := t.TempDir()
	runtimeDirectory := filepath.Join(root, "run")
	for _, path := range []string{runtimeDirectory, filepath.Join(runtimeDirectory, "client-body"), filepath.Join(runtimeDirectory, "proxy"), filepath.Join(root, "secrets")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	material, err := GeneratePublicCertificate(rand.Reader, "192.0.2.10", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(root, "secrets", "gateway.crt")
	privateKeyPath := filepath.Join(root, "secrets", "gateway.key")
	if err := os.WriteFile(certificatePath, material.CertificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyPath, material.PrivateKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	request := nginxRenderFixture()
	request.CertificatePath = certificatePath
	request.PrivateKeyPath = privateKeyPath
	request.RuntimeDirectory = runtimeDirectory
	request.Exposes = []model.Expose{
		nginxExposeFixture(nginxTestExposeA, "/telegram/webhook", model.RouteExact, 20000, model.ExposeReady),
		nginxExposeFixture(nginxTestExposeB, "/api", model.RoutePrefix, 20001, model.ExposeReady),
		nginxExposeFixture(nginxTestExposeC, "/hooks/a$;b", model.RouteExact, 20002, model.ExposeReady),
	}
	candidate, err := RenderNginxConfig(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range candidate.Artifacts() {
		path := filepath.Join(root, filepath.FromSlash(artifact.RelativePath()))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, artifact.Bytes(), artifact.Mode()); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidatePinnedNginxConfig(context.Background(), linuxplatform.OSProbeRunner{}, binary, root); err != nil {
		t.Fatalf("native nginx validation failed: %v", err)
	}
}

type nginxProbeRunner struct {
	commands []linuxplatform.ProbeCommand
	results  []linuxplatform.ProbeResult
	err      error
}

func (runner *nginxProbeRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	runner.commands = append(runner.commands, command)
	if runner.err != nil {
		return linuxplatform.ProbeResult{}, runner.err
	}
	if len(runner.results) == 0 {
		return linuxplatform.ProbeResult{}, nil
	}
	result := runner.results[0]
	runner.results = runner.results[1:]
	return result, nil
}

func nginxRenderFixture() NginxRenderRequest {
	return NginxRenderRequest{
		StateGeneration:  7,
		PublicIPv4:       "192.0.2.10",
		CertificatePath:  "/etc/vpnctl/secrets/public-ingress.crt",
		PrivateKeyPath:   "/etc/vpnctl/secrets/public-ingress.key",
		RuntimeDirectory: "/run/vpnctl-ingress",
		Limits:           DefaultGatewayHardLimits(),
		Exposes:          []model.Expose{},
	}
}

func nginxExposeFixture(id, path string, mode model.RouteMode, port int, state model.ExposeState) model.Expose {
	return model.Expose{
		SchemaVersion: model.ResourceSchemaVersion,
		ID:            id, NodeID: nginxTestNodeA, Name: "expose-" + id[len(id)-1:],
		Upstream: "127.0.0.1:3000", RouteMode: mode, Path: path,
		BodyLimitBytes: DefaultExposeBodyLimitBytes, UpstreamTimeoutSeconds: DefaultExposeUpstreamTimeoutSeconds,
		ConcurrentRequests: DefaultExposeConcurrentRequests, TunnelPort: port, State: state, Generation: 1,
		CreatedAt: time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC),
	}
}

func nginxArtifactContents(candidate NginxCandidate) map[string]string {
	result := make(map[string]string, len(candidate.artifacts))
	for _, artifact := range candidate.Artifacts() {
		result[artifact.RelativePath()] = string(artifact.Bytes())
	}
	return result
}
