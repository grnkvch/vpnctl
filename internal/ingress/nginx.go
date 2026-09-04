package ingress

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

const (
	NginxProviderName           = "nginx"
	NginxProviderRuntimeVersion = "1.24.0"
	NginxProviderPackageVersion = "1.24.0-2ubuntu7.17"
	NginxProviderPackageSHA256  = "84bd95140500fa4d10e11383eac5c864ea7dff24fcca80c442b8449fcc65240c"

	NginxMainConfigPath             = "nginx.conf"
	NginxProxyCommonPath            = "conf.d/proxy-common.conf"
	NginxRoutesConfigPath           = "conf.d/routes.conf"
	NginxPublicHTTPSPort            = 443
	NginxEnrollmentLoopbackPort     = 19092
	NginxEnrollmentUpstream         = "127.0.0.1:19092"
	NginxEnrollmentMaximumBodyBytes = 64 * 1024
	NginxEnrollmentTimeoutSeconds   = 5
	nginxSharedZoneBytes            = 64 * 1024
	nginxEnrollmentZoneBytes        = 64 * 1024
	nginxMaximumTreeBytes           = 32 * 1024 * 1024
	nginxConnectTimeoutSeconds      = 2
	nginxClientTimeoutSeconds       = 10
	nginxKeepaliveSeconds           = 15
	nginxKeepaliveRequests          = 100
)

type NginxRenderRequest struct {
	StateGeneration  uint64
	PublicIPv4       string
	CertificatePath  string
	PrivateKeyPath   string
	RuntimeDirectory string
	Limits           GatewayHardLimits
	Exposes          []model.Expose
}

// NginxArtifact is one immutable file in a complete generated configuration
// tree. Content is copied on access so validation and activation cannot mutate
// the renderer's hash after publication.
type NginxArtifact struct {
	path    string
	mode    fs.FileMode
	content []byte
}

func (artifact NginxArtifact) RelativePath() string { return artifact.path }
func (artifact NginxArtifact) Mode() fs.FileMode    { return artifact.mode }
func (artifact NginxArtifact) Bytes() []byte        { return append([]byte(nil), artifact.content...) }

type NginxCandidate struct {
	stateGeneration  uint64
	publicIPv4       string
	runtimeDirectory string
	configHash       string
	activeExposes    int
	artifacts        []NginxArtifact
}

func (NginxCandidate) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

func (candidate NginxCandidate) StateGeneration() uint64 { return candidate.stateGeneration }
func (candidate NginxCandidate) PublicIPv4() string      { return candidate.publicIPv4 }
func (candidate NginxCandidate) ConfigHash() string      { return candidate.configHash }
func (candidate NginxCandidate) ActiveExposeCount() int  { return candidate.activeExposes }

func (candidate NginxCandidate) Artifacts() []NginxArtifact {
	result := make([]NginxArtifact, len(candidate.artifacts))
	for index, artifact := range candidate.artifacts {
		result[index] = NginxArtifact{path: artifact.path, mode: artifact.mode, content: artifact.Bytes()}
	}
	return result
}

// RenderNginxConfig renders a complete provider-owned tree. It consumes only
// canonical model values and opaque filesystem paths; raw nginx directives are
// not part of this API.
func RenderNginxConfig(request NginxRenderRequest) (NginxCandidate, error) {
	active, err := validateNginxRenderRequest(request)
	if err != nil {
		return NginxCandidate{}, err
	}

	proxyCommon := renderNginxProxyCommon(request.PublicIPv4)
	routes := renderNginxRoutes(active)
	main := renderNginxMain(request)
	artifacts := []NginxArtifact{
		{path: NginxProxyCommonPath, mode: 0o600, content: proxyCommon},
		{path: NginxRoutesConfigPath, mode: 0o600, content: routes},
		{path: NginxMainConfigPath, mode: 0o600, content: main},
	}
	sort.Slice(artifacts, func(left, right int) bool { return artifacts[left].path < artifacts[right].path })
	total := 0
	for _, artifact := range artifacts {
		total += len(artifact.content)
	}
	if total > nginxMaximumTreeBytes {
		return NginxCandidate{}, fmt.Errorf("nginx configuration tree exceeds %d bytes", nginxMaximumTreeBytes)
	}
	candidate := NginxCandidate{
		stateGeneration:  request.StateGeneration,
		publicIPv4:       request.PublicIPv4,
		runtimeDirectory: request.RuntimeDirectory,
		configHash:       hashNginxArtifacts(artifacts),
		activeExposes:    len(active),
		artifacts:        artifacts,
	}
	if err := candidate.Validate(); err != nil {
		return NginxCandidate{}, fmt.Errorf("validate rendered nginx candidate: %w", err)
	}
	return candidate, nil
}

func (candidate NginxCandidate) Validate() error {
	if candidate.stateGeneration == 0 {
		return fmt.Errorf("nginx candidate state generation must be positive")
	}
	if _, err := canonicalPublicCertificateIPv4(candidate.publicIPv4); err != nil {
		return err
	}
	if !filepath.IsAbs(candidate.runtimeDirectory) || filepath.Clean(candidate.runtimeDirectory) != candidate.runtimeDirectory ||
		candidate.runtimeDirectory == string(filepath.Separator) || hasNginxPathControl(candidate.runtimeDirectory) {
		return fmt.Errorf("nginx candidate runtime directory is invalid")
	}
	wantPaths := []string{NginxProxyCommonPath, NginxRoutesConfigPath, NginxMainConfigPath}
	if len(candidate.artifacts) != len(wantPaths) {
		return fmt.Errorf("nginx candidate must contain the complete three-file tree")
	}
	total := 0
	for index, artifact := range candidate.artifacts {
		if artifact.path != wantPaths[index] || artifact.mode.Perm() != 0o600 || artifact.mode.Type() != 0 || len(artifact.content) == 0 {
			return fmt.Errorf("nginx candidate artifact %d is invalid", index)
		}
		total += len(artifact.content)
	}
	if total > nginxMaximumTreeBytes || candidate.activeExposes < 0 {
		return fmt.Errorf("nginx candidate bounds are invalid")
	}
	if candidate.configHash != hashNginxArtifacts(candidate.artifacts) {
		return fmt.Errorf("nginx candidate configuration hash mismatch")
	}
	return nil
}

func validateNginxRenderRequest(request NginxRenderRequest) ([]model.Expose, error) {
	if err := validateNginxReservedContract(); err != nil {
		return nil, err
	}
	if request.StateGeneration == 0 {
		return nil, fmt.Errorf("nginx source state generation must be positive")
	}
	if _, err := canonicalPublicCertificateIPv4(request.PublicIPv4); err != nil {
		return nil, err
	}
	for name, value := range map[string]string{
		"certificate":       request.CertificatePath,
		"private key":       request.PrivateKeyPath,
		"runtime directory": request.RuntimeDirectory,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || hasNginxPathControl(value) {
			return nil, fmt.Errorf("nginx %s path must be clean, absolute, and single-line", name)
		}
	}
	if request.RuntimeDirectory == string(filepath.Separator) {
		return nil, fmt.Errorf("nginx runtime directory must not be the filesystem root")
	}
	if request.CertificatePath == request.PrivateKeyPath {
		return nil, fmt.Errorf("nginx certificate and private-key paths must differ")
	}
	if err := request.Limits.Validate(); err != nil {
		return nil, err
	}
	if request.Exposes == nil {
		return nil, fmt.Errorf("nginx expose records must be present")
	}

	ids := make(map[string]struct{}, len(request.Exposes))
	ports := make(map[int]string, len(request.Exposes))
	routes := model.NewExposeRouteIndex()
	active := make([]model.Expose, 0, len(request.Exposes))
	for index, expose := range request.Exposes {
		if err := expose.Validate(); err != nil {
			return nil, fmt.Errorf("validate nginx expose %d: %w", index, err)
		}
		if expose.ConcurrentRequests != request.Limits.DefaultExposeConcurrent {
			return nil, fmt.Errorf("nginx expose %s concurrency differs from the gateway contract", expose.ID)
		}
		if err := (ExposeLimits{
			BodyBytes: expose.BodyLimitBytes, UpstreamTimeoutSeconds: expose.UpstreamTimeoutSeconds,
			ConcurrentRequests: expose.ConcurrentRequests,
		}).Validate(request.Limits); err != nil {
			return nil, fmt.Errorf("validate nginx expose %s limits: %w", expose.ID, err)
		}
		if _, duplicate := ids[expose.ID]; duplicate {
			return nil, fmt.Errorf("nginx expose identity %s is duplicated", expose.ID)
		}
		ids[expose.ID] = struct{}{}
		if expose.TunnelPort == NginxEnrollmentLoopbackPort {
			return nil, fmt.Errorf("nginx expose %s tunnel port collides with the reserved enrollment upstream", expose.ID)
		}
		if owner, duplicate := ports[expose.TunnelPort]; duplicate {
			return nil, fmt.Errorf("nginx tunnel port %d is shared by exposes %s and %s", expose.TunnelPort, owner, expose.ID)
		}
		ports[expose.TunnelPort] = expose.ID
		if expose.State == model.ExposeDisabled {
			continue
		}
		if owner, routeErr := routes.Add(expose.RouteMode, expose.Path, expose.ID); routeErr != nil {
			return nil, fmt.Errorf("validate nginx expose %s route: %w", expose.ID, routeErr)
		} else if owner != "" {
			return nil, fmt.Errorf("nginx expose %s route overlaps expose %s", expose.ID, owner)
		}
		active = append(active, expose)
	}
	sort.Slice(active, func(left, right int) bool {
		if active[left].Path != active[right].Path {
			return active[left].Path < active[right].Path
		}
		if active[left].RouteMode != active[right].RouteMode {
			return active[left].RouteMode < active[right].RouteMode
		}
		return active[left].ID < active[right].ID
	})
	return active, nil
}

func validateNginxReservedContract() error {
	upstream, err := netip.ParseAddrPort(NginxEnrollmentUpstream)
	if err != nil || upstream.Addr().String() != "127.0.0.1" || int(upstream.Port()) != NginxEnrollmentLoopbackPort {
		return fmt.Errorf("nginx enrollment upstream contract is invalid")
	}
	paths := []string{model.ReservedEnrollmentPath, model.ReservedRecoveryPath, model.ReservedHealthPath}
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if !model.IsReservedExposePath(path) || path == model.ReservedExposePathPrefix {
			return fmt.Errorf("nginx reserved path contract is invalid")
		}
		if _, duplicate := seen[path]; duplicate {
			return fmt.Errorf("nginx reserved path contract contains a duplicate")
		}
		seen[path] = struct{}{}
	}
	return nil
}

func renderNginxMain(request NginxRenderRequest) []byte {
	limits := request.Limits
	var config strings.Builder
	config.WriteString("user www-data;\n")
	config.WriteString("worker_processes 1;\n")
	fmt.Fprintf(&config, "worker_shutdown_timeout %ds;\n", limits.GracefulShutdownSeconds)
	fmt.Fprintf(&config, "worker_rlimit_nofile %d;\n", limits.ConnectionLimit*2)
	fmt.Fprintf(&config, "pid %s;\n", nginxQuote(filepath.Join(request.RuntimeDirectory, "nginx.pid")))
	config.WriteString("daemon off;\n")
	config.WriteString("master_process on;\n")
	config.WriteString("error_log /dev/null crit;\n\n")
	config.WriteString("events {\n")
	fmt.Fprintf(&config, "    worker_connections %d;\n", limits.ConnectionLimit)
	config.WriteString("    multi_accept off;\n")
	config.WriteString("}\n\n")
	config.WriteString("http {\n")
	config.WriteString("    access_log off;\n")
	config.WriteString("    server_tokens off;\n")
	fmt.Fprintf(&config, "    limit_conn_zone $server_name zone=vpnctl_gateway:%dk;\n", nginxSharedZoneBytes/1024)
	config.WriteString("    map $host $vpnctl_expose_key { default \"\"; }\n")
	fmt.Fprintf(&config, "    limit_conn_zone $vpnctl_expose_key zone=vpnctl_expose:%dk;\n", nginxSharedZoneBytes/1024)
	fmt.Fprintf(&config, "    limit_req_zone $binary_remote_addr zone=vpnctl_enrollment:%dk rate=1r/s;\n", nginxEnrollmentZoneBytes/1024)
	config.WriteString("    limit_conn_status 503;\n")
	config.WriteString("    limit_req_status 503;\n")
	config.WriteString("    limit_conn_dry_run off;\n\n")
	config.WriteString("    client_header_buffer_size 1k;\n")
	fmt.Fprintf(&config, "    large_client_header_buffers %d %d;\n", limits.HeaderBufferCount, limits.HeaderBufferBytes)
	fmt.Fprintf(&config, "    client_max_body_size %d;\n", limits.MaximumBodyBytes)
	config.WriteString("    client_body_buffer_size 16k;\n")
	fmt.Fprintf(&config, "    client_body_timeout %ds;\n", nginxClientTimeoutSeconds)
	fmt.Fprintf(&config, "    client_header_timeout %ds;\n", nginxClientTimeoutSeconds)
	fmt.Fprintf(&config, "    keepalive_timeout %ds;\n", nginxKeepaliveSeconds)
	fmt.Fprintf(&config, "    keepalive_requests %d;\n", nginxKeepaliveRequests)
	fmt.Fprintf(&config, "    send_timeout %ds;\n", nginxKeepaliveSeconds)
	config.WriteString("    reset_timedout_connection on;\n")
	fmt.Fprintf(&config, "    client_body_temp_path %s;\n", nginxQuote(filepath.Join(request.RuntimeDirectory, "client-body")))
	fmt.Fprintf(&config, "    proxy_temp_path %s;\n\n", nginxQuote(filepath.Join(request.RuntimeDirectory, "proxy")))
	config.WriteString("    server {\n")
	fmt.Fprintf(&config, "        listen 0.0.0.0:%d ssl http2;\n", NginxPublicHTTPSPort)
	config.WriteString("        server_name _;\n")
	fmt.Fprintf(&config, "        ssl_certificate %s;\n", nginxQuote(request.CertificatePath))
	fmt.Fprintf(&config, "        ssl_certificate_key %s;\n", nginxQuote(request.PrivateKeyPath))
	config.WriteString("        ssl_protocols TLSv1.2 TLSv1.3;\n")
	config.WriteString("        ssl_session_cache shared:VPNCTLIngressTLS:1m;\n")
	config.WriteString("        ssl_session_timeout 10m;\n")
	config.WriteString("        ssl_session_tickets off;\n")
	config.WriteString("        http2_body_preread_size 16k;\n")
	fmt.Fprintf(&config, "        http2_max_concurrent_streams %d;\n", limits.HTTP2ConcurrentStreams)
	fmt.Fprintf(&config, "        limit_conn vpnctl_gateway %d;\n", limits.GatewayConcurrentRequests)
	config.WriteString("        error_page 502 =503 @vpnctl_unavailable;\n")
	config.WriteString("        error_page 504 =504 @vpnctl_timeout;\n")
	config.WriteString("        include conf.d/routes.conf;\n")
	renderNginxFailureLocation(&config, "vpnctl_unavailable", 503, "service_unavailable")
	renderNginxFailureLocation(&config, "vpnctl_timeout", 504, "gateway_timeout")
	config.WriteString("    }\n")
	config.WriteString("}\n")
	return []byte(config.String())
}

func renderNginxProxyCommon(publicIPv4 string) []byte {
	return []byte(fmt.Sprintf(`proxy_http_version 1.1;
proxy_request_buffering off;
proxy_buffering off;
proxy_max_temp_file_size 0;
proxy_store off;
proxy_cache off;
proxy_next_upstream off;
proxy_next_upstream_tries 1;
proxy_intercept_errors off;
proxy_redirect off;
proxy_ignore_headers X-Accel-Buffering X-Accel-Redirect;
proxy_pass_request_body on;
proxy_pass_request_headers on;
proxy_connect_timeout %ds;
proxy_set_header Host %s;
proxy_set_header Authorization $http_authorization;
proxy_set_header Forwarded "";
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Host %s;
proxy_set_header X-Forwarded-Port $server_port;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Prefix "";
proxy_set_header X-Forwarded-Protocol "";
proxy_set_header X-Forwarded-Server "";
proxy_set_header X-Forwarded-Ssl "";
proxy_set_header X-Forwarded-Client-Cert "";
proxy_set_header X-Original-Forwarded-For "";
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header Client-IP "";
proxy_set_header X-Client-IP "";
proxy_set_header True-Client-IP "";
proxy_set_header Via "";
proxy_set_header Connection "";
proxy_set_header Upgrade "";
proxy_set_header TE "";
`, nginxConnectTimeoutSeconds, nginxQuote(publicIPv4), nginxQuote(publicIPv4)))
}

func renderNginxFailureLocation(config *strings.Builder, name string, status int, code string) {
	fmt.Fprintf(config, "        location @%s {\n", name)
	config.WriteString("            internal;\n")
	config.WriteString("            default_type application/json;\n")
	config.WriteString("            add_header Cache-Control \"no-store\" always;\n")
	config.WriteString("            add_header X-Content-Type-Options \"nosniff\" always;\n")
	fmt.Fprintf(config, "            return %d '{\"error\":\"%s\"}';\n", status, code)
	config.WriteString("        }\n")
}

func renderNginxRoutes(exposes []model.Expose) []byte {
	var config strings.Builder
	renderNginxReservedRoutes(&config)
	hasRootPrefix := false
	for _, expose := range exposes {
		if expose.RouteMode == model.RoutePrefix && expose.Path == "/" {
			hasRootPrefix = true
		}
		if expose.RouteMode == model.RoutePrefix && expose.Path != "/" {
			renderNginxLocation(&config, expose, "=", expose.Path)
			renderNginxLocation(&config, expose, "^~", expose.Path+"/")
			continue
		}
		modifier := "="
		if expose.RouteMode == model.RoutePrefix {
			modifier = ""
		}
		renderNginxLocation(&config, expose, modifier, expose.Path)
	}
	if !hasRootPrefix {
		config.WriteString("location / {\n    return 404;\n}\n")
	}
	return []byte(config.String())
}

func renderNginxReservedRoutes(config *strings.Builder) {
	for _, path := range []string{model.ReservedEnrollmentPath, model.ReservedRecoveryPath} {
		fmt.Fprintf(config, "location = %s {\n", nginxQuote(path))
		fmt.Fprintf(config, "    client_max_body_size %d;\n", NginxEnrollmentMaximumBodyBytes)
		fmt.Fprintf(config, "    limit_conn vpnctl_gateway %d;\n", DefaultIngressGatewayConcurrentRequests)
		config.WriteString("    limit_req zone=vpnctl_enrollment burst=4 nodelay;\n")
		fmt.Fprintf(config, "    proxy_read_timeout %ds;\n", NginxEnrollmentTimeoutSeconds)
		fmt.Fprintf(config, "    proxy_send_timeout %ds;\n", NginxEnrollmentTimeoutSeconds)
		fmt.Fprintf(config, "    proxy_pass http://%s;\n", NginxEnrollmentUpstream)
		config.WriteString("    include conf.d/proxy-common.conf;\n")
		config.WriteString("}\n")
	}
	fmt.Fprintf(config, "location = %s {\n", nginxQuote(model.ReservedHealthPath))
	config.WriteString("    default_type application/json;\n")
	config.WriteString("    add_header Cache-Control \"no-store\" always;\n")
	config.WriteString("    add_header X-Content-Type-Options \"nosniff\" always;\n")
	config.WriteString("    return 204;\n")
	config.WriteString("}\n")
	renderNginxFixedNotFound(config, "=", model.ReservedExposePathPrefix)
	renderNginxFixedNotFound(config, "^~", model.ReservedExposePathPrefix+"/")
}

func renderNginxFixedNotFound(config *strings.Builder, modifier, path string) {
	fmt.Fprintf(config, "location %s %s {\n", modifier, nginxQuote(path))
	config.WriteString("    default_type application/json;\n")
	config.WriteString("    add_header Cache-Control \"no-store\" always;\n")
	config.WriteString("    add_header Pragma \"no-cache\" always;\n")
	config.WriteString("    add_header X-Content-Type-Options \"nosniff\" always;\n")
	config.WriteString("    return 404 '{\"error\":\"not_found\"}';\n")
	config.WriteString("}\n")
}

func renderNginxLocation(config *strings.Builder, expose model.Expose, modifier, path string) {
	config.WriteString("location")
	if modifier != "" {
		config.WriteByte(' ')
		config.WriteString(modifier)
	}
	config.WriteByte(' ')
	config.WriteString(nginxQuote(path))
	config.WriteString(" {\n")
	fmt.Fprintf(config, "    set $vpnctl_expose_key %s;\n", nginxExposeKey(expose.ID))
	fmt.Fprintf(config, "    client_max_body_size %d;\n", expose.BodyLimitBytes)
	fmt.Fprintf(config, "    limit_conn vpnctl_gateway %d;\n", DefaultIngressGatewayConcurrentRequests)
	fmt.Fprintf(config, "    limit_conn vpnctl_expose %d;\n", expose.ConcurrentRequests)
	fmt.Fprintf(config, "    proxy_read_timeout %ds;\n", expose.UpstreamTimeoutSeconds)
	fmt.Fprintf(config, "    proxy_send_timeout %ds;\n", expose.UpstreamTimeoutSeconds)
	fmt.Fprintf(config, "    proxy_pass http://127.0.0.1:%d;\n", expose.TunnelPort)
	config.WriteString("    include conf.d/proxy-common.conf;\n")
	config.WriteString("}\n")
}

func nginxExposeKey(id string) string {
	return "e_" + strings.ReplaceAll(id, "-", "")
}

func nginxQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, `$`, `\$`)
	return `"` + value + `"`
}

func hasNginxPathControl(value string) bool {
	for _, character := range []byte(value) {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func hashNginxArtifacts(artifacts []NginxArtifact) string {
	digest := sha256.New()
	var size [8]byte
	for _, artifact := range artifacts {
		binary.BigEndian.PutUint64(size[:], uint64(len(artifact.path)))
		_, _ = digest.Write(size[:])
		_, _ = digest.Write([]byte(artifact.path))
		binary.BigEndian.PutUint64(size[:], uint64(artifact.mode.Perm()))
		_, _ = digest.Write(size[:])
		binary.BigEndian.PutUint64(size[:], uint64(len(artifact.content)))
		_, _ = digest.Write(size[:])
		_, _ = digest.Write(artifact.content)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// ValidatePinnedNginxConfig verifies the selected runtime version and invokes
// nginx's parser against an already staged candidate tree. Staging and atomic
// activation remain separate responsibilities.
func ValidatePinnedNginxConfig(ctx context.Context, runner linuxplatform.ProbeRunner, binaryPath, candidateRoot string) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if runner == nil {
		return fmt.Errorf("nginx validation runner is required")
	}
	for name, value := range map[string]string{"binary": binaryPath, "candidate root": candidateRoot} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("nginx %s path must be clean and absolute", name)
		}
	}
	version, err := runner.Run(ctx, linuxplatform.ProbeCommand{Name: binaryPath, Args: []string{"-v"}})
	if err != nil {
		return fmt.Errorf("inspect nginx version: %w", err)
	}
	if version.ExitCode != 0 || !hasExactNginxVersion(string(version.Stdout)+" "+string(version.Stderr)) {
		return fmt.Errorf("installed nginx does not match pinned runtime version %s", NginxProviderRuntimeVersion)
	}
	validation, err := runner.Run(ctx, linuxplatform.ProbeCommand{
		Name: binaryPath,
		Args: []string{"-t", "-p", candidateRoot + string(filepath.Separator), "-c", NginxMainConfigPath},
	})
	if err != nil {
		return fmt.Errorf("validate nginx candidate: %w", err)
	}
	if validation.ExitCode != 0 {
		return fmt.Errorf("pinned nginx rejected candidate configuration")
	}
	return nil
}

func hasExactNginxVersion(output string) bool {
	want := "nginx/" + NginxProviderRuntimeVersion
	for _, field := range strings.Fields(output) {
		if strings.Trim(field, " ,;()[]") == want {
			return true
		}
	}
	return false
}
