package operations

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

var ErrExposeNotFound = errors.New("expose does not exist")

// GatewayExposeCatalogSnapshot is a bounded control-plane response. It may
// contain sensitive paths belonging to the requesting node, so it is never a
// generic output value. The gateway must not include another node's exposes.
type GatewayExposeCatalogSnapshot struct {
	GatewayID             string
	Generation            uint64
	PublicIPv4            string
	NodeID                string
	Exposes               []model.Expose
	Certificate           model.Certificate
	CertificateExportPath string
	CertificateAvailable  bool
}

func (GatewayExposeCatalogSnapshot) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type ExposeGatewayCatalog interface {
	Inspect(context.Context, string, bool) (GatewayExposeCatalogSnapshot, error)
}

type ExposeCertificateView struct {
	ID          string    `json:"id,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	Generation  uint64    `json:"generation,omitempty"`
	Available   bool      `json:"available"`
	OutputPath  string    `json:"output_path,omitempty"`
	PublicIPv4  string    `json:"public_ipv4,omitempty"`
}

// ExposeView is the only ordinary list/show projection. It deliberately omits
// the webhook path, derived URL, tunnel port, and every opaque reference.
type ExposeView struct {
	ID                     string                `json:"id"`
	Name                   string                `json:"name,omitempty"`
	Upstream               string                `json:"upstream"`
	RouteMode              model.RouteMode       `json:"route_mode"`
	BodyLimitBytes         int64                 `json:"body_limit_bytes"`
	UpstreamTimeoutSeconds int                   `json:"upstream_timeout_seconds"`
	ConcurrentRequests     int                   `json:"concurrent_requests"`
	State                  model.ExposeState     `json:"state"`
	Generation             uint64                `json:"generation"`
	CreatedAt              time.Time             `json:"created_at"`
	Certificate            ExposeCertificateView `json:"public_certificate"`
}

type ExposeList struct {
	LocalStateGeneration   uint64       `json:"local_state_generation"`
	GatewayStateGeneration uint64       `json:"gateway_state_generation,omitempty"`
	GatewayReachable       bool         `json:"gateway_reachable"`
	Items                  []ExposeView `json:"items"`
}

type ExposeShow struct {
	LocalStateGeneration   uint64     `json:"local_state_generation"`
	GatewayStateGeneration uint64     `json:"gateway_state_generation,omitempty"`
	GatewayReachable       bool       `json:"gateway_reachable"`
	Resource               ExposeView `json:"resource"`
	publicURL              output.SensitivePath
}

func (show ExposeShow) PublicURL(callback func(string) error) error {
	return show.publicURL.Use(callback)
}

type ExposeCatalog struct {
	state   ExposeNodeStateStore
	gateway ExposeGatewayCatalog
}

func NewExposeCatalog(state ExposeNodeStateStore, gateway ExposeGatewayCatalog) (*ExposeCatalog, error) {
	if state == nil || gateway == nil {
		return nil, fmt.Errorf("expose catalog state and gateway are required")
	}
	return &ExposeCatalog{state: state, gateway: gateway}, nil
}

func (catalog *ExposeCatalog) List(ctx context.Context) (ExposeList, error) {
	if ctx == nil {
		return ExposeList{}, fmt.Errorf("context is required")
	}
	local, node, err := catalog.loadJoinedNode()
	if err != nil {
		return ExposeList{}, err
	}
	snapshot, err := catalog.gateway.Inspect(ctx, node.ID, false)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return ExposeList{}, contextErr
		}
		return ExposeList{
			LocalStateGeneration: local.Generation, GatewayReachable: false,
			Items: buildExposeViews(local.Exposes, ExposeCertificateView{}),
		}, nil
	}
	if err := validateCatalogSnapshot(snapshot, local, node); err != nil {
		return ExposeList{}, err
	}
	certificate := certificateView(snapshot)
	return ExposeList{
		LocalStateGeneration: local.Generation, GatewayStateGeneration: snapshot.Generation,
		GatewayReachable: true, Items: buildExposeViews(local.Exposes, certificate),
	}, nil
}

func (catalog *ExposeCatalog) Show(ctx context.Context, reference string) (ExposeShow, error) {
	if ctx == nil {
		return ExposeShow{}, fmt.Errorf("context is required")
	}
	local, node, err := catalog.loadJoinedNode()
	if err != nil {
		return ExposeShow{}, err
	}
	expose, err := resolveExpose(local.Exposes, node.ID, reference)
	if err != nil {
		return ExposeShow{}, err
	}
	snapshot, err := catalog.gateway.Inspect(ctx, node.ID, true)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return ExposeShow{}, contextErr
		}
		return ExposeShow{
			LocalStateGeneration: local.Generation, GatewayReachable: false,
			Resource: buildExposeView(expose, ExposeCertificateView{}),
		}, nil
	}
	if err := validateCatalogSnapshot(snapshot, local, node); err != nil {
		return ExposeShow{}, err
	}
	publicURL, err := exposePublicURL(snapshot.PublicIPv4, expose.Path)
	if err != nil {
		return ExposeShow{}, err
	}
	return ExposeShow{
		LocalStateGeneration: local.Generation, GatewayStateGeneration: snapshot.Generation,
		GatewayReachable: true, Resource: buildExposeView(expose, certificateView(snapshot)), publicURL: publicURL,
	}, nil
}

func (catalog *ExposeCatalog) loadJoinedNode() (model.State, model.Node, error) {
	if catalog == nil || catalog.state == nil || catalog.gateway == nil {
		return model.State{}, model.Node{}, fmt.Errorf("expose catalog is incomplete")
	}
	state, err := catalog.state.Load()
	if err != nil {
		return model.State{}, model.Node{}, fmt.Errorf("load node expose state: %w", err)
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleNode || len(state.Nodes) != 1 ||
		state.Nodes[0].Lifecycle != model.LifecycleActive || state.Nodes[0].Gateway == nil {
		return model.State{}, model.Node{}, fmt.Errorf("expose catalog requires one joined active node")
	}
	return state, state.Nodes[0], nil
}

func validateCatalogSnapshot(snapshot GatewayExposeCatalogSnapshot, local model.State, node model.Node) error {
	if model.ValidateResourceID(snapshot.GatewayID) != nil || snapshot.Generation == 0 || snapshot.NodeID != node.ID ||
		snapshot.Generation < node.Gateway.LastKnownGatewayGeneration {
		return ErrExposePlanStale
	}
	address, err := netip.ParseAddr(snapshot.PublicIPv4)
	if err != nil || !address.Is4() || address.String() != snapshot.PublicIPv4 || snapshot.PublicIPv4 != node.Gateway.PublicIPv4 {
		return ErrExposePlanStale
	}
	if err := snapshot.Certificate.Validate(); err != nil || snapshot.Certificate.Kind != model.CertificatePublicIngress ||
		snapshot.Certificate.OwnerID != snapshot.GatewayID || snapshot.Certificate.OwnerKind != "host" {
		return fmt.Errorf("gateway public certificate metadata is invalid")
	}
	if snapshot.CertificateExportPath == "" || !filepath.IsAbs(snapshot.CertificateExportPath) ||
		filepath.Clean(snapshot.CertificateExportPath) != snapshot.CertificateExportPath || strings.ContainsAny(snapshot.CertificateExportPath, "\x00\r\n") {
		return fmt.Errorf("gateway public certificate export path is invalid")
	}
	if len(snapshot.Exposes) != len(local.Exposes) {
		return ErrExposePlanStale
	}
	remote := make(map[string]model.Expose, len(snapshot.Exposes))
	for _, expose := range snapshot.Exposes {
		if err := expose.Validate(); err != nil || expose.NodeID != node.ID {
			return fmt.Errorf("gateway expose catalog contains an invalid owner")
		}
		if _, duplicate := remote[expose.ID]; duplicate {
			return fmt.Errorf("gateway expose catalog duplicates an expose")
		}
		remote[expose.ID] = expose
	}
	for _, expose := range local.Exposes {
		if expose.NodeID != node.ID || !reflect.DeepEqual(remote[expose.ID], expose) {
			return ErrExposePlanStale
		}
	}
	return nil
}

func certificateView(snapshot GatewayExposeCatalogSnapshot) ExposeCertificateView {
	return ExposeCertificateView{
		ID: snapshot.Certificate.ID, Fingerprint: snapshot.Certificate.Fingerprint,
		NotAfter: snapshot.Certificate.NotAfter, Generation: snapshot.Certificate.Generation,
		Available: snapshot.CertificateAvailable, OutputPath: snapshot.CertificateExportPath,
		PublicIPv4: snapshot.PublicIPv4,
	}
}

func buildExposeViews(exposes []model.Expose, certificate ExposeCertificateView) []ExposeView {
	items := make([]ExposeView, 0, len(exposes))
	for _, expose := range exposes {
		items = append(items, buildExposeView(expose, certificate))
	}
	sort.Slice(items, func(left, right int) bool {
		leftName, rightName := strings.ToLower(items[left].Name), strings.ToLower(items[right].Name)
		if leftName != rightName {
			return leftName < rightName
		}
		return items[left].ID < items[right].ID
	})
	return items
}

func buildExposeView(expose model.Expose, certificate ExposeCertificateView) ExposeView {
	return ExposeView{
		ID: expose.ID, Name: expose.Name, Upstream: expose.Upstream, RouteMode: expose.RouteMode,
		BodyLimitBytes: expose.BodyLimitBytes, UpstreamTimeoutSeconds: expose.UpstreamTimeoutSeconds,
		ConcurrentRequests: expose.ConcurrentRequests, State: expose.State,
		Generation: expose.Generation, CreatedAt: expose.CreatedAt, Certificate: certificate,
	}
}

func resolveExpose(exposes []model.Expose, nodeID, reference string) (model.Expose, error) {
	if reference == "" || strings.TrimSpace(reference) != reference || strings.ContainsAny(reference, "\x00\r\n") {
		return model.Expose{}, fmt.Errorf("%w: an explicit name or ID is required", ErrExposeNotFound)
	}
	matches := make([]model.Expose, 0, 1)
	for _, expose := range exposes {
		if expose.NodeID == nodeID && (expose.ID == reference || expose.Name != "" && strings.EqualFold(expose.Name, reference)) {
			matches = append(matches, expose)
		}
	}
	if len(matches) != 1 {
		return model.Expose{}, fmt.Errorf("%w: %s", ErrExposeNotFound, reference)
	}
	return matches[0], nil
}
