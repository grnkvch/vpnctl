package operations

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestExposeCatalogListsSafeStateAndShowRefreshesCertificate(t *testing.T) {
	t.Parallel()

	node, gateway := exposeRemovalStates(t)
	state := &memoryExposeState{state: node, trace: &[]string{}}
	remote := &recordingExposeCatalogGateway{snapshot: GatewayExposeCatalogSnapshot{
		GatewayID: gateway.Host.ID, Generation: gateway.Generation, PublicIPv4: gateway.Host.PublicIPv4,
		NodeID: node.Nodes[0].ID, Exposes: gateway.Exposes, Certificate: gateway.Certificates[0],
		CertificateExportPath: "/var/lib/vpnctl/exports/gateway.crt", CertificateAvailable: true,
	}}
	catalog, err := NewExposeCatalog(state, remote)
	if err != nil {
		t.Fatal(err)
	}
	list, err := catalog.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !list.GatewayReachable || list.GatewayStateGeneration != 11 || len(list.Items) != 2 ||
		list.Items[0].Name != "openai" || list.Items[1].Name != "telegram" || remote.refreshes[0] {
		t.Fatalf("list/refresh = %+v / %v", list, remote.refreshes)
	}
	encoded, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{exposeSagaPathCanary, exposeRemoveSecondPath, `"TunnelPort":`, `"Path":`} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("list leaked %q: %s", forbidden, encoded)
		}
	}

	show, err := catalog.Show(context.Background(), "TeLeGrAm")
	if err != nil {
		t.Fatal(err)
	}
	if !show.GatewayReachable || show.Resource.ID != exposeSagaExposeID || len(remote.refreshes) != 2 || !remote.refreshes[1] {
		t.Fatalf("show/refresh = %+v / %v", show, remote.refreshes)
	}
	var publicURL string
	if err := show.PublicURL(func(value string) error { publicURL = value; return nil }); err != nil {
		t.Fatal(err)
	}
	if publicURL != "https://203.0.113.10"+exposeSagaPathCanary {
		t.Fatalf("public URL = %q", publicURL)
	}
	encoded, err = json.Marshal(show)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), exposeSagaPathCanary) || strings.Contains(string(encoded), "publicURL") {
		t.Fatalf("show leaked sensitive URL: %s", encoded)
	}
	if _, err := json.Marshal(remote.snapshot); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("gateway snapshot serialization error = %v", err)
	}
}

func TestExposeCatalogRetainsLocalNonSecretStateWhenGatewayIsUnavailable(t *testing.T) {
	t.Parallel()

	node, _ := exposeRemovalStates(t)
	catalog, err := NewExposeCatalog(
		&memoryExposeState{state: node, trace: &[]string{}},
		&recordingExposeCatalogGateway{err: errors.New("control transport unavailable")},
	)
	if err != nil {
		t.Fatal(err)
	}
	list, err := catalog.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if list.GatewayReachable || list.GatewayStateGeneration != 0 || len(list.Items) != 2 || list.Items[0].Certificate.Available {
		t.Fatalf("offline list = %+v", list)
	}
	show, err := catalog.Show(context.Background(), exposeSagaExposeID)
	if err != nil {
		t.Fatal(err)
	}
	if show.GatewayReachable || show.Resource.ID != exposeSagaExposeID || show.Resource.Certificate.ID != "" {
		t.Fatalf("offline show = %+v", show)
	}
}

func TestGatewayExposeCatalogInspectionIsReadOnlyUnlessShowRequestsRefresh(t *testing.T) {
	t.Parallel()

	_, gateway := exposeRemovalStates(t)
	trace := &[]string{}
	store := &memoryExposeState{state: gateway, trace: trace, label: "gateway"}
	exporter := &recordingCatalogCertificateExporter{available: true}
	service, err := NewGatewayExposeCoordinatorService(
		store, exporter, memoryGatewayUnavailablePorts{}, &memoryGatewayIngressPublisher{trace: trace},
		memoryGatewayDeferredWriter{}, testExposeNormalizer(), "/var/lib/vpnctl/exports/gateway.crt",
	)
	if err != nil {
		t.Fatal(err)
	}
	before := cloneTestExposeState(t, store.state)
	list, err := service.Inspect(context.Background(), exposeSagaNodeID, false)
	if err != nil {
		t.Fatal(err)
	}
	if !list.CertificateAvailable || exporter.availabilityCalls != 1 || exporter.ensureCalls != 0 ||
		len(list.Exposes) != 2 || !reflectExposeState(before, store.state) {
		t.Fatalf("read-only inspection = %+v exporter:%+v", list, exporter)
	}
	show, err := service.Inspect(context.Background(), exposeSagaNodeID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !show.CertificateAvailable || exporter.ensureCalls != 1 || exporter.availabilityCalls != 1 ||
		!reflectExposeState(before, store.state) || store.saveCalls != 0 {
		t.Fatalf("refresh inspection = %+v exporter:%+v saves:%d", show, exporter, store.saveCalls)
	}
	for _, expose := range show.Exposes {
		if expose.NodeID != exposeSagaNodeID {
			t.Fatalf("inspection crossed node boundary: %+v", show.Exposes)
		}
	}
}

type recordingExposeCatalogGateway struct {
	snapshot  GatewayExposeCatalogSnapshot
	err       error
	refreshes []bool
}

func (gateway *recordingExposeCatalogGateway) Inspect(_ context.Context, nodeID string, refresh bool) (GatewayExposeCatalogSnapshot, error) {
	gateway.refreshes = append(gateway.refreshes, refresh)
	if gateway.err != nil {
		return GatewayExposeCatalogSnapshot{}, gateway.err
	}
	if nodeID != gateway.snapshot.NodeID {
		return GatewayExposeCatalogSnapshot{}, ErrExposePlanStale
	}
	return gateway.snapshot, nil
}

type recordingCatalogCertificateExporter struct {
	available         bool
	availabilityCalls int
	ensureCalls       int
}

func (exporter *recordingCatalogCertificateExporter) Ensure(model.State, string) error {
	exporter.ensureCalls++
	return nil
}

func (exporter *recordingCatalogCertificateExporter) Available(model.State, string) (bool, error) {
	exporter.availabilityCalls++
	return exporter.available, nil
}

func reflectExposeState(left, right model.State) bool {
	leftEncoded, leftErr := model.EncodeState(left)
	rightEncoded, rightErr := model.EncodeState(right)
	return leftErr == nil && rightErr == nil && string(leftEncoded) == string(rightEncoded)
}
