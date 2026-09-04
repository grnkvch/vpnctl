package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const observabilityCanary = "vpnctl-secret-canary-Authorization-Bearer-/telegram/webhook"

func TestEventHasNoArbitraryExportedField(t *testing.T) {
	t.Parallel()
	typeOfEvent := reflect.TypeOf(Event{})
	for index := 0; index < typeOfEvent.NumField(); index++ {
		if typeOfEvent.Field(index).IsExported() {
			t.Fatalf("event exposes arbitrary field %q", typeOfEvent.Field(index).Name)
		}
	}
	if got := fmt.Sprintf("%+v", Event{}); strings.Contains(got, observabilityCanary) {
		t.Fatalf("zero event formatting leaked canary: %q", got)
	}
}

func TestEventCodesHaveFixedScopeAndLevel(t *testing.T) {
	t.Parallel()
	want := map[EventCode]Descriptor{
		ControlServiceStarted:       {ControlServiceStarted, model.LogControl, model.LogInfo},
		ControlServiceStopped:       {ControlServiceStopped, model.LogControl, model.LogInfo},
		ControlRequestRejected:      {ControlRequestRejected, model.LogControl, model.LogDebug},
		ControlMutationCommitted:    {ControlMutationCommitted, model.LogControl, model.LogInfo},
		TransportServiceStarted:     {TransportServiceStarted, model.LogTransport, model.LogInfo},
		TransportServiceReady:       {TransportServiceReady, model.LogTransport, model.LogInfo},
		TransportServiceStopped:     {TransportServiceStopped, model.LogTransport, model.LogInfo},
		TransportRuntimeFailed:      {TransportRuntimeFailed, model.LogTransport, model.LogError},
		RoutingServiceStarted:       {RoutingServiceStarted, model.LogRouting, model.LogInfo},
		RoutingServiceReady:         {RoutingServiceReady, model.LogRouting, model.LogInfo},
		RoutingServiceStopped:       {RoutingServiceStopped, model.LogRouting, model.LogInfo},
		RoutingRuntimeFailed:        {RoutingRuntimeFailed, model.LogRouting, model.LogError},
		DNSServiceStarted:           {DNSServiceStarted, model.LogDNS, model.LogInfo},
		DNSServiceStopped:           {DNSServiceStopped, model.LogDNS, model.LogInfo},
		DNSRuntimeFailed:            {DNSRuntimeFailed, model.LogDNS, model.LogError},
		TunnelServiceStarted:        {TunnelServiceStarted, model.LogTunnel, model.LogInfo},
		TunnelServiceStopped:        {TunnelServiceStopped, model.LogTunnel, model.LogInfo},
		TunnelRuntimeFailed:         {TunnelRuntimeFailed, model.LogTunnel, model.LogError},
		TunnelAuthorizationAccepted: {TunnelAuthorizationAccepted, model.LogTunnel, model.LogDebug},
		TunnelAuthorizationRejected: {TunnelAuthorizationRejected, model.LogTunnel, model.LogInfo},
		IngressReloadStarted:        {IngressReloadStarted, model.LogIngress, model.LogInfo},
		IngressReloadCompleted:      {IngressReloadCompleted, model.LogIngress, model.LogInfo},
		IngressReloadFailed:         {IngressReloadFailed, model.LogIngress, model.LogError},
	}
	if len(want) != len(eventSpecs) {
		t.Fatalf("test covers %d event codes, registry has %d", len(want), len(eventSpecs))
	}
	for code, expected := range want {
		event, err := NewEvent(code)
		if err != nil {
			t.Fatalf("NewEvent(%q): %v", code, err)
		}
		actual, err := Describe(event)
		if err != nil || actual != expected {
			t.Fatalf("Describe(%q) = %+v, %v; want %+v", code, actual, err, expected)
		}
	}
	if _, err := NewEvent(EventCode(observabilityCanary)); err == nil || strings.Contains(err.Error(), observabilityCanary) {
		t.Fatalf("unknown code error = %v", err)
	}
}

func TestEventRejectsCanariesAndEncodesOnlyAllowedFields(t *testing.T) {
	t.Parallel()
	event, err := NewEvent(IngressReloadCompleted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := event.WithResourceID(observabilityCanary); err == nil || strings.Contains(err.Error(), observabilityCanary) {
		t.Fatalf("resource canary error = %v", err)
	}
	if _, err := event.WithSHA256(observabilityCanary); err == nil || strings.Contains(err.Error(), observabilityCanary) {
		t.Fatalf("digest canary error = %v", err)
	}
	if _, err := event.WithDuration(-time.Second); err == nil {
		t.Fatal("negative duration accepted")
	}
	if _, err := event.WithDuration(24*time.Hour + time.Millisecond); err == nil {
		t.Fatal("unbounded duration accepted")
	}

	event, err = event.WithResourceID("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	event, err = event.WithDuration(1500 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	event, err = event.WithSHA256(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	event = event.WithGeneration(7).WithCount(2)
	encoded, err := EncodeRecord(event, time.Date(2026, 9, 4, 12, 34, 56, 789123456, time.FixedZone("test", 2*60*60)))
	if err != nil {
		t.Fatal(err)
	}
	if encoded[len(encoded)-1] != '\n' || strings.Contains(string(encoded), observabilityCanary) {
		t.Fatalf("unsafe record = %q", encoded)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"schema_version", "timestamp", "code", "scope", "level", "resource_id", "generation", "count", "duration_ms", "sha256"}
	if len(document) != len(wantKeys) {
		t.Fatalf("record fields = %#v", document)
	}
	for _, key := range wantKeys {
		if _, found := document[key]; !found {
			t.Errorf("record omits %q", key)
		}
	}
	if document["timestamp"] != "2026-09-04T10:34:56.789Z" || document["duration_ms"] != float64(1500) {
		t.Fatalf("record normalization = %#v", document)
	}
	if _, err := EncodeRecord(Event{}, time.Now()); err == nil || strings.Contains(err.Error(), observabilityCanary) {
		t.Fatalf("zero event error = %v", err)
	}
	if _, err := EncodeRecord(event, time.Time{}); err == nil {
		t.Fatal("zero timestamp accepted")
	}
}

func TestEmitterContextAndConvenienceFunctions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if err := EmitCode(ctx, DNSServiceStarted); err != nil {
		t.Fatalf("nop emitter: %v", err)
	}
	recorder := &recordingEmitter{}
	ctx = WithEmitter(ctx, recorder)
	if err := EmitGenerationSHA256(ctx, IngressReloadCompleted, 9, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if len(recorder.events) != 1 {
		t.Fatalf("events = %d", len(recorder.events))
	}
	descriptor, err := Describe(recorder.events[0])
	if err != nil || descriptor.Code != IngressReloadCompleted {
		t.Fatalf("descriptor = %+v, %v", descriptor, err)
	}
	if err := EmitGenerationSHA256(ctx, IngressReloadCompleted, 9, observabilityCanary); err == nil {
		t.Fatal("invalid digest reached emitter")
	}
	if len(recorder.events) != 1 {
		t.Fatalf("invalid event was emitted: %d", len(recorder.events))
	}
}

type recordingEmitter struct {
	events []Event
}

func (emitter *recordingEmitter) Emit(_ context.Context, event Event) error {
	emitter.events = append(emitter.events, event)
	return nil
}
