package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

type EventCode string

const (
	ControlServiceStarted       EventCode = "control_service_started"
	ControlServiceStopped       EventCode = "control_service_stopped"
	ControlRequestRejected      EventCode = "control_request_rejected"
	ControlMutationCommitted    EventCode = "control_mutation_committed"
	TransportServiceStarted     EventCode = "transport_service_started"
	TransportServiceReady       EventCode = "transport_service_ready"
	TransportServiceStopped     EventCode = "transport_service_stopped"
	TransportRuntimeFailed      EventCode = "transport_runtime_failed"
	RoutingServiceStarted       EventCode = "routing_service_started"
	RoutingServiceReady         EventCode = "routing_service_ready"
	RoutingServiceStopped       EventCode = "routing_service_stopped"
	RoutingRuntimeFailed        EventCode = "routing_runtime_failed"
	DNSServiceStarted           EventCode = "dns_service_started"
	DNSServiceStopped           EventCode = "dns_service_stopped"
	DNSRuntimeFailed            EventCode = "dns_runtime_failed"
	TunnelServiceStarted        EventCode = "tunnel_service_started"
	TunnelServiceStopped        EventCode = "tunnel_service_stopped"
	TunnelRuntimeFailed         EventCode = "tunnel_runtime_failed"
	TunnelAuthorizationAccepted EventCode = "tunnel_authorization_accepted"
	TunnelAuthorizationRejected EventCode = "tunnel_authorization_rejected"
	IngressReloadStarted        EventCode = "ingress_reload_started"
	IngressReloadCompleted      EventCode = "ingress_reload_completed"
	IngressReloadFailed         EventCode = "ingress_reload_failed"
)

type eventSpec struct {
	scope model.LogScope
	level model.LogLevel
}

var eventSpecs = map[EventCode]eventSpec{
	ControlServiceStarted:       {model.LogControl, model.LogInfo},
	ControlServiceStopped:       {model.LogControl, model.LogInfo},
	ControlRequestRejected:      {model.LogControl, model.LogDebug},
	ControlMutationCommitted:    {model.LogControl, model.LogInfo},
	TransportServiceStarted:     {model.LogTransport, model.LogInfo},
	TransportServiceReady:       {model.LogTransport, model.LogInfo},
	TransportServiceStopped:     {model.LogTransport, model.LogInfo},
	TransportRuntimeFailed:      {model.LogTransport, model.LogError},
	RoutingServiceStarted:       {model.LogRouting, model.LogInfo},
	RoutingServiceReady:         {model.LogRouting, model.LogInfo},
	RoutingServiceStopped:       {model.LogRouting, model.LogInfo},
	RoutingRuntimeFailed:        {model.LogRouting, model.LogError},
	DNSServiceStarted:           {model.LogDNS, model.LogInfo},
	DNSServiceStopped:           {model.LogDNS, model.LogInfo},
	DNSRuntimeFailed:            {model.LogDNS, model.LogError},
	TunnelServiceStarted:        {model.LogTunnel, model.LogInfo},
	TunnelServiceStopped:        {model.LogTunnel, model.LogInfo},
	TunnelRuntimeFailed:         {model.LogTunnel, model.LogError},
	TunnelAuthorizationAccepted: {model.LogTunnel, model.LogDebug},
	TunnelAuthorizationRejected: {model.LogTunnel, model.LogInfo},
	IngressReloadStarted:        {model.LogIngress, model.LogInfo},
	IngressReloadCompleted:      {model.LogIngress, model.LogInfo},
	IngressReloadFailed:         {model.LogIngress, model.LogError},
}

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Event deliberately has no exported field. Callers can attach only bounded
// numeric metadata, a UUID resource identity, or a SHA-256 digest; arbitrary
// strings, errors, headers, paths, URLs and bodies cannot cross this API.
type Event struct {
	code       EventCode
	resourceID string
	generation uint64
	count      uint64
	durationMS uint64
	sha256     string
}

func NewEvent(code EventCode) (Event, error) {
	if _, found := eventSpecs[code]; !found {
		return Event{}, fmt.Errorf("unsupported operational event code")
	}
	return Event{code: code}, nil
}

func (event Event) WithResourceID(id string) (Event, error) {
	if !uuidPattern.MatchString(id) {
		return Event{}, fmt.Errorf("operational event resource ID must be a UUID")
	}
	event.resourceID = id
	return event, nil
}

func (event Event) WithGeneration(generation uint64) Event {
	event.generation = generation
	return event
}

func (event Event) WithCount(count uint64) Event {
	event.count = count
	return event
}

func (event Event) WithDuration(duration time.Duration) (Event, error) {
	if duration < 0 || duration > 24*time.Hour {
		return Event{}, fmt.Errorf("operational event duration is outside its bound")
	}
	event.durationMS = uint64(duration / time.Millisecond)
	return event, nil
}

func (event Event) WithSHA256(digest string) (Event, error) {
	if !sha256Pattern.MatchString(digest) {
		return Event{}, fmt.Errorf("operational event digest must be lowercase SHA-256")
	}
	event.sha256 = digest
	return event, nil
}

type Descriptor struct {
	Code  EventCode
	Scope model.LogScope
	Level model.LogLevel
}

func Describe(event Event) (Descriptor, error) {
	spec, found := eventSpecs[event.code]
	if !found {
		return Descriptor{}, fmt.Errorf("unsupported operational event")
	}
	if event.resourceID != "" && !uuidPattern.MatchString(event.resourceID) {
		return Descriptor{}, fmt.Errorf("invalid operational event resource ID")
	}
	if event.sha256 != "" && !sha256Pattern.MatchString(event.sha256) {
		return Descriptor{}, fmt.Errorf("invalid operational event digest")
	}
	return Descriptor{Code: event.code, Scope: spec.scope, Level: spec.level}, nil
}

type record struct {
	SchemaVersion int            `json:"schema_version"`
	Timestamp     time.Time      `json:"timestamp"`
	Code          EventCode      `json:"code"`
	Scope         model.LogScope `json:"scope"`
	Level         model.LogLevel `json:"level"`
	ResourceID    string         `json:"resource_id,omitempty"`
	Generation    uint64         `json:"generation,omitempty"`
	Count         uint64         `json:"count,omitempty"`
	DurationMS    uint64         `json:"duration_ms,omitempty"`
	SHA256        string         `json:"sha256,omitempty"`
}

func EncodeRecord(event Event, at time.Time) ([]byte, error) {
	descriptor, err := Describe(event)
	if err != nil {
		return nil, err
	}
	if at.IsZero() {
		return nil, fmt.Errorf("operational event timestamp is required")
	}
	record := record{
		SchemaVersion: 1, Timestamp: at.UTC().Truncate(time.Millisecond), Code: descriptor.Code,
		Scope: descriptor.Scope, Level: descriptor.Level, ResourceID: event.resourceID,
		Generation: event.generation, Count: event.count, DurationMS: event.durationMS, SHA256: event.sha256,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode operational event: %w", err)
	}
	return append(encoded, '\n'), nil
}

type Emitter interface {
	Emit(context.Context, Event) error
}

type nopEmitter struct{}

func (nopEmitter) Emit(context.Context, Event) error { return nil }

type emitterContextKey struct{}

func WithEmitter(ctx context.Context, emitter Emitter) context.Context {
	if ctx == nil {
		panic("observability context is required")
	}
	if emitter == nil {
		return ctx
	}
	return context.WithValue(ctx, emitterContextKey{}, emitter)
}

func FromContext(ctx context.Context) Emitter {
	if ctx != nil {
		if emitter, ok := ctx.Value(emitterContextKey{}).(Emitter); ok && emitter != nil {
			return emitter
		}
	}
	return nopEmitter{}
}

func Emit(ctx context.Context, event Event) error {
	if _, err := Describe(event); err != nil {
		return err
	}
	return FromContext(ctx).Emit(ctx, event)
}

func EmitCode(ctx context.Context, code EventCode) error {
	event, err := NewEvent(code)
	if err != nil {
		return err
	}
	return Emit(ctx, event)
}

func EmitGeneration(ctx context.Context, code EventCode, generation uint64) error {
	event, err := NewEvent(code)
	if err != nil {
		return err
	}
	return Emit(ctx, event.WithGeneration(generation))
}

func EmitGenerationSHA256(ctx context.Context, code EventCode, generation uint64, digest string) error {
	event, err := NewEvent(code)
	if err != nil {
		return err
	}
	event, err = event.WithSHA256(digest)
	if err != nil {
		return err
	}
	return Emit(ctx, event.WithGeneration(generation))
}
