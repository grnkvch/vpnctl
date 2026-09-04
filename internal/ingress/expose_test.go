package ingress

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const (
	exposeTestNodeID      = "91000000-0000-4000-8000-000000000001"
	exposeTestExistingID  = "91000000-0000-4000-8000-000000000002"
	exposeTestNewID       = "91000000-0000-4000-8000-000000000003"
	exposeTestOtherNodeID = "91000000-0000-4000-8000-000000000004"
)

func TestNormalizeExposeUpstreamPortAndHostForms(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		input    string
		want     string
		loopback bool
	}{
		{input: "3000", want: "127.0.0.1:3000", loopback: true},
		{input: "00080", want: "127.0.0.1:80", loopback: true},
		{input: "127.0.0.1:3000", want: "127.0.0.1:3000", loopback: true},
		{input: "LOCALHOST:8080", want: "localhost:8080", loopback: true},
		{input: "[0:0:0:0:0:0:0:1]:443", want: "[::1]:443", loopback: true},
		{input: "10.0.0.5:8080", want: "10.0.0.5:8080"},
		{input: "Example.COM:8443", want: "example.com:8443"},
	} {
		normalized, err := NormalizeExposeUpstream(test.input)
		if err != nil {
			t.Fatalf("NormalizeExposeUpstream(%q): %v", test.input, err)
		}
		if normalized.Value != test.want || normalized.Loopback != test.loopback {
			t.Errorf("NormalizeExposeUpstream(%q) = %+v, want %q loopback=%t", test.input, normalized, test.want, test.loopback)
		}
	}
}

func TestNormalizeExposeUpstreamRejectsInvalidForms(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		"", " 3000", "0", "65536", "+3000", "localhost", "localhost:", ":3000",
		"0.0.0.0:3000", "[::]:3000", "224.0.0.1:3000", "[::ffff:127.0.0.1]:3000",
		"bad_name:3000", "example.com.:3000", "127.0.0.1:3x", "127.0.0.01:3000", "127.1:3000",
		"[2001:db8::1%eth0]:3000",
	} {
		if _, err := NormalizeExposeUpstream(input); !errors.Is(err, ErrExposeInvalidInput) {
			t.Errorf("NormalizeExposeUpstream(%q) error = %v", input, err)
		}
	}
}

func TestExposeNormalizerAllocatesImmutableIdentityAndGeneratedExactPath(t *testing.T) {
	t.Parallel()

	existing := testExpose(exposeTestExistingID, "existing", model.RouteExact, "/existing", model.ExposeReady, 20000)
	namespace := ExposeNamespace{NodeID: exposeTestNodeID, StateGeneration: 7, Existing: []model.Expose{existing}}
	before := append([]model.Expose(nil), namespace.Existing...)
	uuidCalls := 0
	normalizer := NewExposeNormalizer(ExposeNormalizerRuntime{
		Entropy: bytes.NewReader(bytes.Repeat([]byte{0x42}, GeneratedExposePathEntropyBytes)),
		NewUUID: func() (string, error) {
			uuidCalls++
			if uuidCalls == 1 {
				return exposeTestExistingID, nil
			}
			return exposeTestNewID, nil
		},
		Now: func() time.Time { return time.Date(2026, 9, 4, 12, 0, 0, 123, time.FixedZone("offset", 3600)) },
	})
	plan, err := normalizer.Normalize(namespace, ExposeCreateRequest{Upstream: "3000", Name: "telegram"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ExposeID != exposeTestNewID || plan.NodeID != exposeTestNodeID || plan.Upstream != "127.0.0.1:3000" ||
		plan.RouteMode != model.RouteExact || plan.Name != "telegram" || plan.NonLoopback || len(plan.Warnings) != 0 ||
		plan.ExpectedStateGeneration != 7 || plan.CreatedAt.Location() != time.UTC || uuidCalls != 2 {
		t.Fatalf("normalized expose plan = %+v, uuid calls=%d", plan, uuidCalls)
	}
	if !strings.HasPrefix(plan.Path, GeneratedExposePathPrefix) {
		t.Fatalf("generated path = %q", plan.Path)
	}
	token := strings.TrimPrefix(plan.Path, GeneratedExposePathPrefix)
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != GeneratedExposePathEntropyBytes {
		t.Fatalf("generated path entropy = %d bytes, %v", len(decoded), err)
	}
	if !reflect.DeepEqual(namespace.Existing, before) {
		t.Fatal("normalization mutated the authoritative namespace")
	}
	if _, err := json.Marshal(plan); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("expose plan serialization error = %v", err)
	}
}

func TestExposeNormalizerPrefixAndNonLoopbackOptIn(t *testing.T) {
	t.Parallel()

	normalizer := deterministicExposeNormalizer()
	plan, err := normalizer.Normalize(emptyExposeNamespace(), ExposeCreateRequest{
		Upstream: "10.0.0.5:3000", Name: "api", Path: "/api/", Prefix: true, AllowNonLoopback: true,
		LimitOverrides: ExposeLimitOverrides{BodyLimitSet: true, BodyBytes: 2 << 20, TimeoutSet: true, TimeoutSeconds: 30},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Path != "/api" || plan.RouteMode != model.RoutePrefix || !plan.NonLoopback || len(plan.Warnings) != 1 ||
		plan.Warnings[0].Code != ExposeNonLoopbackWarningCode ||
		plan.Limits != (ExposeLimits{BodyBytes: 2 << 20, UpstreamTimeoutSeconds: 30, ConcurrentRequests: 40}) {
		t.Fatalf("prefix/non-loopback plan = %+v", plan)
	}
}

func TestExposePlanValidationRejectsTampering(t *testing.T) {
	t.Parallel()

	base, err := deterministicExposeNormalizer().Normalize(emptyExposeNamespace(), ExposeCreateRequest{Upstream: "3000", Path: "/hook"})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ExposePlan){
		func(plan *ExposePlan) { plan.ExposeID = "not-an-id" },
		func(plan *ExposePlan) { plan.Upstream = "127.0.0.1:03000" },
		func(plan *ExposePlan) { plan.NonLoopback = true },
		func(plan *ExposePlan) { plan.Path = "/hook/%2e" },
		func(plan *ExposePlan) { plan.RouteMode = "unknown" },
		func(plan *ExposePlan) { plan.ExpectedStateGeneration = 0 },
		func(plan *ExposePlan) {
			plan.Warnings = []ExposePlanWarning{{Code: "unexpected", Message: "unexpected"}}
		},
	} {
		candidate := base
		candidate.Warnings = append([]ExposePlanWarning(nil), base.Warnings...)
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrExposeInvalidInput) {
			t.Errorf("tampered plan error = %v", err)
		}
	}
}

func TestExposeNormalizerRejectsOptInNameRouteAndReservedConflicts(t *testing.T) {
	t.Parallel()

	existing := testExpose(exposeTestExistingID, "telegram", model.RoutePrefix, "/api", model.ExposeReady, 20000)
	namespace := ExposeNamespace{NodeID: exposeTestNodeID, StateGeneration: 7, Existing: []model.Expose{existing}}
	for _, test := range []struct {
		name    string
		request ExposeCreateRequest
		want    error
	}{
		{name: "non-loopback", request: ExposeCreateRequest{Upstream: "10.0.0.5:3000", Path: "/other"}, want: ErrExposeNonLoopbackOptIn},
		{name: "name case", request: ExposeCreateRequest{Upstream: "3000", Name: "TELEGRAM", Path: "/other"}, want: ErrExposeNameConflict},
		{name: "exact inside prefix", request: ExposeCreateRequest{Upstream: "3000", Name: "other", Path: "/api/v1"}, want: ErrExposeRouteConflict},
		{name: "nested prefix", request: ExposeCreateRequest{Upstream: "3000", Name: "other", Path: "/api/v1", Prefix: true}, want: ErrExposeRouteConflict},
		{name: "reserved root", request: ExposeCreateRequest{Upstream: "3000", Path: "/.well-known/vpnctl"}, want: ErrExposeReservedPath},
		{name: "reserved child", request: ExposeCreateRequest{Upstream: "3000", Path: "/.well-known/vpnctl/enroll"}, want: ErrExposeReservedPath},
		{name: "prefix without path", request: ExposeCreateRequest{Upstream: "3000", Prefix: true}, want: ErrExposeInvalidInput},
	} {
		if _, err := deterministicExposeNormalizer().Normalize(namespace, test.request); !errors.Is(err, test.want) {
			t.Errorf("%s error = %v, want %v", test.name, err, test.want)
		}
	}
}

func TestExposeNormalizerAllowsSameNameOnAnotherNodeButKeepsRoutesGlobal(t *testing.T) {
	t.Parallel()

	other := testExpose(exposeTestExistingID, "telegram", model.RouteExact, "/other-node", model.ExposeReady, 20000)
	other.NodeID = exposeTestOtherNodeID
	namespace := ExposeNamespace{NodeID: exposeTestNodeID, StateGeneration: 7, Existing: []model.Expose{other}}
	plan, err := deterministicExposeNormalizer().Normalize(namespace, ExposeCreateRequest{
		Upstream: "3000", Name: "TELEGRAM", Path: "/this-node",
	})
	if err != nil || plan.Name != "TELEGRAM" {
		t.Fatalf("same name on another node plan = %+v, %v", plan, err)
	}
	if _, err := deterministicExposeNormalizer().Normalize(namespace, ExposeCreateRequest{
		Upstream: "3000", Name: "different", Path: "/other-node",
	}); !errors.Is(err, ErrExposeRouteConflict) {
		t.Fatalf("cross-node route conflict error = %v", err)
	}
}

func TestExposeGeneratedPathFailsClosedOnAncestorPrefixAndEntropyError(t *testing.T) {
	t.Parallel()

	existing := testExpose(exposeTestExistingID, "catch-generated", model.RoutePrefix, "/hooks", model.ExposeReady, 20000)
	reads := 0
	reader := countingByteReader{read: func(buffer []byte) (int, error) {
		reads++
		for index := range buffer {
			buffer[index] = byte(reads)
		}
		return len(buffer), nil
	}}
	normalizer := NewExposeNormalizer(ExposeNormalizerRuntime{
		Entropy: reader, NewUUID: func() (string, error) { return exposeTestNewID, nil }, Now: time.Now,
	})
	if _, err := normalizer.Normalize(ExposeNamespace{NodeID: exposeTestNodeID, StateGeneration: 1, Existing: []model.Expose{existing}}, ExposeCreateRequest{Upstream: "3000"}); !errors.Is(err, ErrExposePathGeneration) {
		t.Fatalf("generated ancestor collision error = %v", err)
	}
	if reads != GeneratedExposePathRetryLimit {
		t.Fatalf("path generation reads = %d", reads)
	}

	normalizer = NewExposeNormalizer(ExposeNormalizerRuntime{
		Entropy: errorReader{}, NewUUID: func() (string, error) { return exposeTestNewID, nil }, Now: time.Now,
	})
	if _, err := normalizer.Normalize(emptyExposeNamespace(), ExposeCreateRequest{Upstream: "3000"}); !errors.Is(err, ErrExposePathGeneration) || !strings.Contains(err.Error(), "entropy") {
		t.Fatalf("entropy failure error = %v", err)
	}
}

func TestGeneratedExposePathUniquenessAndShapeProperty(t *testing.T) {
	t.Parallel()

	namespace := emptyExposeNamespace()
	normalizer := NewExposeNormalizer(ExposeNormalizerRuntime{Entropy: rand.Reader, NewUUID: model.NewUUID, Now: time.Now})
	seen := make(map[string]struct{})
	for sample := 0; sample < 128; sample++ {
		plan, err := normalizer.Normalize(namespace, ExposeCreateRequest{Upstream: "3000"})
		if err != nil {
			t.Fatalf("sample %d: %v", sample, err)
		}
		if _, duplicate := seen[plan.Path]; duplicate {
			t.Fatalf("generated path collision at sample %d", sample)
		}
		seen[plan.Path] = struct{}{}
		namespace.Existing = append(namespace.Existing, testExpose(plan.ExposeID, "", plan.RouteMode, plan.Path, model.ExposePending, 20000+sample))
	}
}

func TestExposeUpstreamPortShorthandProperty(t *testing.T) {
	t.Parallel()

	for port := 1; port <= 65535; port += 97 {
		normalized, err := NormalizeExposeUpstream(strings.Repeat("0", port%4) + strconv.Itoa(port))
		if err != nil || normalized.Value != "127.0.0.1:"+strconv.Itoa(port) || !normalized.Loopback {
			t.Fatalf("port %d normalized to %+v, %v", port, normalized, err)
		}
	}
}

func deterministicExposeNormalizer() *ExposeNormalizer {
	return NewExposeNormalizer(ExposeNormalizerRuntime{
		Entropy: bytes.NewReader(bytes.Repeat([]byte{0x21}, GeneratedExposePathEntropyBytes)),
		NewUUID: func() (string, error) { return exposeTestNewID, nil },
		Now:     func() time.Time { return time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC) },
	})
}

func emptyExposeNamespace() ExposeNamespace {
	return ExposeNamespace{NodeID: exposeTestNodeID, StateGeneration: 1, Existing: []model.Expose{}}
}

func testExpose(id, name string, mode model.RouteMode, path string, state model.ExposeState, tunnelPort int) model.Expose {
	return model.Expose{
		SchemaVersion: model.ResourceSchemaVersion, ID: id, NodeID: exposeTestNodeID, Name: name,
		Upstream: "127.0.0.1:3000", RouteMode: mode, Path: path,
		BodyLimitBytes: 1 << 20, UpstreamTimeoutSeconds: 15, ConcurrentRequests: 40,
		TunnelPort: tunnelPort, State: state, Generation: 1, CreatedAt: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC),
	}
}

type countingByteReader struct {
	read func([]byte) (int, error)
}

func (reader countingByteReader) Read(buffer []byte) (int, error) { return reader.read(buffer) }

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
