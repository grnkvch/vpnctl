package ingress

import (
	"errors"
	"reflect"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestDefaultGatewayHardLimitsMatchMeasuredContract(t *testing.T) {
	t.Parallel()

	limits := DefaultGatewayHardLimits()
	if err := limits.Validate(); err != nil {
		t.Fatal(err)
	}
	if limits.ConnectionLimit != 256 || limits.GatewayConcurrentRequests != 64 || limits.HTTP2ConcurrentStreams != 64 ||
		limits.DefaultExposeConcurrent != 40 || limits.MaximumBodyBytes != 8*1024*1024 || limits.DefaultExposeBodyBytes != 1024*1024 ||
		limits.DefaultUpstreamTimeoutSeconds != 15 || limits.MaximumUpstreamTimeoutSeconds != 60 ||
		limits.GracefulShutdownSeconds != 10 || limits.HeaderBufferCount != 4 || limits.HeaderBufferBytes != 8192 {
		t.Fatalf("gateway hard limits = %+v", limits)
	}
}

func TestGatewayHardLimitsRejectEveryUnversionedChange(t *testing.T) {
	t.Parallel()

	mutations := []func(*GatewayHardLimits){
		func(value *GatewayHardLimits) { value.ConnectionLimit++ },
		func(value *GatewayHardLimits) { value.GatewayConcurrentRequests++ },
		func(value *GatewayHardLimits) { value.HTTP2ConcurrentStreams++ },
		func(value *GatewayHardLimits) { value.DefaultExposeConcurrent++ },
		func(value *GatewayHardLimits) { value.MaximumBodyBytes++ },
		func(value *GatewayHardLimits) { value.DefaultExposeBodyBytes++ },
		func(value *GatewayHardLimits) { value.DefaultUpstreamTimeoutSeconds++ },
		func(value *GatewayHardLimits) { value.MaximumUpstreamTimeoutSeconds++ },
		func(value *GatewayHardLimits) { value.GracefulShutdownSeconds++ },
		func(value *GatewayHardLimits) { value.HeaderBufferCount++ },
		func(value *GatewayHardLimits) { value.HeaderBufferBytes++ },
	}
	for index, mutate := range mutations {
		candidate := DefaultGatewayHardLimits()
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrIngressLimitsInvalid) {
			t.Errorf("mutation %d error = %v", index, err)
		}
	}
}

func TestParseAndResolveExposeLimitOverrides(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		arguments []string
		want      ExposeLimits
	}{
		{arguments: nil, want: ExposeLimits{BodyBytes: 1 << 20, UpstreamTimeoutSeconds: 15, ConcurrentRequests: 40}},
		{arguments: []string{"--body-limit", "2MiB", "--timeout", "30s"}, want: ExposeLimits{BodyBytes: 2 << 20, UpstreamTimeoutSeconds: 30, ConcurrentRequests: 40}},
		{arguments: []string{"--timeout=1m", "--body-limit=512KiB"}, want: ExposeLimits{BodyBytes: 512 << 10, UpstreamTimeoutSeconds: 60, ConcurrentRequests: 40}},
		{arguments: []string{"--body-limit", "4096", "--timeout", "7"}, want: ExposeLimits{BodyBytes: 4096, UpstreamTimeoutSeconds: 7, ConcurrentRequests: 40}},
	} {
		overrides, err := ParseExposeLimitOptions(test.arguments)
		if err != nil {
			t.Fatalf("ParseExposeLimitOptions(%v): %v", test.arguments, err)
		}
		resolved, err := ResolveExposeLimits(DefaultGatewayHardLimits(), overrides)
		if err != nil || !reflect.DeepEqual(resolved, test.want) {
			t.Errorf("ResolveExposeLimits(%v) = %+v, %v; want %+v", test.arguments, resolved, err, test.want)
		}
	}
}

func TestExposeLimitParserRejectsImpossibleAndRawProviderInput(t *testing.T) {
	t.Parallel()

	for _, arguments := range [][]string{
		{"--body-limit", "0"}, {"--body-limit", "8388609"}, {"--body-limit", "9MiB"},
		{"--body-limit", "1.5MiB"}, {"--body-limit", "1m"}, {"--body-limit", "1MiB; proxy_pass=http://attacker"},
		{"--timeout", "0"}, {"--timeout", "61s"}, {"--timeout", "500ms"}, {"--timeout", "0.5m"}, {"--timeout", "1m0s"},
		{"--timeout", "15s; proxy_next_upstream=on"},
		{"--body-limit", "1MiB", "--body-limit", "2MiB"}, {"--timeout=15s", "--timeout=20s"},
		{"--proxy-read-timeout", "15s"}, {"--nginx-directive=proxy_next_upstream on"}, {"proxy_buffering=on"},
	} {
		if _, err := ParseExposeLimitOptions(arguments); err == nil {
			t.Errorf("ParseExposeLimitOptions(%v) accepted unsafe input", arguments)
		}
	}
}

func TestExposeLimitParserClassifiesRawProviderOptions(t *testing.T) {
	t.Parallel()

	for _, arguments := range [][]string{
		{"--proxy-read-timeout", "15s"},
		{"--nginx-directive=proxy_next_upstream on"},
		{"proxy_buffering=on"},
	} {
		if _, err := ParseExposeLimitOptions(arguments); !errors.Is(err, ErrUnsupportedExposeLimitOption) {
			t.Errorf("ParseExposeLimitOptions(%v) error = %v", arguments, err)
		}
	}
}

func TestResolveExposeLimitsRejectsImpossibleTypedValues(t *testing.T) {
	t.Parallel()

	for _, overrides := range []ExposeLimitOverrides{
		{BodyLimitSet: true, BodyBytes: -1},
		{BodyLimitSet: true, BodyBytes: model.MaximumExposeBodyLimitBytes + 1},
		{TimeoutSet: true, TimeoutSeconds: -1},
		{TimeoutSet: true, TimeoutSeconds: model.MaximumExposeUpstreamTimeoutSeconds + 1},
		{BodyBytes: 1},
		{TimeoutSeconds: 1},
	} {
		if _, err := ResolveExposeLimits(DefaultGatewayHardLimits(), overrides); !errors.Is(err, ErrExposeLimitInvalid) {
			t.Errorf("ResolveExposeLimits(%+v) error = %v", overrides, err)
		}
	}
}

func TestExposeLimitResolutionPropertyStaysInsideHardBounds(t *testing.T) {
	t.Parallel()

	hard := DefaultGatewayHardLimits()
	for body := int64(1); body <= hard.MaximumBodyBytes; body += 65537 {
		for timeout := 1; timeout <= hard.MaximumUpstreamTimeoutSeconds; timeout++ {
			resolved, err := ResolveExposeLimits(hard, ExposeLimitOverrides{
				BodyLimitSet: true, BodyBytes: body, TimeoutSet: true, TimeoutSeconds: timeout,
			})
			if err != nil || resolved.BodyBytes != body || resolved.UpstreamTimeoutSeconds != timeout ||
				resolved.ConcurrentRequests != hard.DefaultExposeConcurrent {
				t.Fatalf("body=%d timeout=%d resolved=%+v error=%v", body, timeout, resolved, err)
			}
		}
	}
}

func TestExposeNormalizerRejectsImpossibleLimitsBeforeEntropyOrIdentity(t *testing.T) {
	t.Parallel()

	read := false
	generated := false
	normalizer := NewExposeNormalizer(ExposeNormalizerRuntime{
		Entropy: countingByteReader{read: func([]byte) (int, error) { read = true; return 0, nil }},
		NewUUID: func() (string, error) { generated = true; return exposeTestNewID, nil },
	})
	_, err := normalizer.Normalize(emptyExposeNamespace(), ExposeCreateRequest{
		Upstream: "3000", LimitOverrides: ExposeLimitOverrides{BodyLimitSet: true, BodyBytes: model.MaximumExposeBodyLimitBytes + 1},
	})
	if !errors.Is(err, ErrExposeLimitInvalid) || read || generated {
		t.Fatalf("invalid limits error=%v entropy=%t identity=%t", err, read, generated)
	}
}
