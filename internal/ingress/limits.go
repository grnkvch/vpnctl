package ingress

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	DefaultIngressConnectionLimit                 = 256
	DefaultIngressGatewayConcurrentRequests       = 64
	DefaultIngressHTTP2ConcurrentStreams          = 64
	DefaultExposeConcurrentRequests               = model.MaximumExposeConcurrentRequests
	DefaultIngressBodyLimitBytes            int64 = model.MaximumExposeBodyLimitBytes
	DefaultExposeBodyLimitBytes             int64 = 1024 * 1024
	DefaultExposeUpstreamTimeoutSeconds           = 15
	DefaultIngressGracefulShutdownSeconds         = 10
	DefaultIngressHeaderBufferCount               = 4
	DefaultIngressHeaderBufferBytes               = 8192
)

var (
	ErrIngressLimitsInvalid         = errors.New("ingress hard limits are invalid")
	ErrExposeLimitInvalid           = errors.New("expose limit override is invalid")
	ErrUnsupportedExposeLimitOption = errors.New("unsupported expose limit option")
)

// GatewayHardLimits is independent from an nginx/Caddy configuration grammar.
// It is the measured v1 contract that every provider renderer must enforce.
type GatewayHardLimits struct {
	ConnectionLimit               int
	GatewayConcurrentRequests     int
	HTTP2ConcurrentStreams        int
	DefaultExposeConcurrent       int
	MaximumBodyBytes              int64
	DefaultExposeBodyBytes        int64
	DefaultUpstreamTimeoutSeconds int
	MaximumUpstreamTimeoutSeconds int
	GracefulShutdownSeconds       int
	HeaderBufferCount             int
	HeaderBufferBytes             int
}

func DefaultGatewayHardLimits() GatewayHardLimits {
	return GatewayHardLimits{
		ConnectionLimit:               DefaultIngressConnectionLimit,
		GatewayConcurrentRequests:     DefaultIngressGatewayConcurrentRequests,
		HTTP2ConcurrentStreams:        DefaultIngressHTTP2ConcurrentStreams,
		DefaultExposeConcurrent:       DefaultExposeConcurrentRequests,
		MaximumBodyBytes:              DefaultIngressBodyLimitBytes,
		DefaultExposeBodyBytes:        DefaultExposeBodyLimitBytes,
		DefaultUpstreamTimeoutSeconds: DefaultExposeUpstreamTimeoutSeconds,
		MaximumUpstreamTimeoutSeconds: model.MaximumExposeUpstreamTimeoutSeconds,
		GracefulShutdownSeconds:       DefaultIngressGracefulShutdownSeconds,
		HeaderBufferCount:             DefaultIngressHeaderBufferCount,
		HeaderBufferBytes:             DefaultIngressHeaderBufferBytes,
	}
}

// Validate rejects silent widening or weakening of the versioned measured
// contract. A future limit revision must be explicit and versioned.
func (limits GatewayHardLimits) Validate() error {
	want := DefaultGatewayHardLimits()
	if limits != want {
		return fmt.Errorf("%w: limits differ from the measured v1 contract", ErrIngressLimitsInvalid)
	}
	return nil
}

type ExposeLimitOverrides struct {
	BodyLimitSet   bool
	BodyBytes      int64
	TimeoutSet     bool
	TimeoutSeconds int
}

type ExposeLimits struct {
	BodyBytes              int64
	UpstreamTimeoutSeconds int
	ConcurrentRequests     int
}

func ResolveExposeLimits(limits GatewayHardLimits, overrides ExposeLimitOverrides) (ExposeLimits, error) {
	if err := limits.Validate(); err != nil {
		return ExposeLimits{}, err
	}
	if (!overrides.BodyLimitSet && overrides.BodyBytes != 0) || (!overrides.TimeoutSet && overrides.TimeoutSeconds != 0) {
		return ExposeLimits{}, fmt.Errorf("%w: unset override contains a value", ErrExposeLimitInvalid)
	}
	resolved := ExposeLimits{
		BodyBytes:              limits.DefaultExposeBodyBytes,
		UpstreamTimeoutSeconds: limits.DefaultUpstreamTimeoutSeconds,
		ConcurrentRequests:     limits.DefaultExposeConcurrent,
	}
	if overrides.BodyLimitSet {
		if overrides.BodyBytes < 1 || overrides.BodyBytes > limits.MaximumBodyBytes {
			return ExposeLimits{}, fmt.Errorf("%w: body limit must be between 1 and %d bytes", ErrExposeLimitInvalid, limits.MaximumBodyBytes)
		}
		resolved.BodyBytes = overrides.BodyBytes
	}
	if overrides.TimeoutSet {
		if overrides.TimeoutSeconds < 1 || overrides.TimeoutSeconds > limits.MaximumUpstreamTimeoutSeconds {
			return ExposeLimits{}, fmt.Errorf("%w: timeout must be between 1 and %d seconds", ErrExposeLimitInvalid, limits.MaximumUpstreamTimeoutSeconds)
		}
		resolved.UpstreamTimeoutSeconds = overrides.TimeoutSeconds
	}
	if err := resolved.Validate(limits); err != nil {
		return ExposeLimits{}, err
	}
	return resolved, nil
}

func (limits ExposeLimits) Validate(gateway GatewayHardLimits) error {
	if err := gateway.Validate(); err != nil {
		return err
	}
	if limits.BodyBytes < 1 || limits.BodyBytes > gateway.MaximumBodyBytes ||
		limits.UpstreamTimeoutSeconds < 1 || limits.UpstreamTimeoutSeconds > gateway.MaximumUpstreamTimeoutSeconds ||
		limits.ConcurrentRequests != gateway.DefaultExposeConcurrent {
		return fmt.Errorf("%w: resolved limits exceed or bypass the gateway contract", ErrExposeLimitInvalid)
	}
	return nil
}

// ParseExposeLimitOptions accepts only the two public provider-neutral flags.
// It deliberately rejects every unknown option, including raw proxy directives.
func ParseExposeLimitOptions(arguments []string) (ExposeLimitOverrides, error) {
	result := ExposeLimitOverrides{}
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		name, value, inline := strings.Cut(argument, "=")
		if !strings.HasPrefix(name, "--") {
			return ExposeLimitOverrides{}, fmt.Errorf("%w: %s", ErrUnsupportedExposeLimitOption, name)
		}
		if !inline {
			if index+1 >= len(arguments) {
				return ExposeLimitOverrides{}, fmt.Errorf("%w: %s requires a value", ErrExposeLimitInvalid, name)
			}
			index++
			value = arguments[index]
		}
		if value == "" {
			return ExposeLimitOverrides{}, fmt.Errorf("%w: %s requires a value", ErrExposeLimitInvalid, name)
		}
		switch name {
		case "--body-limit":
			if result.BodyLimitSet {
				return ExposeLimitOverrides{}, fmt.Errorf("%w: --body-limit is duplicated", ErrExposeLimitInvalid)
			}
			parsed, err := parseBodyLimit(value)
			if err != nil {
				return ExposeLimitOverrides{}, err
			}
			result.BodyLimitSet, result.BodyBytes = true, parsed
		case "--timeout":
			if result.TimeoutSet {
				return ExposeLimitOverrides{}, fmt.Errorf("%w: --timeout is duplicated", ErrExposeLimitInvalid)
			}
			parsed, err := parseUpstreamTimeout(value)
			if err != nil {
				return ExposeLimitOverrides{}, err
			}
			result.TimeoutSet, result.TimeoutSeconds = true, parsed
		default:
			return ExposeLimitOverrides{}, fmt.Errorf("%w: %s", ErrUnsupportedExposeLimitOption, name)
		}
	}
	return result, nil
}

func parseBodyLimit(value string) (int64, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, ";\r\n\x00") {
		return 0, fmt.Errorf("%w: body limit must be bytes, KiB, or MiB", ErrExposeLimitInvalid)
	}
	multiplier := int64(1)
	number := value
	for _, suffix := range []struct {
		text       string
		multiplier int64
	}{{"MiB", 1024 * 1024}, {"KiB", 1024}, {"B", 1}} {
		if strings.HasSuffix(value, suffix.text) {
			number = strings.TrimSuffix(value, suffix.text)
			multiplier = suffix.multiplier
			break
		}
	}
	parsed, err := strconv.ParseUint(number, 10, 63)
	if err != nil || parsed == 0 || parsed > uint64(model.MaximumExposeBodyLimitBytes)/uint64(multiplier) {
		return 0, fmt.Errorf("%w: body limit must be between 1 byte and 8MiB", ErrExposeLimitInvalid)
	}
	return int64(parsed) * multiplier, nil
}

func parseUpstreamTimeout(value string) (int, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, ";\r\n\x00") {
		return 0, fmt.Errorf("%w: timeout must be a whole-second duration", ErrExposeLimitInvalid)
	}
	seconds := value
	if value == "1m" {
		seconds = "60"
	} else if strings.HasSuffix(value, "s") {
		seconds = strings.TrimSuffix(value, "s")
	}
	if !allDecimal(seconds) {
		return 0, fmt.Errorf("%w: timeout must be between 1s and 60s in whole seconds", ErrExposeLimitInvalid)
	}
	parsed, err := strconv.Atoi(seconds)
	if err != nil || parsed < 1 || parsed > model.MaximumExposeUpstreamTimeoutSeconds {
		return 0, fmt.Errorf("%w: timeout must be between 1s and 60s in whole seconds", ErrExposeLimitInvalid)
	}
	return parsed, nil
}
