package output

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	RedactedMarker      = "<redacted>"
	SensitivePathMarker = "<sensitive-path>"
)

var ErrSensitiveSerialization = errors.New("sensitive value cannot be serialized")

type Classification string

const (
	ClassPublic        Classification = "public"
	ClassIdentifier    Classification = "identifier"
	ClassPublicPath    Classification = "public_path"
	ClassSensitivePath Classification = "sensitive_path"
	ClassSecret        Classification = "secret"
	ClassBody          Classification = "body"
)

type FieldRule struct {
	Classification  Classification
	AllowedInResult bool
}

var fieldRules = map[string]FieldRule{
	"authorization":        {Classification: ClassSecret},
	"authorization_header": {Classification: ClassSecret},
	"body":                 {Classification: ClassBody},
	"credential":           {Classification: ClassSecret},
	"credential_ref":       {Classification: ClassSecret},
	"invite_token":         {Classification: ClassSecret},
	"key":                  {Classification: ClassSecret},
	"passphrase":           {Classification: ClassSecret},
	"password":             {Classification: ClassSecret},
	"path":                 {Classification: ClassSensitivePath},
	"private_key":          {Classification: ClassSecret},
	"profile":              {Classification: ClassSecret},
	"profile_content":      {Classification: ClassSecret},
	"probe_url":            {Classification: ClassSensitivePath},
	"public_url":           {Classification: ClassSensitivePath},
	"recovery_token":       {Classification: ClassSecret},
	"request_body":         {Classification: ClassBody},
	"response_body":        {Classification: ClassBody},
	"secret":               {Classification: ClassSecret},
	"token":                {Classification: ClassSecret},
	"tunnel_token":         {Classification: ClassSecret},
	"url":                  {Classification: ClassSensitivePath},
	"webhook_path":         {Classification: ClassSensitivePath},

	"body_limit":            {Classification: ClassPublic, AllowedInResult: true},
	"credential_generation": {Classification: ClassIdentifier, AllowedInResult: true},
	"file_path":             {Classification: ClassPublicPath, AllowedInResult: true},
	"output_path":           {Classification: ClassPublicPath, AllowedInResult: true},
	"public_key":            {Classification: ClassPublic, AllowedInResult: true},
}

// RedactionMetadata returns a defensive copy of explicit output field rules.
// ClassifyField also applies conservative suffix/segment rules to unknown keys.
func RedactionMetadata() map[string]FieldRule {
	result := make(map[string]FieldRule, len(fieldRules))
	for key, rule := range fieldRules {
		result[key] = rule
	}
	return result
}

func ClassifyField(name string) FieldRule {
	normalized := strings.ToLower(name)
	if rule, found := fieldRules[normalized]; found {
		return rule
	}
	if strings.Contains(normalized, "request_body") || strings.Contains(normalized, "response_body") {
		return FieldRule{Classification: ClassBody}
	}
	if strings.Contains(normalized, "webhook_path") || strings.Contains(normalized, "public_url") || strings.Contains(normalized, "probe_url") {
		return FieldRule{Classification: ClassSensitivePath}
	}
	segments := strings.Split(normalized, "_")
	for index, segment := range segments {
		switch segment {
		case "secret", "token", "passphrase", "password", "credential", "authorization":
			return FieldRule{Classification: ClassSecret}
		case "private":
			if index+1 < len(segments) && segments[index+1] == "key" {
				return FieldRule{Classification: ClassSecret}
			}
		case "webhook":
			return FieldRule{Classification: ClassSensitivePath}
		}
	}
	return FieldRule{Classification: ClassPublic, AllowedInResult: true}
}

// Secret keeps raw secret bytes outside ordinary formatting and JSON paths.
// Use supplies a temporary copy to a narrow callback and clears that copy when
// the callback returns.
type Secret struct {
	value []byte
}

func NewSecret(value []byte) (Secret, error) {
	if len(value) == 0 {
		return Secret{}, fmt.Errorf("secret must not be empty")
	}
	return Secret{value: append([]byte(nil), value...)}, nil
}

func NewSecretString(value string) (Secret, error) {
	return NewSecret([]byte(value))
}

func (secret Secret) Use(callback func([]byte) error) error {
	if len(secret.value) == 0 {
		return fmt.Errorf("secret is not initialized")
	}
	if callback == nil {
		return fmt.Errorf("secret callback must not be nil")
	}
	temporary := append([]byte(nil), secret.value...)
	defer clear(temporary)
	return callback(temporary)
}

func (Secret) String() string   { return RedactedMarker }
func (Secret) GoString() string { return RedactedMarker }
func (Secret) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, RedactedMarker)
}
func (Secret) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (Secret) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// SensitivePath protects webhook/probe paths and URLs while allowing callers
// to pass the value to a narrowly scoped renderer or network adapter.
type SensitivePath struct {
	value string
}

func NewSensitivePath(value string) (SensitivePath, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
		return SensitivePath{}, fmt.Errorf("sensitive path must be a non-empty trimmed single line")
	}
	return SensitivePath{value: value}, nil
}

func (path SensitivePath) Use(callback func(string) error) error {
	if path.value == "" {
		return fmt.Errorf("sensitive path is not initialized")
	}
	if callback == nil {
		return fmt.Errorf("sensitive path callback must not be nil")
	}
	return callback(path.value)
}

func (SensitivePath) String() string   { return SensitivePathMarker }
func (SensitivePath) GoString() string { return SensitivePathMarker }
func (SensitivePath) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, SensitivePathMarker)
}
func (SensitivePath) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SensitivePath) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
