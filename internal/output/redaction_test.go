package output

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRedactionFormattingGolden(t *testing.T) {
	t.Parallel()

	secret := mustSecret(t, "token-canary-7K3M2P")
	path := mustSensitivePath(t, "/telegram/webhook/path-canary-9X2Q")
	formatted := fmt.Sprintf(
		"secret string: %s\nsecret value: %v\nsecret quoted: %q\nsecret detail: %#v\npath string: %s\npath value: %v\npath quoted: %q\npath detail: %#v\n",
		secret, secret, secret, secret, path, path, path, path,
	)
	want, err := os.ReadFile(filepath.Join("testdata", "redaction.golden"))
	if err != nil {
		t.Fatalf("read redaction golden: %v", err)
	}
	if formatted != string(want) {
		t.Fatalf("redaction golden mismatch\nwant:\n%s\ngot:\n%s", want, formatted)
	}
	for _, canary := range []string{"token-canary-7K3M2P", "/telegram/webhook/path-canary-9X2Q"} {
		if strings.Contains(formatted, canary) {
			t.Errorf("formatted output leaked %q", canary)
		}
	}
}

func TestSensitiveValuesRefuseSerializationAndGenericResults(t *testing.T) {
	t.Parallel()

	secret := mustSecret(t, "private-key-canary")
	path := mustSensitivePath(t, "/webhook/path-canary")
	for name, value := range map[string]any{"secret": secret, "path": path} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(value)
			if !errors.Is(err, ErrSensitiveSerialization) {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if bytes.Contains(encoded, []byte("canary")) {
				t.Fatalf("json.Marshal() leaked sensitive bytes: %q", encoded)
			}

			result := NewResult("status", StatusOK, CategorySuccess, SafeObject{"value": value})
			var human bytes.Buffer
			if err := RenderHuman(&human, result); err == nil {
				t.Fatal("RenderHuman() accepted an opaque sensitive value")
			}
			if human.Len() != 0 {
				t.Fatalf("RenderHuman() wrote partial sensitive output: %q", human.String())
			}
			var automation bytes.Buffer
			if err := RenderJSON(&automation, result); err == nil {
				t.Fatal("RenderJSON() accepted an opaque sensitive value")
			}
			if automation.Len() != 0 {
				t.Fatalf("RenderJSON() wrote partial sensitive output: %q", automation.String())
			}
		})
	}
}

func TestCentralFieldClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		class   Classification
		allowed bool
	}{
		{name: "invite_token", class: ClassSecret},
		{name: "control_private_key_pem", class: ClassSecret},
		{name: "profile", class: ClassSecret},
		{name: "authorization_header", class: ClassSecret},
		{name: "request_body_json", class: ClassBody},
		{name: "response_body", class: ClassBody},
		{name: "webhook_path", class: ClassSensitivePath},
		{name: "path", class: ClassSensitivePath},
		{name: "probe_url", class: ClassSensitivePath},
		{name: "output_path", class: ClassPublicPath, allowed: true},
		{name: "public_key", class: ClassPublic, allowed: true},
		{name: "credential_generation", class: ClassIdentifier, allowed: true},
		{name: "body_limit", class: ClassPublic, allowed: true},
		{name: "generation", class: ClassPublic, allowed: true},
	}
	for _, test := range tests {
		rule := ClassifyField(test.name)
		if rule.Classification != test.class || rule.AllowedInResult != test.allowed {
			t.Errorf("ClassifyField(%q) = %+v, want class=%s allowed=%t", test.name, rule, test.class, test.allowed)
		}
	}

	metadata := RedactionMetadata()
	metadata["token"] = FieldRule{Classification: ClassPublic, AllowedInResult: true}
	if ClassifyField("token").AllowedInResult {
		t.Fatal("RedactionMetadata() exposed mutable central rules")
	}
}

func TestResultValidationUsesCentralClassification(t *testing.T) {
	t.Parallel()

	for _, key := range []string{
		"token", "api_token", "key", "private_key", "control_private_key_pem", "profile", "authorization_header",
		"request_body", "response_body_json", "webhook_path", "path", "url",
	} {
		result := NewResult("status", StatusOK, CategorySuccess, SafeObject{key: "canary"})
		if err := result.Validate(); err == nil {
			t.Errorf("Result.Validate() accepted centrally redacted field %q", key)
		}
	}
	for _, key := range []string{"public_key", "credential_generation", "body_limit", "output_path", "generation"} {
		result := NewResult("status", StatusOK, CategorySuccess, SafeObject{key: "public"})
		if err := result.Validate(); err != nil {
			t.Errorf("Result.Validate() rejected public field %q: %v", key, err)
		}
	}
}

func TestSensitiveUseCallbacksAreExplicit(t *testing.T) {
	t.Parallel()

	secret := mustSecret(t, "use-secret-canary")
	var secretCopy []byte
	if err := secret.Use(func(value []byte) error {
		secretCopy = append([]byte(nil), value...)
		return nil
	}); err != nil {
		t.Fatalf("Secret.Use() error = %v", err)
	}
	if string(secretCopy) != "use-secret-canary" {
		t.Fatalf("Secret.Use() value = %q", secretCopy)
	}
	path := mustSensitivePath(t, "/use/path-canary")
	var pathCopy string
	if err := path.Use(func(value string) error { pathCopy = value; return nil }); err != nil {
		t.Fatalf("SensitivePath.Use() error = %v", err)
	}
	if pathCopy != "/use/path-canary" {
		t.Fatalf("SensitivePath.Use() value = %q", pathCopy)
	}
}

func TestSecretAcceptsArbitraryBinaryMaterial(t *testing.T) {
	t.Parallel()

	input := []byte{0x00, 0x01, 0x80, 0xff}
	secret, err := NewSecret(input)
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	input[1] = 0xff
	var used []byte
	if err := secret.Use(func(value []byte) error {
		used = append([]byte(nil), value...)
		return nil
	}); err != nil {
		t.Fatalf("Secret.Use() error = %v", err)
	}
	if !bytes.Equal(used, []byte{0x00, 0x01, 0x80, 0xff}) {
		t.Fatalf("Secret.Use() value = %x", used)
	}
}

func TestSecretDestroyClearsRetainedValue(t *testing.T) {
	t.Parallel()

	secret := mustSecret(t, "short-lived-token")
	secret.Destroy()
	if err := secret.Use(func([]byte) error { return nil }); err == nil {
		t.Fatal("Secret.Use() succeeded after Destroy()")
	}
	secret.Destroy()
	var nilSecret *Secret
	nilSecret.Destroy()
}

func FuzzOpaqueSensitiveFormatting(f *testing.F) {
	for _, seed := range []string{"invite token", "private key", "Authorization: Bearer abc", "request body", "/telegram/webhook"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1024 {
			return
		}
		canary := "BEGIN" + hex.EncodeToString([]byte(input)) + "END"
		secret, err := NewSecretString(canary)
		if err != nil {
			t.Skip()
		}
		path, err := NewSensitivePath("/hook/" + canary)
		if err != nil {
			t.Skip()
		}
		outputs := []string{
			fmt.Sprintf("%s", secret), fmt.Sprintf("%v", secret), fmt.Sprintf("%q", secret), fmt.Sprintf("%#v", secret), fmt.Sprintf("%x", secret),
			fmt.Sprintf("%s", path), fmt.Sprintf("%v", path), fmt.Sprintf("%q", path), fmt.Sprintf("%#v", path), fmt.Sprintf("%x", path),
		}
		for _, formatted := range outputs {
			if strings.Contains(formatted, canary) {
				t.Fatalf("ordinary formatter leaked opaque value: %q", formatted)
			}
		}
		for _, value := range []any{secret, path} {
			encoded, err := json.Marshal(value)
			if !errors.Is(err, ErrSensitiveSerialization) || bytes.Contains(encoded, []byte(canary)) {
				t.Fatalf("JSON serialization = %q, %v", encoded, err)
			}
		}
	})
}

func mustSecret(t *testing.T, value string) Secret {
	t.Helper()
	secret, err := NewSecretString(value)
	if err != nil {
		t.Fatalf("NewSecretString() error = %v", err)
	}
	return secret
}

func mustSensitivePath(t *testing.T, value string) SensitivePath {
	t.Helper()
	path, err := NewSensitivePath(value)
	if err != nil {
		t.Fatalf("NewSensitivePath() error = %v", err)
	}
	return path
}

func TestFieldRuleValueSemantics(t *testing.T) {
	t.Parallel()

	if !reflect.DeepEqual(ClassifyField("output_path"), FieldRule{Classification: ClassPublicPath, AllowedInResult: true}) {
		t.Fatal("output_path rule changed")
	}
}
