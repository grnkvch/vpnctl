package output

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

func TestRenderJSONWritesExactlyOneDocument(t *testing.T) {
	t.Parallel()

	result := NewResult("status", StatusOK, CategorySuccess, SafeObject{
		"role":       "gateway",
		"overall":    "healthy",
		"generation": 7,
	})
	var output bytes.Buffer
	if err := RenderJSON(&output, result); err != nil {
		t.Fatalf("RenderJSON() error = %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	var decoded Result
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode first JSON document: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("JSON stdout contains trailing data: %v", err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("decoded result is invalid: %v", err)
	}
	if decoded.Command != result.Command || decoded.Status != result.Status || decoded.ExitCategory != result.ExitCategory || decoded.Data["generation"] != float64(7) {
		t.Fatalf("JSON round trip mismatch\nwant: %#v\n got: %#v", result, decoded)
	}
}

func TestRenderJSONValidatesBeforeWriting(t *testing.T) {
	t.Parallel()

	result := NewResult("status", StatusOK, CategorySuccess, SafeObject{"private_key": "canary"})
	var output bytes.Buffer
	if err := RenderJSON(&output, result); err == nil {
		t.Fatal("RenderJSON() accepted invalid result")
	}
	if output.Len() != 0 {
		t.Fatalf("RenderJSON() wrote partial output: %q", output.String())
	}
}
