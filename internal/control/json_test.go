package control

import (
	"strings"
	"testing"
)

func TestLocalRequestCodecRejectsAmbiguousJSON(t *testing.T) {
	valid := `{"schema_version":1,"method":"observe"}`
	if request, err := DecodeLocalRequest([]byte(valid)); err != nil || request.Method != LocalObserve {
		t.Fatalf("DecodeLocalRequest(valid) = %+v, %v", request, err)
	}
	for name, input := range map[string]string{
		"duplicate": `{"schema_version":1,"method":"observe","method":"mutate"}`,
		"unknown":   `{"schema_version":1,"method":"observe","extra":true}`,
		"trailing":  valid + ` {}`,
		"schema":    `{"schema_version":2,"method":"observe"}`,
		"too-deep":  `{"schema_version":1,"method":"mutate","operation":"test.deep","payload":{"value":` + strings.Repeat("[", maximumJSONDepth+1) + `0` + strings.Repeat("]", maximumJSONDepth+1) + `}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLocalRequest([]byte(input)); err == nil {
				t.Fatalf("DecodeLocalRequest(%s) error = nil", input)
			}
		})
	}
}

func TestLocalResponseCodecRejectsAmbiguousJSON(t *testing.T) {
	valid := `{"schema_version":1,"ok":true}`
	if response, err := DecodeLocalResponse([]byte(valid)); err != nil || !response.OK {
		t.Fatalf("DecodeLocalResponse(valid) = %+v, %v", response, err)
	}
	for _, input := range []string{
		`{"schema_version":1,"ok":true,"ok":false}`,
		`{"schema_version":1,"ok":true,"extra":true}`,
		valid + ` []`,
		`{"schema_version":2,"ok":true}`,
	} {
		if _, err := DecodeLocalResponse([]byte(input)); err == nil {
			t.Fatalf("DecodeLocalResponse(%s) error = nil", input)
		}
	}
}
