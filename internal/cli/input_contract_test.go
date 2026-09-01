package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestV2InputContractGolden(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("testdata", "v2", "input-contract.json"))
	if err != nil {
		t.Fatalf("read input contract fixture: %v", err)
	}
	var cases []struct {
		Name    string         `json:"name"`
		Request PromptRequest  `json:"request"`
		Want    PromptDecision `json:"want"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatalf("parse input contract fixture: %v", err)
	}
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			if got := ResolvePrompt(test.Request); !reflect.DeepEqual(got, test.Want) {
				t.Fatalf("ResolvePrompt(%+v) = %+v, want %+v", test.Request, got, test.Want)
			}
		})
	}
}
