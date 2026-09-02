package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func DecodeState(data []byte) (State, error) {
	var state State
	if err := decodeStrict(data, &state); err != nil {
		return State{}, fmt.Errorf("decode state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return State{}, fmt.Errorf("validate state: %w", err)
	}
	return state, nil
}

func EncodeState(state State) ([]byte, error) {
	if err := state.Validate(); err != nil {
		return nil, fmt.Errorf("validate state: %w", err)
	}
	return encodeIndented(state)
}

func DecodePreset(data []byte) (Preset, error) {
	var preset Preset
	if err := decodeStrict(data, &preset); err != nil {
		return Preset{}, fmt.Errorf("decode preset: %w", err)
	}
	if err := preset.Validate(); err != nil {
		return Preset{}, fmt.Errorf("validate preset: %w", err)
	}
	return preset, nil
}

func EncodePreset(preset Preset) ([]byte, error) {
	if err := preset.Validate(); err != nil {
		return nil, fmt.Errorf("validate preset: %w", err)
	}
	return encodeIndented(preset)
}

func DecodeComponentManifest(data []byte) (ComponentManifest, error) {
	var manifest ComponentManifest
	if err := decodeStrict(data, &manifest); err != nil {
		return ComponentManifest{}, fmt.Errorf("decode component manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return ComponentManifest{}, fmt.Errorf("validate component manifest: %w", err)
	}
	return manifest, nil
}

func EncodeComponentManifest(manifest ComponentManifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("validate component manifest: %w", err)
	}
	return encodeIndented(manifest)
}

func decodeStrict(data []byte, destination any) error {
	if err := rejectDuplicateObjectKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON documents")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func rejectDuplicateObjectKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON documents")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			keys[key] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return fmt.Errorf("invalid JSON object closing token")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return fmt.Errorf("invalid JSON array closing token")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func encodeIndented(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
