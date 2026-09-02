package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

const maximumJSONDepth = 32

func DecodeLocalRequest(data []byte) (LocalRequest, error) {
	var request LocalRequest
	if err := decodeStrictJSON(data, &request); err != nil {
		return LocalRequest{}, err
	}
	if request.SchemaVersion != LocalSchemaVersion {
		return LocalRequest{}, fmt.Errorf("unsupported local request schema")
	}
	return request, nil
}

func DecodeLocalResponse(data []byte) (LocalResponse, error) {
	var response LocalResponse
	if err := decodeStrictJSON(data, &response); err != nil {
		return LocalResponse{}, err
	}
	if response.SchemaVersion != LocalSchemaVersion {
		return LocalResponse{}, fmt.Errorf("unsupported local response schema")
	}
	return response, nil
}

func decodeStrictJSON(data []byte, destination any) error {
	return decodeStrictJSONWithDepth(data, destination, maximumJSONDepth)
}

func decodeStrictJSONWithDepth(data []byte, destination any, maximumDepth int) error {
	if maximumDepth < 1 {
		return fmt.Errorf("maximum JSON depth must be positive")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSONValue(decoder, 1, maximumDepth); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON documents")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}

	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, depth, maximumDepth int) error {
	if depth > maximumDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maximumDepth)
	}
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
			if err := walkJSONValue(decoder, depth+1, maximumDepth); err != nil {
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
			if err := walkJSONValue(decoder, depth+1, maximumDepth); err != nil {
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
