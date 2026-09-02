package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// RenderJSON validates and writes exactly one newline-terminated JSON document.
// Encoding happens in memory first, so validation/encoding failures cannot
// leave a partial document in the destination.
func RenderJSON(writer io.Writer, result Result) error {
	if writer == nil {
		return fmt.Errorf("JSON output writer must not be nil")
	}
	if err := result.Validate(); err != nil {
		return fmt.Errorf("validate result: %w", err)
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("encode result JSON: %w", err)
	}
	if _, err := writer.Write(encoded.Bytes()); err != nil {
		return fmt.Errorf("write result JSON: %w", err)
	}
	return nil
}
