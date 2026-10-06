package server

import (
	"bytes"
	"encoding/json"
)

// jsonMarshal encodes without HTML escaping (entries hold Markdown with
// "<" and "&") and ends with a newline.
func jsonMarshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
