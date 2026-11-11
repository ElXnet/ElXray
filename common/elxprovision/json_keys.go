package elxprovision

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// rejectDuplicateJSONKeys refuses ambiguous JSON object members before a
// Go struct decoder can silently overwrite a signed Control field. Keys are
// compared case-insensitively to match encoding/json's struct matching.
func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := readUniqueJSONValue(decoder); err != nil {
		return ErrInvalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func readUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	var closing json.Delim
	switch delimiter {
	case '{':
		closing = '}'
		seen := make(map[string]struct{})
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return ErrInvalid
			}
			canonical := strings.ToLower(key)
			if _, duplicate := seen[canonical]; duplicate {
				return ErrInvalid
			}
			seen[canonical] = struct{}{}
			if err := readUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		closing = ']'
		for decoder.More() {
			if err := readUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return ErrInvalid
	}
	end, err := decoder.Token()
	if err != nil || end != closing {
		return ErrInvalid
	}
	return nil
}
