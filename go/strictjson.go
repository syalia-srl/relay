package relay

import (
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

const maxInteger = int64(1<<53 - 1)

var errDuplicateKey = errors.New("duplicate key")

// parseJSON is PROTOCOL.md section 1: JSON with no duplicate key anywhere in
// the tree. Numbers stay json.Number so an integer field can be told apart
// from 3.0 and 3e0.
func parseJSON(text string) (any, error) {
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	value, err := parseJSONValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON text")
	}
	return value, nil
}

func parseJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("invalid object key")
			}
			if _, exists := object[key]; exists {
				return nil, errDuplicateKey
			}
			value, err := parseJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		_, err := decoder.Token()
		return object, err
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, err := parseJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		_, err := decoder.Token()
		return array, err
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}

// asInteger accepts a JSON number only when it is written as an integer in
// 0 to 2^53 - 1, as section 1 requires.
func asInteger(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	text := number.String()
	if !integerLexeme(text) {
		return 0, false
	}
	parsed, err := strconv.ParseInt(text, 10, 64)
	if err != nil || parsed < 0 || parsed > maxInteger {
		return 0, false
	}
	return parsed, true
}

func integerLexeme(text string) bool {
	if text == "" {
		return false
	}
	start := 0
	if text[0] == '-' {
		start = 1
	}
	if start == len(text) {
		return false
	}
	for i := start; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return false
		}
	}
	return true
}

func isHex64(value any) (string, bool) {
	text, ok := value.(string)
	if !ok || len(text) != 64 {
		return "", false
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return text, true
}

func isB64URL(value any, length int) (string, bool) {
	text, ok := value.(string)
	if !ok || len(text) != length {
		return "", false
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return "", false
		}
	}
	return text, true
}
