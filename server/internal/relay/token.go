package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// A relay token is a signed statement of a quota, at most 4 KiB.
const maxRelayTokenLen = 4096

// Field limits from PROTOCOL.md 2.2.
const (
	maxIssuerLen = 64
	maxAudience  = 64
	maxSubject   = 128
)

// The largest integer field PROTOCOL.md section 1 allows.
const maxQuota = 1<<53 - 1

// RelayToken is a verified rt1 token.
type RelayToken struct {
	Iss           string
	Aud           string
	Sub           string
	Exp           int64
	Channels      int64
	CreatesPerMin int64
	BytesPerDay   int64
}

var errMalformed = errors.New("malformed relay token")

// VerifyRelayToken parses and checks an rt1 token against the issuers this
// relay trusts and its own id, at a given instant. The clock is a parameter so
// the published vectors can replay at their own `now`.
func VerifyRelayToken(raw string, issuers map[string]ed25519.PublicKey, relayID string, now time.Time) (*RelayToken, error) {
	if len(raw) > maxRelayTokenLen {
		return nil, errMalformed
	}
	if !strings.HasPrefix(raw, "rt1.") {
		return nil, errMalformed
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errMalformed
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) == 0 {
		return nil, errMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errMalformed
	}
	value, err := decodeStrictJSON(payload)
	if err != nil {
		return nil, errMalformed
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, errMalformed
	}
	t := &RelayToken{}
	if t.Iss, ok = textField(obj, "iss", maxIssuerLen); !ok {
		return nil, errMalformed
	}
	if t.Aud, ok = textField(obj, "aud", maxAudience); !ok {
		return nil, errMalformed
	}
	if t.Sub, ok = textField(obj, "sub", maxSubject); !ok {
		return nil, errMalformed
	}
	if t.Exp, ok = intField(obj, "exp", 0, maxQuota); !ok {
		return nil, errMalformed
	}
	if t.Channels, ok = intField(obj, "channels", 0, maxQuota); !ok {
		return nil, errMalformed
	}
	if t.CreatesPerMin, ok = intField(obj, "creates_per_minute", 0, maxQuota); !ok {
		return nil, errMalformed
	}
	if t.BytesPerDay, ok = intField(obj, "bytes_per_day", 0, maxQuota); !ok {
		return nil, errMalformed
	}
	if t.Aud != relayID || now.Unix() >= t.Exp {
		return nil, errMalformed
	}
	pub, known := issuers[t.Iss]
	if !known || !ed25519.Verify(pub, []byte("rt1."+parts[1]), sig) {
		return nil, errors.New("relay token signature")
	}
	return t, nil
}

func textField(obj map[string]any, name string, max int) (string, bool) {
	v, ok := obj[name]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || utf8.RuneCountInString(s) < 1 || utf8.RuneCountInString(s) > max {
		return "", false
	}
	return s, true
}

// intField accepts a bare JSON integer in range. A fraction, an exponent, a
// string or a boolean is refused even when it names the same number.
func intField(obj map[string]any, name string, min, max int64) (int64, bool) {
	v, ok := obj[name]
	if !ok {
		return 0, false
	}
	num, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	s := num.String()
	if strings.ContainsAny(s, ".eE") {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < min || n > max {
		return 0, false
	}
	return n, true
}

// decodeStrictJSON decodes one JSON value and refuses duplicate object keys,
// which encoding/json would silently let the last one win.
func decodeStrictJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errMalformed
	}
	return value, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch delim {
	case '{':
		obj := make(map[string]any)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyTok.(string)
			if !ok {
				return nil, errMalformed
			}
			if _, duplicate := obj[key]; duplicate {
				return nil, errors.New("duplicate key")
			}
			value, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			obj[key] = value
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return obj, nil
	case '[':
		var arr []any
		for dec.More() {
			value, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, value)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return arr, nil
	}
	return nil, errMalformed
}
