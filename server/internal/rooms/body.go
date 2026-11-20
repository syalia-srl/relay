package rooms

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/syalia-srl/relay/server/internal/relay"
)

// object decodes a JSON body under PROTOCOL.md section 1: one object, no
// duplicate keys. A body over the limit is 413, anything else 400.
func (req *request) object() (map[string]any, error) {
	if req.tooBig {
		return nil, errTooLarge
	}
	value, err := relay.DecodeStrictJSON(req.body)
	if err != nil {
		return nil, errBadRequest
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, errBadRequest
	}
	return obj, nil
}

func intOf(obj map[string]any, name string, min int64) (int64, bool) {
	return relay.IntField(obj, name, min, relay.MaxInt)
}

func strOf(obj map[string]any, name string) (string, bool) {
	s, ok := obj[name].(string)
	return s, ok
}

// b64 decodes base64url without padding and with canonical trailing bits
// (ROOMS.md 2), and refuses anything else.
func b64(s string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, err == nil
}

// isID reports whether s is an id of n random bytes in base64url: a client
// id or a relay id (16 bytes, 22 characters).
func isID(s string, n int) bool {
	if len(s) != base64.RawURLEncoding.EncodedLen(n) {
		return false
	}
	b, ok := b64(s)
	return ok && len(b) == n
}

// jwk reduces a P-256 public JWK to kty, crv, x and y and returns its JSON,
// refusing another curve or a coordinate that is not 32 bytes.
func jwk(v any) (string, bool) {
	obj, ok := v.(map[string]any)
	if !ok || obj["kty"] != "EC" || obj["crv"] != "P-256" {
		return "", false
	}
	x, ok1 := obj["x"].(string)
	y, ok2 := obj["y"].(string)
	if !ok1 || !ok2 {
		return "", false
	}
	if bx, ok := b64(x); !ok || len(bx) != 32 {
		return "", false
	}
	if by, ok := b64(y); !ok || len(by) != 32 {
		return "", false
	}
	data, _ := json.Marshal(map[string]string{"kty": "EC", "crv": "P-256", "x": x, "y": y})
	return string(data), true
}

// raw re-encodes a decoded JSON value for storage. Numbers stay as they were
// written, since the decoder keeps them as json.Number.
func raw(v any) string {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return strings.TrimSuffix(buf.String(), "\n")
}
