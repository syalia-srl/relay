package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type roomQuotaVectors struct {
	Credentials []struct {
		Name       string          `json:"name"`
		KeysEntry  json.RawMessage `json:"keys_entry"`
		RT1Payload json.RawMessage `json:"rt1_payload"`
		RoomQuota  *RoomQuota      `json:"room_quota"`
	} `json:"credentials"`
	Creates []struct {
		Name      string          `json:"name"`
		RoomQuota *RoomQuota      `json:"room_quota"`
		Request   json.RawMessage `json:"request"`
		Limits    *RoomLimits     `json:"limits"`
	} `json:"creates"`
}

func loadRoomQuotaVectors(t *testing.T) roomQuotaVectors {
	t.Helper()
	data, err := os.ReadFile("../../../vectors/rooms_quota.json")
	if err != nil {
		t.Fatal(err)
	}
	var v roomQuotaVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Credentials) == 0 || len(v.Creates) == 0 {
		t.Fatal("no cases in the vector file")
	}
	return v
}

// TestRoomQuotaVectors puts every published credential through the path the
// relay takes: a keys.json entry through LoadKeys and Lookup, an rt1 payload
// signed and verified as a presented token.
func TestRoomQuotaVectors(t *testing.T) {
	v := loadRoomQuotaVectors(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Credentials {
		t.Run(c.Name, func(t *testing.T) {
			var info KeyInfo
			switch {
			case c.KeysEntry != nil:
				const operatorKey = "a test operator key"
				var entry map[string]any
				if err := json.Unmarshal(c.KeysEntry, &entry); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256([]byte(operatorKey))
				entry["sha256"] = hex.EncodeToString(sum[:])
				file, _ := json.Marshal(map[string]any{"relay_id": "relay.example", "keys": []any{entry}})
				path := filepath.Join(t.TempDir(), "keys.json")
				if err := os.WriteFile(path, file, 0o600); err != nil {
					t.Fatal(err)
				}
				keys, err := LoadKeys(path)
				if err != nil {
					t.Fatalf("a room quota must never make the keys file invalid: %v", err)
				}
				var ok bool
				if info, ok = keys.Lookup(operatorKey, time.Now()); !ok {
					t.Fatal("the key was not accepted")
				}
			case c.RT1Payload != nil:
				body := base64.RawURLEncoding.EncodeToString(c.RT1Payload)
				sig := ed25519.Sign(priv, []byte("rt1."+body))
				token := "rt1." + body + "." + base64.RawURLEncoding.EncodeToString(sig)
				var p struct {
					Iss string `json:"iss"`
					Exp int64  `json:"exp"`
				}
				json.Unmarshal(c.RT1Payload, &p)
				keys := &Keys{RelayID: "relay.example", issuers: map[string]ed25519.PublicKey{p.Iss: pub}}
				var ok bool
				if info, ok = keys.Lookup(token, time.Unix(p.Exp-1, 0)); !ok {
					t.Fatal("room fields must never make a relay token invalid")
				}
				if !info.Token || info.Exp != p.Exp {
					t.Fatalf("token expiry not carried: %+v", info)
				}
			default:
				t.Fatal("a case with neither keys_entry nor rt1_payload")
			}
			switch {
			case c.RoomQuota == nil && info.Rooms != nil:
				t.Fatalf("got a room quota %+v, want none", *info.Rooms)
			case c.RoomQuota != nil && info.Rooms == nil:
				t.Fatalf("got no room quota, want %+v", *c.RoomQuota)
			case c.RoomQuota != nil && *info.Rooms != *c.RoomQuota:
				t.Fatalf("got %+v, want %+v", *info.Rooms, *c.RoomQuota)
			}
		})
	}
}

// TestRoomLimitVectors clamps every published create request to its quota,
// the first credential's unless the case names its own.
func TestRoomLimitVectors(t *testing.T) {
	v := loadRoomQuotaVectors(t)
	base := v.Credentials[0].RoomQuota
	if base == nil {
		t.Fatal("the first credential has no room quota")
	}
	for _, c := range v.Creates {
		t.Run(c.Name, func(t *testing.T) {
			q := *base
			if c.RoomQuota != nil {
				q = *c.RoomQuota
			}
			value, err := DecodeStrictJSON(c.Request)
			if err != nil {
				t.Fatal(err)
			}
			got, err := q.Limits(value.(map[string]any))
			if c.Limits == nil {
				if err == nil {
					t.Fatalf("got %+v, want a refusal", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got != *c.Limits {
				t.Fatalf("got %+v, want %+v", got, *c.Limits)
			}
		})
	}
}
