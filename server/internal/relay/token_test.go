package relay

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type tokenVectors struct {
	Now     int64             `json:"now"`
	RelayID string            `json:"relay_id"`
	Issuers map[string]string `json:"issuers"`
	Cases   []struct {
		Name  string `json:"name"`
		Token string `json:"token"`
		Valid bool   `json:"valid"`
	} `json:"cases"`
}

// TestRelayTokenVectors replays every published case at its own clock and
// insists the relay agrees with each verdict.
func TestRelayTokenVectors(t *testing.T) {
	data, err := os.ReadFile("../../../vectors/relay_token.json")
	if err != nil {
		t.Fatal(err)
	}
	var v tokenVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	issuers := make(map[string]ed25519.PublicKey, len(v.Issuers))
	for iss, hexKey := range v.Issuers {
		raw, err := hex.DecodeString(hexKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			t.Fatalf("issuer %q: bad public key", iss)
		}
		issuers[iss] = ed25519.PublicKey(raw)
	}
	now := time.Unix(v.Now, 0)
	if len(v.Cases) == 0 {
		t.Fatal("no cases in the vector file")
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got, err := VerifyRelayToken(c.Token, issuers, v.RelayID, now)
			if valid := err == nil; valid != c.Valid {
				t.Fatalf("valid = %v, want %v (err %v)", valid, c.Valid, err)
			}
			if err == nil && c.Name == "valid" {
				if got.Iss != "syalia" || got.Sub != "i_7f3a9c" {
					t.Fatalf("parsed the wrong holder: %+v", got)
				}
				if got.Channels != 64 || got.CreatesPerMin != 10 || got.BytesPerDay != 200000000 {
					t.Fatalf("parsed the wrong quota: %+v", got)
				}
				if got.Exp != 1800086400 {
					t.Fatalf("parsed the wrong expiry: %+v", got)
				}
			}
		})
	}
}
