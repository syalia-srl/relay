package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOperatorKeysComeFromTheFile(t *testing.T) {
	key := "the-operator-key"
	sum := sha256.Sum256([]byte(key))
	path := filepath.Join(t.TempDir(), "keys.json")
	body := `{"relay_id":"relay.example","issuers":{},"keys":[
		{"id":"local","sha256":"` + hex.EncodeToString(sum[:]) + `","channels":7,"creates_per_minute":8,"bytes_per_day":9}
	]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	info, ok := keys.Lookup(key, time.Now())
	if !ok {
		t.Fatal("the listed key was refused")
	}
	if info.Channels != 7 || info.CreatesPerMinute != 8 || info.BytesPerDay != 9 {
		t.Fatalf("the key lost its quota: %+v", info)
	}
	if info.ID != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("the key id is %q", info.ID)
	}
	if _, ok := keys.Lookup("another-key", time.Now()); ok {
		t.Fatal("an unlisted key was accepted")
	}
	if _, ok := keys.Lookup("rt1.not.a.token", time.Now()); ok {
		t.Fatal("anything shaped like a relay token must verify or be refused")
	}
}

func TestAMissingKeysFileAcceptsNothing(t *testing.T) {
	keys, err := LoadKeys(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("a missing keys file must not stop the relay: %v", err)
	}
	if _, ok := keys.Lookup("any-key", time.Now()); ok {
		t.Fatal("a missing keys file accepted a key")
	}
}

func TestTokenKeyIDsDoNotCollide(t *testing.T) {
	if tokenKeyID("ab", "c") == tokenKeyID("a", "bc") {
		t.Fatal("two holders share one id")
	}
}

func TestBucketSpendsAndRefills(t *testing.T) {
	b := NewBucket(2, 0)
	if !b.Take() || !b.Take() {
		t.Fatal("the burst did not allow two creations")
	}
	if b.Take() {
		t.Fatal("an empty bucket still allowed a creation")
	}
}
