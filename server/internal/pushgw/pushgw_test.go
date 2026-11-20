package pushgw

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseTokens(t *testing.T) {
	long := strings.Repeat("x", maxTokenLen)
	for body, want := range map[string]int{
		`{"tokens": ["a", "b", "a"]}`:    2,
		`{"tokens": ["` + long + `"]}`:   1,
		`{"tokens": []}`:                 -1,
		`{"tokens": ["a"], "room": "r"}`: -1,
		`{"tokens": [""]}`:               -1,
		`{"tokens": [1]}`:                -1,
		`{"tokens": ["` + long + `x"]}`:  -1,
		`{}`:                             -1,
		`not json`:                       -1,
	} {
		tokens, ok := parseTokens(strings.NewReader(body))
		if got := len(tokens); (want < 0 && ok) || (want >= 0 && got != want) {
			t.Errorf("%.40s: got %d tokens, ok %v; want %d", body, got, ok, want)
		}
	}
}

func writeKeys(t *testing.T, perMinute int) *Keys {
	t.Helper()
	sum := sha256.Sum256([]byte("relay-key"))
	data, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"id": "r", "sha256": hex.EncodeToString(sum[:]), "per_minute": perMinute}}})
	path := filepath.Join(t.TempDir(), "keys.json")
	os.WriteFile(path, data, 0o600)
	k, err := LoadKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAdmitCountsAMinute(t *testing.T) {
	k := writeKeys(t, 2)
	now := time.Unix(1_000_000, 0)
	k.now = func() time.Time { return now }
	if _, ok, _ := k.Admit("wrong"); ok {
		t.Fatal("a wrong key was admitted")
	}
	for range 2 {
		if _, ok, wait := k.Admit("relay-key"); !ok || wait != 0 {
			t.Fatal("refused within the limit")
		}
	}
	now = now.Add(20 * time.Second)
	if _, ok, wait := k.Admit("relay-key"); !ok || wait != 40*time.Second {
		t.Fatalf("wait %v, want 40s", wait)
	}
	now = now.Add(40 * time.Second)
	if _, _, wait := k.Admit("relay-key"); wait != 0 {
		t.Fatal("a new minute is still refused")
	}
}

func TestMissingKeysFileRefusesAll(t *testing.T) {
	k, err := LoadKeys(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatal("no error for a missing file")
	}
	if _, ok, _ := k.Admit("relay-key"); ok {
		t.Fatal("admitted with no keys")
	}
}

func TestErrorCode(t *testing.T) {
	for body, want := range map[string]string{
		`{"error": {"status": "NOT_FOUND", "details": [{"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": "UNREGISTERED"}]}}`: "UNREGISTERED",
		`{"error": {"status": "INVALID_ARGUMENT"}}`:                                                                "INVALID_ARGUMENT",
		`{"error": {"status": "PERMISSION_DENIED", "details": [{"@type": "other", "errorCode": "UNREGISTERED"}]}}`: "PERMISSION_DENIED",
		`junk`: "",
	} {
		if got := errorCode(strings.NewReader(body)); got != want {
			t.Errorf("%.50s: %q, want %q", body, got, want)
		}
	}
}

func TestAssertionIsAVerifiableRS256JWT(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	account := map[string]string{
		"project_id": "example-project", "client_email": "pushgw@example-project.example",
		"token_uri":   "http://127.0.0.1:1/token",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	}
	data, _ := json.Marshal(account)
	path := filepath.Join(t.TempDir(), "sa.json")
	os.WriteFile(path, data, 0o600)
	f, err := NewFCM(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if f.sendURL != "https://fcm.googleapis.com/v1/projects/example-project/messages:send" {
		t.Fatal(f.sendURL)
	}
	now := time.Unix(1_000_000, 0)
	jwt, err := f.assertion(now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatal(err)
	}
	claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	json.Unmarshal(claimsJSON, &claims)
	if claims["iss"] != account["client_email"] || claims["aud"] != account["token_uri"] ||
		claims["scope"] != fcmScope || claims["exp"].(float64)-claims["iat"].(float64) != 3600 {
		t.Fatalf("claims %v", claims)
	}
}
