package relay

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// KeySpec is one operator key in the keys file. A limit of zero allows
// nothing; only "unlimited" lifts the limits, for a relay an install runs for
// itself.
type KeySpec struct {
	ID               string `json:"id"`
	SHA256           string `json:"sha256"`
	Channels         int64  `json:"channels"`
	CreatesPerMinute int64  `json:"creates_per_minute"`
	BytesPerDay      int64  `json:"bytes_per_day"`
	Unlimited        bool   `json:"unlimited"`
}

// Keys is the file RELAY_KEYS_PATH points at, read at start and on SIGHUP.
type Keys struct {
	RelayID string            `json:"relay_id"`
	Issuers map[string]string `json:"issuers"`
	Keys    []KeySpec         `json:"keys"`

	issuers map[string]ed25519.PublicKey
	specs   []keyDigest
}

type keyDigest struct {
	spec   KeySpec
	digest string
}

// KeyInfo is what one presented key allows.
type KeyInfo struct {
	ID               string
	Channels         int64
	CreatesPerMinute int64
	BytesPerDay      int64
	Unlimited        bool
}

// LoadKeys reads and validates the keys file. A missing or unreadable file is
// not fatal: every v1 creation then answers 401, which is the safe default.
func LoadKeys(path string) (*Keys, error) {
	k := &Keys{issuers: make(map[string]ed25519.PublicKey)}
	if path == "" {
		log.Print("no keys file configured; no v1 key will be accepted")
		return k, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("cannot read the keys file; no v1 key will be accepted")
		return k, nil
	}
	if err := json.Unmarshal(data, k); err != nil {
		return nil, fmt.Errorf("keys file: %w", err)
	}
	for iss, hexKey := range k.Issuers {
		raw, err := hex.DecodeString(hexKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			log.Printf("issuer %q has no usable Ed25519 public key; ignoring it", iss)
			continue
		}
		k.issuers[iss] = ed25519.PublicKey(raw)
	}
	for _, spec := range k.Keys {
		digest := strings.ToLower(strings.TrimSpace(spec.SHA256))
		if len(digest) != sha256.Size*2 {
			log.Printf("key %q has no usable SHA-256 digest; ignoring it", spec.ID)
			continue
		}
		if _, err := hex.DecodeString(digest); err != nil {
			log.Printf("key %q has no usable SHA-256 digest; ignoring it", spec.ID)
			continue
		}
		k.specs = append(k.specs, keyDigest{spec: spec, digest: digest})
	}
	return k, nil
}

// Lookup decides whether a bearer string is a key this relay accepts, and what
// it allows. A string starting with "rt1." must verify as a relay token; any
// other string is an operator key looked up by digest.
func (k *Keys) Lookup(raw string, now time.Time) (KeyInfo, bool) {
	if strings.HasPrefix(raw, "rt1.") {
		t, err := VerifyRelayToken(raw, k.issuers, k.RelayID, now)
		if err != nil {
			return KeyInfo{}, false
		}
		return KeyInfo{
			ID:               tokenKeyID(t.Iss, t.Sub),
			Channels:         t.Channels,
			CreatesPerMinute: t.CreatesPerMin,
			BytesPerDay:      t.BytesPerDay,
		}, true
	}
	sum := sha256.Sum256([]byte(raw))
	digest := hex.EncodeToString(sum[:])
	for _, entry := range k.specs {
		if subtle.ConstantTimeCompare([]byte(entry.digest), []byte(digest)) == 1 {
			return KeyInfo{
				ID:               "sha256:" + digest,
				Channels:         entry.spec.Channels,
				CreatesPerMinute: entry.spec.CreatesPerMinute,
				BytesPerDay:      entry.spec.BytesPerDay,
				Unlimited:        entry.spec.Unlimited,
			}, true
		}
	}
	return KeyInfo{}, false
}

// tokenKeyID names a relay token holder without letting two pairs collide.
func tokenKeyID(iss, sub string) string {
	return fmt.Sprintf("rt1:%d:%s%s", len(iss), iss, sub)
}

// Quotas tracks what each key has used today and in the last minute. The
// counters live in memory: they bound a day's traffic, and a restart only
// gives a holder a fresh day early.
type Quotas struct {
	mu      sync.Mutex
	day     int64
	bytes   map[string]int64
	creates map[string][]int64
}

func NewQuotas() *Quotas {
	return &Quotas{
		day:     time.Now().Unix() / 86400,
		bytes:   make(map[string]int64),
		creates: make(map[string][]int64),
	}
}

// rollover forgets yesterday's counts at 00:00 UTC, which also lifts the 4429
// refusal and drops the creation logs of keys that went quiet.
func (q *Quotas) rollover(now int64) {
	day := now / 86400
	if day == q.day {
		return
	}
	q.day = day
	q.bytes = make(map[string]int64)
	q.creates = make(map[string][]int64)
}

// Take records a creation if the key is still under its per-minute limit and
// reports, when it refuses, how many seconds until the window frees a slot.
func (q *Quotas) Take(key string, limit int64, now int64) (int, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.rollover(now)
	if limit == 0 {
		return 60, false
	}
	window := q.creates[key]
	cut := now - 60
	i := 0
	for i < len(window) && window[i] <= cut {
		i++
	}
	window = window[i:]
	if len(window) >= int(limit) {
		q.creates[key] = window
		retry := int(window[0] + 60 - now)
		if retry < 1 {
			retry = 1
		}
		return retry, false
	}
	q.creates[key] = append(window, now)
	return 0, true
}

// AddBytes counts forwarded data and reports the key's total for today.
func (q *Quotas) AddBytes(key string, n int64, now int64) int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.rollover(now)
	q.bytes[key] += n
	return q.bytes[key]
}

// Used reports the key's forwarded bytes today.
func (q *Quotas) Used(key string, now int64) int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.rollover(now)
	return q.bytes[key]
}

// Bucket is v0's anonymous creation limiter, a token bucket as before.
type Bucket struct {
	mu    sync.Mutex
	burst float64
	rate  float64 // tokens per second
	level float64
	at    time.Time
}

func NewBucket(burst, perMinute float64) *Bucket {
	return &Bucket{burst: burst, rate: perMinute / 60, level: burst, at: time.Now()}
}

func (b *Bucket) Take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.level += now.Sub(b.at).Seconds() * b.rate
	if b.level > b.burst {
		b.level = b.burst
	}
	b.at = now
	if b.level < 1 {
		return false
	}
	b.level--
	return true
}
