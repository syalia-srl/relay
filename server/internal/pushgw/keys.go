// Package pushgw is the push gateway of contract C11: it takes batches of push
// tokens from relays and sends each token one data-only FCM HTTP v1 message.
// It learns a token and the time of each wake-up, and nothing else.
package pushgw

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// keysFile is PUSHGW_KEYS_PATH.
type keysFile struct {
	Keys []struct {
		ID        string `json:"id"`
		SHA256    string `json:"sha256"`
		PerMinute int    `json:"per_minute"`
	} `json:"keys"`
}

type key struct {
	id        string
	digest    []byte
	perMinute int
}

// window counts one key's calls in the current minute.
type window struct {
	start time.Time
	calls int
}

// Keys holds the relay keys and their per-minute limits.
type Keys struct {
	path string

	mu      sync.Mutex
	keys    []key
	windows map[string]*window // by key id; kept across reloads
	now     func() time.Time
}

// LoadKeys reads path. A missing or bad file leaves no key, which refuses
// every call; the error says why.
func LoadKeys(path string) (*Keys, error) {
	k := &Keys{path: path, windows: map[string]*window{}, now: time.Now}
	return k, k.Reload()
}

// Reload re-reads the file. On error the keys in use are kept, except at
// first load, when there are none.
func (k *Keys) Reload() error {
	data, err := os.ReadFile(k.path)
	if err != nil {
		return fmt.Errorf("keys file not readable")
	}
	var f keysFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("keys file is not valid JSON")
	}
	keys := make([]key, 0, len(f.Keys))
	for i, entry := range f.Keys {
		digest, err := hex.DecodeString(entry.SHA256)
		if err != nil || len(digest) != sha256.Size || entry.ID == "" || entry.PerMinute < 0 {
			return fmt.Errorf("keys file entry %d is malformed", i)
		}
		keys = append(keys, key{id: entry.ID, digest: digest, perMinute: entry.PerMinute})
	}
	k.mu.Lock()
	k.keys = keys
	k.mu.Unlock()
	return nil
}

// Count is how many keys are loaded.
func (k *Keys) Count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.keys)
}

// Admit checks a bearer key and takes one call from its minute. ok is false
// for an unknown key; retryAfter is set when the key is over its limit.
func (k *Keys) Admit(bearer string) (id string, ok bool, retryAfter time.Duration) {
	sum := sha256.Sum256([]byte(bearer))
	k.mu.Lock()
	defer k.mu.Unlock()
	var found *key
	for i := range k.keys {
		if subtle.ConstantTimeCompare(sum[:], k.keys[i].digest) == 1 {
			found = &k.keys[i]
		}
	}
	if bearer == "" || found == nil {
		return "", false, 0
	}
	now := k.now()
	w := k.windows[found.id]
	if w == nil || now.Sub(w.start) >= time.Minute {
		w = &window{start: now}
		k.windows[found.id] = w
	}
	if w.calls >= found.perMinute {
		return found.id, true, w.start.Add(time.Minute).Sub(now)
	}
	w.calls++
	return found.id, true, 0
}
