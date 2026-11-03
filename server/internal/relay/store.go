// Package relay implements the E2E message relay: two-slot channels, kept
// across a restart, and the bytes in between.
package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// A channel whose guest never came is a QR nobody scanned: gone after an hour.
const GuestTTL = 3600

// A paired channel with neither side connected for this long is abandoned.
// Long on purpose: an install switched off for a holiday must find it again.
const IdleTTL = 30 * 24 * 3600

// A channel has two slots. v0 calls them mobile and bridge, v1 host and guest;
// the difference is only in the state file's field names.
const (
	sideA = 0 // host (v1), mobile (v0)
	sideB = 1 // guest (v1), bridge (v0)
)

// Channel is one row of the store. Its zero value in V means a v0 channel, so
// state files written before v1 load unchanged.
type Channel struct {
	ID         string  `json:"channel_id"`
	HashMobile string  `json:"hash_mobile,omitempty"`
	HashBridge string  `json:"hash_bridge,omitempty"`
	CreatedAt  float64 `json:"created_at"`
	LastSeen   float64 `json:"last_seen"`
	MobileSeen bool    `json:"mobile_seen,omitempty"`

	V         int    `json:"v,omitempty"`
	HashHost  string `json:"hash_host,omitempty"`
	HashGuest string `json:"hash_guest,omitempty"`
	Key       string `json:"key,omitempty"`
	GuestSeen bool   `json:"guest_seen,omitempty"`

	// The quota the creating key carried. Data frames carry no key of their
	// own, so the limit that governs them has to travel with the channel.
	LimitChannels int64 `json:"limit_channels,omitempty"`
	LimitCreates  int64 `json:"limit_creates,omitempty"`
	LimitBytes    int64 `json:"limit_bytes,omitempty"`

	conns [2]*wsConn
}

func (ch *Channel) hash(side int) string {
	if ch.V == 1 {
		if side == sideA {
			return ch.HashHost
		}
		return ch.HashGuest
	}
	if side == sideA {
		return ch.HashMobile
	}
	return ch.HashBridge
}

func (ch *Channel) seen(side int) bool {
	if ch.V == 1 {
		return ch.GuestSeen
	}
	return ch.MobileSeen
}

func (ch *Channel) markSeen(side int) bool {
	if ch.V == 1 {
		if side == sideA || ch.GuestSeen {
			return false
		}
		ch.GuestSeen = true
		return true
	}
	if side == sideB || ch.MobileSeen {
		return false
	}
	ch.MobileSeen = true
	return true
}

type tokenRef struct {
	ch     *Channel
	side   int
	digest [32]byte
}

// Store keeps channels and their token digests. What reaches disk is the
// channel id and a SHA-256 of each token, never a token: a copy of the file
// opens no slot.
type Store struct {
	mu       sync.Mutex
	path     string
	channels map[string]*Channel
	tokens   map[[32]byte]tokenRef
	alive    map[string]int // channels still alive per key id
	warned   sync.Once
}

func NewStore(path string) *Store {
	s := &Store{
		path:     path,
		channels: make(map[string]*Channel),
		tokens:   make(map[[32]byte]tokenRef),
		alive:    make(map[string]int),
	}
	if path != "" {
		s.load()
	}
	return s
}

func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("cannot read the channel store: %v", err)
		}
		return
	}
	var file struct {
		Channels []Channel `json:"channels"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		log.Printf("cannot parse the channel store: %v", err)
		return
	}
	for i := range file.Channels {
		ch := file.Channels[i]
		if ch.ID == "" || ch.HashMobile == "" && ch.HashHost == "" {
			continue
		}
		if ch.CreatedAt == 0 {
			ch.CreatedAt = ch.LastSeen
		}
		s.index(&ch)
	}
	log.Printf("loaded %d channel(s)", len(s.channels))
}

func (s *Store) index(ch *Channel) {
	s.channels[ch.ID] = ch
	for _, side := range [2]int{sideA, sideB} {
		h := ch.hash(side)
		if h == "" {
			continue
		}
		digest, err := hex.DecodeString(h)
		if err != nil || len(digest) != sha256.Size {
			continue
		}
		var key [32]byte
		copy(key[:], digest)
		s.tokens[key] = tokenRef{ch: ch, side: side, digest: key}
	}
	if ch.Key != "" {
		s.alive[ch.Key]++
	}
}

func (s *Store) drop(ch *Channel) {
	delete(s.channels, ch.ID)
	for _, side := range [2]int{sideA, sideB} {
		if h := ch.hash(side); h != "" {
			if digest, err := hex.DecodeString(h); err == nil && len(digest) == sha256.Size {
				var key [32]byte
				copy(key[:], digest)
				delete(s.tokens, key)
			}
		}
	}
	if ch.Key != "" {
		s.alive[ch.Key]--
		if s.alive[ch.Key] <= 0 {
			delete(s.alive, ch.Key)
		}
	}
}

// saveLocked writes the store atomically at 0600. An unwritable path is not
// fatal: the relay keeps every channel in memory and says so once.
func (s *Store) saveLocked() {
	if s.path == "" {
		return
	}
	rows := make([]Channel, 0, len(s.channels))
	for _, ch := range s.channels {
		row := *ch
		row.conns = [2]*wsConn{}
		rows = append(rows, row)
	}
	data, err := json.Marshal(struct {
		Channels []Channel `json:"channels"`
	}{Channels: rows})
	if err != nil {
		log.Printf("cannot encode the channel store: %v", err)
		return
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, filepath.Base(s.path)+".*.tmp")
	if err != nil {
		s.warn()
		return
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		s.warn()
		return
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		s.warn()
		return
	}
	if err := tmp.Close(); err != nil {
		s.warn()
		return
	}
	if err := os.Rename(name, s.path); err != nil {
		s.warn()
		return
	}
}

func (s *Store) warn() {
	s.warned.Do(func() {
		log.Print("channel store not writable; channels will not survive a restart")
	})
}

// Save persists the store without other changes.
func (s *Store) Save() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveLocked()
}

func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.channels)
}

// Alive reports how many live channels a key created.
func (s *Store) Alive(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.alive[key]
}

func (s *Store) Get(id string) *Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.channels[id]
}

// ByToken resolves a token digest to its channel and slot. The final compare
// is constant time so two tokens do not get compared byte by byte.
func (s *Store) ByToken(digest [32]byte) (*Channel, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, ok := s.tokens[digest]
	if !ok {
		return nil, 0, false
	}
	if subtle.ConstantTimeCompare(ref.digest[:], digest[:]) != 1 {
		return nil, 0, false
	}
	return ref.ch, ref.side, true
}

// Create makes a channel and returns it with both plaintext tokens, which
// exist only in the creating request's answer.
func (s *Store) Create(v int, key string, limits [3]int64) (*Channel, string, string) {
	var id, tokA, tokB string
	if v == 1 {
		id, tokA, tokB = randomB64(16), randomB64(32), randomB64(32)
	} else {
		// v0's ids and tokens are both 64 hex characters; keep them so a
		// client that stored one keeps working.
		id, tokA, tokB = randomHex(32), randomHex(32), randomHex(32)
	}
	now := float64(time.Now().UnixNano()) / 1e9
	ch := &Channel{
		ID:            id,
		CreatedAt:     now,
		LastSeen:      now,
		V:             v,
		Key:           key,
		LimitChannels: limits[0],
		LimitCreates:  limits[1],
		LimitBytes:    limits[2],
	}
	hashA, hashB := digestHex(tokA), digestHex(tokB)
	if v == 1 {
		ch.HashHost, ch.HashGuest = hashA, hashB
	} else {
		ch.HashMobile, ch.HashBridge = hashA, hashB
	}
	s.mu.Lock()
	s.index(ch)
	s.saveLocked()
	s.mu.Unlock()
	return ch, tokA, tokB
}

// Remove deletes a channel and returns it with its sockets, for the caller to
// close outside the lock.
func (s *Store) Remove(id string) *Channel {
	s.mu.Lock()
	ch := s.channels[id]
	if ch != nil {
		s.drop(ch)
		s.saveLocked()
	}
	s.mu.Unlock()
	return ch
}

// GC forgets unscanned and abandoned channels; a connected one always stays.
func (s *Store) GC(now float64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	gone := 0
	for id, ch := range s.channels {
		if ch.conns[sideA] != nil || ch.conns[sideB] != nil {
			continue // a connected channel always stays
		}
		old := now-ch.CreatedAt > GuestTTL && !ch.seen(sideB)
		if old || now-ch.LastSeen > IdleTTL {
			s.drop(ch)
			delete(s.channels, id)
			gone++
		}
	}
	if gone > 0 {
		s.saveLocked()
	}
	return gone
}

// Engraft installs a socket into a slot, replacing an older one, and reports
// the socket it displaced plus whether the other side is present.
func (s *Store) Engraft(ch *Channel, side int, conn *wsConn) (old *wsConn, other *wsConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old = ch.conns[side]
	ch.conns[side] = conn
	ch.LastSeen = float64(time.Now().UnixNano()) / 1e9
	other = ch.conns[1-side]
	if ch.markSeen(side) {
		s.saveLocked()
	}
	return old, other
}

// Release frees a slot only if this socket still holds it, and reports whether
// it did. A replaced socket leaving late must not orphan its successor.
func (s *Store) Release(ch *Channel, side int, conn *wsConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch.conns[side] != conn {
		return false
	}
	ch.conns[side] = nil
	ch.LastSeen = float64(time.Now().UnixNano()) / 1e9
	s.saveLocked()
	return true
}

// Peer returns the socket in the other slot, if any.
func (s *Store) Peer(ch *Channel, side int) *wsConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ch.conns[1-side]
}

// CloseAll closes every socket with a code, for shutdown or a key over quota.
func (s *Store) CloseAll(code int, onlyKey string) {
	s.mu.Lock()
	var conns []*wsConn
	for _, ch := range s.channels {
		if onlyKey != "" && ch.Key != onlyKey {
			continue
		}
		for _, c := range ch.conns {
			if c != nil {
				conns = append(conns, c)
			}
		}
	}
	s.mu.Unlock()
	// Each Close waits for the peer's echo, so they run side by side and the
	// caller does not wait for any of them.
	for _, c := range conns {
		go c.close(code, "")
	}
}

// CloseAllNow closes every socket and waits for the close handshakes, for a
// process that is about to exit.
func (s *Store) CloseAllNow(code int, onlyKey string) {
	s.mu.Lock()
	var conns []*wsConn
	for _, ch := range s.channels {
		if onlyKey != "" && ch.Key != onlyKey {
			continue
		}
		for _, c := range ch.conns {
			if c != nil {
				conns = append(conns, c)
			}
		}
	}
	s.mu.Unlock()
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func(c *wsConn) {
			defer wg.Done()
			c.close(code, "")
		}(c)
	}
	wg.Wait()
}

func digestHex(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("relay: no entropy: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func randomB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("relay: no entropy: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
