// Package relay implements the E2E message relay: two-slot channels, kept
// across a restart, and the bytes in between.
package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// A channel has two slots. v0 calls the host slot bridge and the guest slot
// mobile; the difference is only in the state file's field names.
const (
	host  = 0
	guest = 1
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

	// The bytes_per_day of the creating key. Data frames carry no key of their
	// own, so the limit that governs them has to travel with the channel.
	LimitBytes int64 `json:"limit_bytes,omitempty"`
	Unlimited  bool  `json:"unlimited,omitempty"`

	conns   [2]*wsConn
	savedAt float64 // when this row last reached disk, to keep saves rare
}

func (ch *Channel) hash(side int) string {
	switch {
	case ch.V == 1 && side == host:
		return ch.HashHost
	case ch.V == 1:
		return ch.HashGuest
	case side == host:
		return ch.HashBridge
	default:
		return ch.HashMobile
	}
}

func (ch *Channel) guestSeen() bool {
	return ch.GuestSeen || ch.MobileSeen
}

// markGuestSeen reports whether this is the first time, which is worth a save.
func (ch *Channel) markGuestSeen() bool {
	if ch.guestSeen() {
		return false
	}
	if ch.V == 1 {
		ch.GuestSeen = true
	} else {
		ch.MobileSeen = true
	}
	return true
}

type tokenRef struct {
	ch   *Channel
	side int
}

// Store keeps channels and their token digests. What reaches disk is the
// channel id and a SHA-256 of each token, never a token: a copy of the file
// opens no slot. Tokens are found by digest, so no token is ever compared with
// another, and nobody can choose a digest to probe the map with.
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
	for _, side := range [2]int{host, guest} {
		if digest, ok := parseDigest(ch.hash(side)); ok {
			s.tokens[digest] = tokenRef{ch: ch, side: side}
		}
	}
	if ch.Key != "" {
		s.alive[ch.Key]++
	}
}

func (s *Store) drop(ch *Channel) {
	delete(s.channels, ch.ID)
	for _, side := range [2]int{host, guest} {
		if digest, ok := parseDigest(ch.hash(side)); ok {
			delete(s.tokens, digest)
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
	now := float64(time.Now().Unix())
	for _, ch := range s.channels {
		ch.savedAt = now
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

func (s *Store) Get(id string) *Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.channels[id]
}

// ByToken resolves a token digest to its channel and slot.
func (s *Store) ByToken(digest [32]byte) (*Channel, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, ok := s.tokens[digest]
	return ref.ch, ref.side, ok
}

var (
	errQuota = errors.New("over the key's channels")
	errFull  = errors.New("relay full")
)

// Create makes a channel and returns it with both plaintext tokens, which
// exist only in the creating request's answer. The key's channel quota and the
// relay's capacity are checked under the same lock that adds the channel, so
// concurrent creations cannot overshoot either.
func (s *Store) Create(v int, key KeyInfo, maxChannels int64) (ch *Channel, hostToken, guestToken string, err error) {
	if v == 1 {
		hostToken, guestToken = randomB64(32), randomB64(32)
	} else {
		// v0's ids and tokens are both 64 hex characters; keep them so a
		// client that stored one keeps working.
		hostToken, guestToken = randomHex(32), randomHex(32)
	}
	now := float64(time.Now().UnixNano()) / 1e9
	ch = &Channel{CreatedAt: now, LastSeen: now, V: v, Key: key.ID, LimitBytes: key.BytesPerDay, Unlimited: key.Unlimited}
	if v == 1 {
		ch.ID = randomB64(16)
		ch.HashHost, ch.HashGuest = digestHex(hostToken), digestHex(guestToken)
	} else {
		ch.ID = randomHex(32)
		ch.HashBridge, ch.HashMobile = digestHex(hostToken), digestHex(guestToken)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if key.ID != "" && !key.Unlimited && int64(s.alive[key.ID]) >= key.Channels {
		return nil, "", "", errQuota
	}
	if int64(len(s.channels)) >= maxChannels {
		return nil, "", "", errFull
	}
	s.index(ch)
	s.saveLocked()
	return ch, hostToken, guestToken, nil
}

// Delete removes a channel and closes both its sockets with code.
func (s *Store) Delete(id string, code int) bool {
	s.mu.Lock()
	ch := s.channels[id]
	if ch == nil {
		s.mu.Unlock()
		return false
	}
	conns := ch.conns
	ch.conns = [2]*wsConn{}
	s.drop(ch)
	s.saveLocked()
	s.mu.Unlock()
	// Outside the lock: claiming a socket can wait on a write in progress.
	// Their read loops cannot close them first, since nothing ends a read
	// but the close sent here or the client leaving.
	for _, c := range conns {
		if c != nil {
			c.closeSoon(code, "deleted")
		}
	}
	return true
}

// GC forgets unscanned and abandoned channels; a connected one always stays.
func (s *Store) GC(now float64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	gone := 0
	for _, ch := range s.channels {
		if ch.conns[host] != nil || ch.conns[guest] != nil {
			continue // a connected channel always stays
		}
		old := now-ch.CreatedAt > GuestTTL && !ch.guestSeen()
		if old || now-ch.LastSeen > IdleTTL {
			s.drop(ch)
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
	if side == guest && ch.markGuestSeen() {
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
	now := float64(time.Now().UnixNano()) / 1e9
	ch.LastSeen = now
	// A disconnect is worth persisting for the 30-day sweep, but not a file
	// rewrite per reconnection: an hour of staleness cannot matter there.
	if now-ch.savedAt > 3600 {
		s.saveLocked()
	}
	return true
}

// Peer returns the socket in the other slot, if any.
func (s *Store) Peer(ch *Channel, side int) *wsConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ch.conns[1-side]
}

// sockets lists the open sockets, of one key's channels or of all of them.
func (s *Store) sockets(onlyKey string) []*wsConn {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	return conns
}

// CloseKey closes the sockets of one key's channels, for a key over quota.
func (s *Store) CloseKey(code int, key string) {
	for _, c := range s.sockets(key) {
		c.closeSoon(code, "")
	}
}

// CloseAll closes every socket and waits for the close handshakes, for a
// process that is about to exit.
func (s *Store) CloseAll(code int) {
	var wg sync.WaitGroup
	for _, c := range s.sockets("") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.close(code, "")
		}()
	}
	wg.Wait()
}

// parseDigest reads a hex SHA-256 from the state file.
func parseDigest(h string) ([32]byte, bool) {
	var digest [32]byte
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != sha256.Size {
		return digest, false
	}
	copy(digest[:], raw)
	return digest, true
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
