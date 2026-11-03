package relay

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// A data frame's body is at most 1 MiB, first byte excluded.
const maxFrameBody = 1 << 20

// v0 set no explicit frame limit; uvicorn's default was 16 MiB.
const v0MaxMessage = 16 << 20

// How long a WebSocket may exist before its first frame names a token.
const authTimeout = 5 * time.Second

// Close codes from PROTOCOL.md 2.4.
const (
	codeProtocol    = 4400
	codeAuth        = 4401
	codeReplaced    = 4409
	codeDeleted     = 4410
	codeTooLarge    = 4413
	codeOverQuota   = 4429
	codeGoingAway   = 1001
	codeNormalClose = 1000
)

var systemFrames = map[string][]byte{
	"ready":             append([]byte{0}, []byte(`{"type":"system","event":"ready"}`)...),
	"peer_connected":    append([]byte{0}, []byte(`{"type":"system","event":"peer_connected"}`)...),
	"peer_disconnected": append([]byte{0}, []byte(`{"type":"system","event":"peer_disconnected"}`)...),
	"replaced":          append([]byte{0}, []byte(`{"type":"system","event":"replaced"}`)...),
}

// Config is the environment the relay runs with.
type Config struct {
	Addr            string
	StatePath       string
	KeysPath        string
	V0              bool
	MaxChannels     int64
	MaxPendingAuth  int64
	CreateBurst     float64
	CreatePerMinute float64
	SweepEvery      time.Duration
}

func ConfigFromEnv() Config {
	return Config{
		Addr:            envOr("RELAY_ADDR", "127.0.0.1:8010"),
		StatePath:       envOr("RELAY_STATE_PATH", "/data/channels.json"),
		KeysPath:        envOr("RELAY_KEYS_PATH", ""),
		V0:              strings.EqualFold(envOr("RELAY_V0", ""), "on"),
		MaxChannels:     envInt("RELAY_MAX_CHANNELS", 50000),
		MaxPendingAuth:  envInt("RELAY_MAX_PENDING_AUTH", 1024),
		CreateBurst:     float64(envInt("RELAY_CREATE_BURST", 30)),
		CreatePerMinute: float64(envInt("RELAY_CREATE_PER_MINUTE", 30)),
		SweepEvery:      5 * time.Minute,
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envInt(name string, fallback int64) int64 {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		log.Printf("%s is not a number; using %d", name, fallback)
		return fallback
	}
	return n
}

// Server holds the store, the keys and the counters the routes share.
type Server struct {
	cfg    Config
	store  *Store
	keys   atomic.Pointer[Keys]
	quotas *Quotas
	bucket *Bucket
	// pending counts sockets that have not authenticated yet, across all
	// channels; it is released when auth succeeds, fails or times out.
	pending atomic.Int64
}

func New(cfg Config) (*Server, error) {
	keys, err := LoadKeys(cfg.KeysPath)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:    cfg,
		store:  NewStore(cfg.StatePath),
		quotas: NewQuotas(),
		bucket: NewBucket(cfg.CreateBurst, cfg.CreatePerMinute),
	}
	s.keys.Store(keys)
	s.store.GC(float64(time.Now().Unix()))
	log.Printf("relay %s, v0 %t, %d issuer(s), %d operator key(s)", cfg.Addr, cfg.V0, len(keys.Issuers), len(keys.Keys))
	return s, nil
}

// ReloadKeys re-reads the keys file for SIGHUP. A broken file keeps the keys
// already loaded: a typo must not stop the relay that is serving.
func (s *Server) ReloadKeys() error {
	keys, err := LoadKeys(s.cfg.KeysPath)
	if err != nil {
		return err
	}
	s.keys.Store(keys)
	log.Printf("reloaded %d issuer(s), %d operator key(s)", len(keys.Issuers), len(keys.Keys))
	return nil
}

// Sweep forgets channels nobody claimed and channels abandoned for a month.
func (s *Server) Sweep() {
	if n := s.store.GC(float64(time.Now().Unix())); n > 0 {
		log.Printf("swept %d abandoned channel(s)", n)
	}
}

// Shutdown closes the sockets and writes the store once more.
func (s *Server) Shutdown() {
	s.store.CloseAll(codeGoingAway)
	s.store.Save()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/channels", s.createV1)
	mux.HandleFunc("DELETE /v1/channels/{id}", s.deleteV1)
	mux.HandleFunc("GET /v1/ws/{id}", s.wsV1)
	if s.cfg.V0 {
		mux.HandleFunc("POST /channels", s.createV0)
		mux.HandleFunc("GET /ws/{id}", s.wsV0)
	}
	return mux
}

func (s *Server) createV1(w http.ResponseWriter, r *http.Request) {
	raw := bearer(r)
	if raw == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	key, ok := s.keys.Load().Lookup(raw, time.Now())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !key.Unlimited {
		if retry, ok := s.quotas.Take(key.ID, key.CreatesPerMinute, time.Now().Unix()); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
	}
	ch, hostToken, guestToken, err := s.store.Create(1, key, s.cfg.MaxChannels)
	switch {
	case errors.Is(err, errQuota):
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	case errors.Is(err, errFull):
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	log.Printf("channel %s created", short(ch.ID))
	writeJSON(w, http.StatusCreated, map[string]string{
		"channel":     ch.ID,
		"host_token":  hostToken,
		"guest_token": guestToken,
	})
}

func (s *Server) deleteV1(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	token := bearer(r)
	if token != "" {
		ch, side, ok := s.store.ByToken(sha256.Sum256([]byte(token)))
		if ok && ch.V == 1 && ch.ID == id && side == host && s.store.Delete(id, codeDeleted) {
			log.Printf("channel %s deleted", short(id))
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

func (s *Server) wsV1(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.beginAuth() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	conn, err := accept(w, r)
	if err != nil {
		s.endAuth()
		return
	}
	ws := newWSConn(conn)

	// The URL carries no token: the first frame has five seconds to give one.
	// The deadline is a timer, not a read context: an expired read context
	// tears the connection down and the client would see 1006, not 4401.
	authed := make(chan struct{})
	timer := time.AfterFunc(authTimeout, func() {
		select {
		case <-authed:
		default:
			ws.close(codeAuth, "auth")
		}
	})
	typ, data, err := readMessage(context.Background(), conn, 64<<10)
	timer.Stop()
	close(authed)
	s.endAuth()
	if err != nil {
		ws.close(codeAuth, "auth")
		return
	}
	if typ != websocket.MessageText {
		ws.close(codeAuth, "auth")
		return
	}
	value, err := decodeStrictJSON(data)
	if err != nil {
		ws.close(codeAuth, "auth")
		return
	}
	obj, ok := value.(map[string]any)
	if !ok {
		ws.close(codeAuth, "auth")
		return
	}
	auth, ok := obj["auth"].(string)
	if !ok || auth == "" {
		ws.close(codeAuth, "auth")
		return
	}

	ch, side, ok := s.store.ByToken(sha256.Sum256([]byte(auth)))
	if !ok || ch.V != 1 || ch.ID != id {
		ws.close(codeAuth, "auth")
		return
	}
	// Authentication is settled; only now does quota speak, so a wrong token
	// learns nothing about the channel it named.
	if !ch.Unlimited && s.quotas.Used(ch.Key, time.Now().Unix()) >= ch.LimitBytes {
		ws.close(codeOverQuota, "bytes_per_day")
		return
	}

	old, other := s.store.Engraft(ch, side, ws)
	if old != nil {
		old.sendSystem("replaced")
		old.closeSoon(codeReplaced, "replaced")
	}
	ws.sendReady()
	if other != nil {
		other.sendSystem("peer_connected")
		ws.sendSystem("peer_connected")
	}
	s.readLoop(ws, conn, ch, side, true)
}

// beginAuth takes one pending-auth slot, or reports that the global cap is
// already reached and the upgrade must be refused before it is accepted.
func (s *Server) beginAuth() bool {
	if s.pending.Add(1) > s.cfg.MaxPendingAuth {
		s.pending.Add(-1)
		return false
	}
	return true
}

// endAuth releases a slot taken by beginAuth. It runs on every exit from the
// auth phase: success, a bad frame, a read error or the timeout closing the
// socket.
func (s *Server) endAuth() {
	s.pending.Add(-1)
}

func (s *Server) createV0(w http.ResponseWriter, r *http.Request) {
	// v0's order is kept as it was: a full relay refuses before the bucket.
	if int64(s.store.Len()) >= s.cfg.MaxChannels {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if !s.bucket.Take() {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	ch, bridge, mobile, err := s.store.Create(0, KeyInfo{}, s.cfg.MaxChannels)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	log.Printf("channel %s created", short(ch.ID))
	writeJSON(w, http.StatusOK, map[string]string{
		"channel_id":   ch.ID,
		"token_mobile": mobile,
		"token_bridge": bridge,
	})
}

func (s *Server) wsV0(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	token := r.URL.Query().Get("token")
	ch, side, ok := s.store.ByToken(sha256.Sum256([]byte(token)))
	// Refused before the handshake: a wrong or forgotten slot gets an HTTP
	// 403, never an open socket a client counts as a connection.
	if token == "" || !ok || ch.V != 0 || ch.ID != id {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	conn, err := accept(w, r)
	if err != nil {
		return
	}
	ws := newWSConn(conn)
	ws.ready = true

	old, other := s.store.Engraft(ch, side, ws)
	if old != nil {
		old.closeSoon(codeReplaced, "replaced")
	}
	if other != nil {
		other.sendSystem("peer_connected")
		ws.sendSystem("peer_connected")
	}
	s.readLoop(ws, conn, ch, side, false)
}

// readLoop moves frames from one side to the other until the socket goes.
func (s *Server) readLoop(ws *wsConn, conn *websocket.Conn, ch *Channel, side int, v1 bool) {
	defer func() {
		if s.store.Release(ch, side, ws) {
			if peer := s.store.Peer(ch, side); peer != nil {
				peer.sendSystem("peer_disconnected")
			}
		}
		ws.close(codeNormalClose, "")
	}()
	limit := v0MaxMessage
	if v1 {
		limit = maxFrameBody + 1
	}
	for {
		typ, data, err := readMessage(context.Background(), conn, limit)
		if err != nil {
			return
		}
		if v1 {
			if typ != websocket.MessageBinary {
				ws.close(codeProtocol, "binary frames only")
				return
			}
			if len(data) == 0 || data[0] != 0x01 {
				ws.close(codeProtocol, "data frames only")
				return
			}
			if len(data) > maxFrameBody+1 {
				ws.close(codeTooLarge, "frame too large")
				return
			}
		} else {
			if typ != websocket.MessageBinary {
				return
			}
			if len(data) > limit {
				ws.close(int(websocket.StatusMessageTooBig), "message too big")
				return
			}
		}
		peer := s.store.Peer(ch, side)
		if peer == nil {
			continue // no store and forward
		}
		if err := peer.send(data); err != nil {
			continue
		}
		if v1 && !ch.Unlimited {
			used := s.quotas.AddBytes(ch.Key, int64(len(data)), time.Now().Unix())
			if used > ch.LimitBytes {
				log.Printf("key over bytes_per_day; closing its channels")
				s.store.CloseKey(codeOverQuota, ch.Key)
				return
			}
		}
	}
}

func accept(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Authentication is a bearer token in the first frame, never a cookie
		// or any other ambient credential, so a cross-site origin has nothing
		// to hijack. Refusing it only locks out browsers and WebViews, which
		// always send Origin.
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err == nil {
		// Messages are bounded by the caller's own reader, which is what lets a
		// too-large frame end in 4413 rather than the library's 1009.
		conn.SetReadLimit(-1)
	}
	return conn, err
}

// readMessage reads one message up to limit bytes and returns how much it got.
// Reading one byte past the limit is what lets the caller answer with the
// protocol's own 4413 rather than the library's 1009.
func readMessage(ctx context.Context, conn *websocket.Conn, limit int) (websocket.MessageType, []byte, error) {
	typ, reader, err := conn.Reader(ctx)
	if err != nil {
		return 0, nil, err
	}
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	return typ, data, err
}

func bearer(r *http.Request) string {
	scheme, value, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	data, err := json.Marshal(body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}

// short is all a log line may carry of a channel id.
func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// wsConn serializes writes and holds back system frames until `ready` has
// gone out first, so a fast peer cannot make peer_connected precede it.
type wsConn struct {
	conn   *websocket.Conn
	mu     sync.Mutex
	ready  bool
	queue  [][]byte
	closed bool
}

func newWSConn(conn *websocket.Conn) *wsConn {
	return &wsConn{conn: conn}
}

func (w *wsConn) write(data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return w.conn.Write(ctx, websocket.MessageBinary, data)
}

// maxQueued bounds what a socket can receive before its ready frame has gone
// out. It is a few frames wide: the window opens and closes in one handler.
const maxQueued = 64

func (w *wsConn) sendSystem(event string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	if !w.ready {
		w.enqueue(systemFrames[event])
		return
	}
	w.write(systemFrames[event])
}

func (w *wsConn) enqueue(frame []byte) {
	if len(w.queue) < maxQueued {
		w.queue = append(w.queue, frame)
	}
}

func (w *wsConn) sendReady() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.write(systemFrames["ready"])
	w.ready = true
	for _, frame := range w.queue {
		w.write(frame)
	}
	w.queue = nil
}

func (w *wsConn) send(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("closed")
	}
	if !w.ready {
		// A frame can arrive from the other side between this socket taking
		// its slot and its ready frame leaving; hold it so ready still goes
		// first, in order.
		w.enqueue(data)
		return nil
	}
	return w.write(data)
}

// claimClose takes ownership of the socket's close, so the code that wins the
// race is the one the client sees. It reports whether this call owns it.
func (w *wsConn) claimClose() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return false
	}
	w.closed = true
	w.queue = nil
	return true
}

// close sends a close frame and waits for the peer's echo.
func (w *wsConn) close(code int, reason string) {
	if !w.claimClose() {
		return
	}
	w.conn.Close(websocket.StatusCode(code), reason)
}

// closeSoon claims the close now and writes the frame in the background, so a
// caller holding a lock never waits on the network.
func (w *wsConn) closeSoon(code int, reason string) {
	if !w.claimClose() {
		return
	}
	go w.conn.Close(websocket.StatusCode(code), reason)
}
