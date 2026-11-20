package rooms

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/syalia-srl/relay/server/internal/relay"
)

// Close codes of ROOMS.md 3.5.
const (
	codeAuth    = 4401
	codeNothing = 4410
)

const authTimeout = 5 * time.Second

// watcher is one notification socket and the rooms it watches, each through
// the device whose token named it.
type watcher struct {
	conn   *websocket.Conn
	frames chan []byte
	rooms  map[string]string // room id -> device id
	once   sync.Once
	done   chan struct{}
}

// close ends the socket once, with the first code asked for.
func (w *watcher) close(code int) {
	w.once.Do(func() {
		close(w.done)
		go w.conn.Close(websocket.StatusCode(code), "")
	})
}

// hub knows which sockets watch which room.
type hub struct {
	mu       sync.Mutex
	watchers map[string]map[*watcher]bool
}

func newHub() *hub {
	return &hub{watchers: make(map[string]map[*watcher]bool)}
}

func (h *hub) add(w *watcher) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for roomID := range w.rooms {
		if h.watchers[roomID] == nil {
			h.watchers[roomID] = make(map[*watcher]bool)
		}
		h.watchers[roomID][w] = true
	}
}

func (h *hub) remove(w *watcher) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for roomID := range w.rooms {
		delete(h.watchers[roomID], w)
		if len(h.watchers[roomID]) == 0 {
			delete(h.watchers, roomID)
		}
	}
}

// notify sends {"room", "seq"} to each socket watching the room. A socket too
// slow to take it misses the hint, which loses nothing: it fetches from its
// last sequence.
func (h *hub) notify(roomID string, seq int64) {
	frame, _ := json.Marshal(map[string]any{"room": roomID, "seq": seq})
	h.mu.Lock()
	defer h.mu.Unlock()
	for w := range h.watchers[roomID] {
		select {
		case w.frames <- frame:
		default:
		}
	}
}

// drop stops sockets watching a room, through one device or any; a socket
// left with nothing to watch is closed with 4410.
func (h *hub) drop(roomID, deviceID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for w := range h.watchers[roomID] {
		if deviceID != "" && w.rooms[roomID] != deviceID {
			continue
		}
		delete(w.rooms, roomID)
		delete(h.watchers[roomID], w)
		if len(w.rooms) == 0 {
			w.close(codeNothing)
		}
	}
	if len(h.watchers[roomID]) == 0 {
		delete(h.watchers, roomID)
	}
}

func (h *hub) dropRoom(roomID string)             { h.drop(roomID, "") }
func (h *hub) dropDevice(roomID, deviceID string) { h.drop(roomID, deviceID) }

func (h *hub) closeAll(code int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, set := range h.watchers {
		for w := range set {
			w.close(code)
		}
	}
}

func (s *Service) beginAuth() bool {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.pending >= s.maxAuth {
		return false
	}
	s.pending++
	return true
}

func (s *Service) endAuth() {
	s.pendingMu.Lock()
	s.pending--
	s.pendingMu.Unlock()
}

// socket serves GET /v1/rooms/ws: the first text frame, within five seconds,
// names 1 to 256 device tokens; the relay watches the rooms of those it
// accepts and closes with 4401 when it accepts none.
func (s *Service) socket(w http.ResponseWriter, r *http.Request) {
	if !s.beginAuth() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Tokens travel in the first frame, never in a cookie, so a
		// cross-site origin has nothing to ride on.
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		s.endAuth()
		return
	}
	conn.SetReadLimit(-1)

	// The deadline is a timer, not a read context: an expired read context
	// tears the connection down and the client would see 1006, not 4401.
	authed := make(chan struct{})
	timer := time.AfterFunc(authTimeout, func() {
		select {
		case <-authed:
		default:
			conn.Close(codeAuth, "auth")
		}
	})
	tokens, ok := readTokens(conn)
	timer.Stop()
	close(authed)
	s.endAuth()
	if !ok {
		conn.Close(codeAuth, "auth")
		return
	}
	rooms, err := s.watchable(r.Context(), tokens)
	if err != nil || len(rooms) == 0 {
		conn.Close(codeAuth, "auth")
		return
	}

	wt := &watcher{conn: conn, frames: make(chan []byte, 64), rooms: rooms, done: make(chan struct{})}
	s.hub.add(wt)
	defer s.hub.remove(wt)

	// Reads are only drained, to see the close: the client has nothing to say.
	go func() {
		for {
			if _, _, err := conn.Reader(context.Background()); err != nil {
				wt.close(int(websocket.StatusNormalClosure))
				return
			}
		}
	}()
	for {
		select {
		case <-wt.done:
			return
		case frame := <-wt.frames:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := conn.Write(ctx, websocket.MessageText, frame)
			cancel()
			if err != nil {
				wt.close(int(websocket.StatusGoingAway))
				return
			}
		}
	}
}

func readTokens(conn *websocket.Conn) ([]string, bool) {
	typ, reader, err := conn.Reader(context.Background())
	if err != nil || typ != websocket.MessageText {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(reader, 64<<10+1))
	if err != nil || len(data) > 64<<10 {
		return nil, false
	}
	value, err := relay.DecodeStrictJSON(data)
	if err != nil {
		return nil, false
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	list, ok := obj["tokens"].([]any)
	if !ok || len(list) < 1 || len(list) > maxSocketTokens {
		return nil, false
	}
	tokens := make([]string, 0, len(list))
	for _, v := range list {
		t, ok := v.(string)
		if !ok {
			return nil, false
		}
		tokens = append(tokens, t)
	}
	return tokens, true
}

// watchable maps the rooms of the accepted tokens to their devices: tokens
// not revoked, of rooms not deleted. Others are ignored.
func (s *Service) watchable(ctx context.Context, tokens []string) (map[string]string, error) {
	rooms := make(map[string]string)
	err := inTx(ctx, s.db, func(tx *sql.Tx) error {
		for _, t := range tokens {
			var deviceID, roomID string
			err := tx.QueryRow(`SELECT d.id, d.room FROM devices d JOIN rooms r ON r.id = d.room
				WHERE d.token = ? AND d.revoked = 0 AND r.deleted_at IS NULL`, digest(t)).Scan(&deviceID, &roomID)
			if err == sql.ErrNoRows {
				continue
			}
			if err != nil {
				return err
			}
			rooms[roomID] = deviceID
		}
		return nil
	})
	return rooms, err
}
