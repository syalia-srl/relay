package rooms

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syalia-srl/relay/server/internal/relay"
)

// Limits of ROOMS.md 3.3 and 3.4.
const (
	maxJSONBody     = 1 << 20
	maxRecord       = 64 << 10
	maxCiphertext   = 65536
	maxPushToken    = 4096
	maxInviteUses   = 1000
	maxInviteDays   = 30
	defaultPage     = 100
	maxPage         = 500
	maxSocketTokens = 256

	day             = 86400
	silentAfter     = 14 * day // a device silent this long holds nothing back
	setUpWithin     = 3600     // a room without roster record 1 is deleted after this
	unnamedBlobLife = day      // a blob no message names
	readOnlyLife    = 30 * day // a read-only room, then deleted
	tombstoneLife   = 30 * day // a deleted room answers 410 this long
)

// Config is what the rooms service runs with.
type Config struct {
	// Path is the SQLite database, RELAY_ROOMS_PATH.
	Path string
	// TestClock, RELAY_TEST_CLOCK, names a file holding a number of seconds
	// added to the real clock. Test-only: it also sweeps before every
	// request, so a test that moves the clock sees the rules at once.
	TestClock string
	// MaxPendingAuth caps notification sockets that have not sent tokens.
	MaxPendingAuth int64
	// Push names the push gateway; its zero value leaves push off.
	Push PushConfig
}

// Service serves /v1/rooms.
type Service struct {
	db    *sql.DB
	keys  func() *relay.Keys
	now   Clock
	test  bool
	hub   *hub
	push  *pusher
	sweep sync.Mutex

	pendingMu sync.Mutex
	pending   int64
	maxAuth   int64
}

// Open opens the database and returns the service. keys gives the keys file
// in use, which SIGHUP may replace.
func Open(cfg Config, keys func() *relay.Keys) (*Service, error) {
	db, err := openDB(cfg.Path)
	if err != nil {
		return nil, err
	}
	s := &Service{db: db, keys: keys, now: time.Now, hub: newHub(), maxAuth: cfg.MaxPendingAuth}
	if cfg.TestClock != "" {
		s.now = fileClock(cfg.TestClock)
		s.test = true
		log.Print("RELAY_TEST_CLOCK is set: the rooms clock is shifted and sweeps run on every request; never in production")
	}
	s.push = newPusher(cfg.Push, s.clearPush)
	return s, nil
}

// fileClock is the test clock: the real time plus the seconds in a file.
func fileClock(path string) Clock {
	return func() time.Time {
		data, err := os.ReadFile(path)
		if err != nil {
			return time.Now()
		}
		offset, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			return time.Now()
		}
		return time.Now().Add(time.Duration(offset) * time.Second)
	}
}

// Close closes the notification sockets with 1001 and the database.
func (s *Service) Close() {
	s.push.close()
	s.hub.closeAll(1001)
	s.db.Close()
}

// Unavailable serves /v1/rooms when the database could not be opened: the
// channels keep working, rooms answer 503.
func Unavailable() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
	})
}

// CORS lets a page on any origin call the room routes (ROOMS.md 3.3): every
// answer under /v1/rooms carries the headers, and a preflight gets 204. Tokens
// travel in the Authorization header, never in a cookie, so no credentials are
// allowed. Other routes pass through untouched.
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/rooms" && !strings.HasPrefix(r.URL.Path, "/v1/rooms/") {
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Expose-Headers", "Relay-Room-Watermark")
		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Register adds the room routes to mux.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/rooms", s.wrap(s.createRoom))
	mux.HandleFunc("GET /v1/rooms/quota", s.wrap(s.quota))
	mux.HandleFunc("GET /v1/rooms/ws", s.socket)
	mux.HandleFunc("POST /v1/rooms/{id}/join", s.wrap(s.join))

	mux.HandleFunc("POST /v1/rooms/{id}/invites", s.device(owner|write, s.createInvite))
	mux.HandleFunc("DELETE /v1/rooms/{id}/invites/{invite}", s.device(owner|write, s.closeInvite))
	mux.HandleFunc("GET /v1/rooms/{id}/roster", s.device(0, s.getRoster))
	mux.HandleFunc("POST /v1/rooms/{id}/roster", s.device(write, s.postRoster))
	mux.HandleFunc("GET /v1/rooms/{id}/epochs", s.device(0, s.getEpochs))
	mux.HandleFunc("POST /v1/rooms/{id}/epochs", s.device(noCustodian|write, s.postEpoch))
	mux.HandleFunc("POST /v1/rooms/{id}/owners", s.device(owner|write, s.setOwner))
	mux.HandleFunc("DELETE /v1/rooms/{id}/devices/{device}", s.device(0, s.removeDevice))
	mux.HandleFunc("GET /v1/rooms/{id}/messages", s.device(noCustodian, s.getMessages))
	mux.HandleFunc("POST /v1/rooms/{id}/messages", s.device(noCustodian|write, s.postMessage))
	mux.HandleFunc("PUT /v1/rooms/{id}/blobs/{blob}", s.putBlob)
	mux.HandleFunc("GET /v1/rooms/{id}/blobs/{blob}", s.device(noCustodian, s.getBlob))
	mux.HandleFunc("POST /v1/rooms/{id}/ack", s.device(0, s.ack))
	mux.HandleFunc("PUT /v1/rooms/{id}/push", s.device(write, s.setPush))
	mux.HandleFunc("GET /v1/rooms/{id}", s.device(0, s.getRoom))
	mux.HandleFunc("DELETE /v1/rooms/{id}", s.device(owner, s.deleteRoom))
}

// apiError is a refusal: a status and one of ROOMS.md 3.3's codes. commit
// keeps what the transaction did before the refusal.
type apiError struct {
	status int
	code   string
	commit bool
}

func (e *apiError) Error() string { return e.code }

var (
	errBadRequest   = &apiError{status: 400, code: "bad_request"}
	errUnauthorized = &apiError{status: 401, code: "unauthorized"}
	errForbidden    = &apiError{status: 403, code: "forbidden"}
	errNotFound     = &apiError{status: 404, code: "not_found"}
	errConflict     = &apiError{status: 409, code: "conflict"}
	errGone         = &apiError{status: 410, code: "gone"}
	errTooLarge     = &apiError{status: 413, code: "too_large"}
	errReadOnly     = &apiError{status: 423, code: "read_only"}
	errFull         = &apiError{status: 507, code: "full"}
)

// reply is what a handler answers: a status and a JSON body, raw bytes, or
// nothing for 204.
type reply struct {
	status int
	body   any
	raw    []byte
}

func noContent() reply { return reply{status: http.StatusNoContent} }

// request is what every handler gets: the request, its body read up to the
// JSON limit, and the instant it is judged at.
type request struct {
	r       *http.Request
	body    []byte
	tooBig  bool
	now     int64
	headers http.Header
}

func (s *Service) newRequest(w http.ResponseWriter, r *http.Request, readBody bool) *request {
	if s.test {
		s.Sweep()
	}
	req := &request{r: r, now: s.now().Unix(), headers: w.Header()}
	if readBody {
		data, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
		if err == nil {
			req.body = data
			req.tooBig = len(data) > maxJSONBody
		}
	}
	return req
}

// wrap runs a handler that authenticates for itself, in one transaction.
func (s *Service) wrap(fn func(tx *sql.Tx, req *request) (reply, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := s.newRequest(w, r, r.Method != http.MethodGet)
		var out reply
		err := inTx(r.Context(), s.db, func(tx *sql.Tx) error {
			var err error
			out, err = fn(tx, req)
			return err
		})
		respond(w, out, err)
	}
}

func respond(w http.ResponseWriter, out reply, err error) {
	var api *apiError
	switch {
	case errors.As(err, &api):
		writeJSON(w, api.status, map[string]string{"error": api.code})
	case err != nil:
		if !errors.Is(err, context.Canceled) {
			log.Printf("rooms: %v", err)
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
	case out.raw != nil:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(out.status)
		w.Write(out.raw)
	case out.body == nil:
		w.WriteHeader(out.status)
	default:
		writeJSON(w, out.status, out.body)
	}
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

func bearer(r *http.Request) string {
	scheme, value, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

// short is all a log line may carry of an id.
func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
