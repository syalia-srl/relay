package pushgw

import (
	"encoding/json"
	"io"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxTokens    = 500
	maxTokenLen  = 4096     // characters, as the relay's PUT /push
	maxBody      = 16 << 20 // 500 tokens of 4096 characters, escaped
	sendWorkers  = 16
	fcmRetryWait = 10 * time.Second // Retry-After when FCM gave none
	maxRetryWait = 60 * time.Second
)

// Sender is what the gateway needs of FCM.
type Sender interface {
	Send(token string) (Outcome, time.Duration)
}

// Server answers POST /v1/wake.
type Server struct {
	keys *Keys
	fcm  Sender
}

func NewServer(keys *Keys, fcm Sender) *Server { return &Server{keys: keys, fcm: fcm} }

// Handler serves the one route.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/wake", s.wake)
	return mux
}

func (s *Server) wake(w http.ResponseWriter, r *http.Request) {
	scheme, bearer, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Bearer") {
		bearer = ""
	}
	id, ok, retryAfter := s.keys.Admit(strings.TrimSpace(bearer))
	if !ok {
		log.Print("wake refused: 401")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if retryAfter > 0 {
		log.Printf("wake from %s refused: 429, over per_minute", id)
		w.Header().Set("Retry-After", seconds(retryAfter))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}
	tokens, ok := parseTokens(http.MaxBytesReader(w, r.Body, maxBody))
	if !ok {
		log.Printf("wake from %s refused: 400", id)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}

	outcomes := make([]Outcome, len(tokens))
	waits := make([]time.Duration, len(tokens))
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(sendWorkers, len(tokens)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				outcomes[i], waits[i] = s.fcm.Send(tokens[i])
			}
		}()
	}
	for i := range tokens {
		next <- i
	}
	close(next)
	wg.Wait()

	invalid := []string{}
	var sent, transient, failed int
	var wait time.Duration
	for i, o := range outcomes {
		switch o {
		case Sent:
			sent++
		case Invalid:
			invalid = append(invalid, tokens[i])
		case Transient:
			transient++
			wait = max(wait, waits[i])
		case Failed:
			failed++
		}
	}
	log.Printf("wake from %s: %d tokens, %d sent, %d invalid, %d transient, %d failed",
		id, len(tokens), sent, len(invalid), transient, failed)
	if transient > 0 {
		// FCM is busy or down: the relay retries the whole batch, and no token
		// is marked invalid on a partial answer.
		if wait == 0 {
			wait = fcmRetryWait
		}
		w.Header().Set("Retry-After", seconds(min(wait, maxRetryWait)))
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"invalid": invalid})
}

// parseTokens accepts {"tokens": [...]} with 1 to 500 non-empty strings of at
// most 4096 characters and nothing else, and drops repeats.
func parseTokens(body io.Reader) ([]string, bool) {
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(body).Decode(&raw); err != nil || len(raw) != 1 {
		return nil, false
	}
	var tokens []any
	if err := json.Unmarshal(raw["tokens"], &tokens); err != nil || len(tokens) < 1 || len(tokens) > maxTokens {
		return nil, false
	}
	seen := make(map[string]bool, len(tokens))
	out := make([]string, 0, len(tokens))
	for _, v := range tokens {
		t, ok := v.(string)
		if !ok || t == "" || utf8.RuneCountInString(t) > maxTokenLen {
			return nil, false
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, true
}

func seconds(d time.Duration) string {
	return strconv.Itoa(max(1, int(math.Ceil(d.Seconds()))))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	data, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}
