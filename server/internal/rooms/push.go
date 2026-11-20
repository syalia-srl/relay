package rooms

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Push of ROOMS.md 3.7 and contract C11: when a room takes a message, the
// push tokens of its other devices go to the gateway named in the relay's own
// configuration, and nothing else does. Turning push on sends the gateway's
// operator, for each wake-up, a device's push token and the time; never a
// room id, a sender or any content.
const (
	pushWindow     = 2 * time.Second // a batch is sent this long after its first token
	pushBatchMax   = 500             // tokens per call
	pushQueueMax   = 10000           // tokens waiting; the oldest go first
	pushTimeout    = 5 * time.Second
	pushRetryAfter = 60 * time.Second // the longest Retry-After the relay honours
	pushAnswerMax  = 1 << 20
)

// pushBackoff is the wait before each retry; after the last the batch is dropped.
var pushBackoff = []time.Duration{1 * time.Second, 4 * time.Second, 16 * time.Second}

// PushConfig is how the relay reaches its push gateway.
type PushConfig struct {
	// URL, RELAY_PUSH_URL, is the gateway's full endpoint. Empty: push is off.
	URL string
	// KeyPath, RELAY_PUSH_KEY_PATH, is a file (0600) holding the gateway key.
	KeyPath string
	// Scale, RELAY_TEST_PUSH_SCALE, multiplies the batch window and the
	// backoff. Test-only; 0 means 1.
	Scale float64
}

// pusher queues push tokens and sends them to the gateway in batches.
type pusher struct {
	url    string
	key    string
	client *http.Client
	window time.Duration
	scale  float64
	clear  func(tokens []string) // forgets tokens the gateway called invalid

	mu     sync.Mutex
	queue  []string
	queued map[string]bool
	wake   chan struct{}
	stop   chan struct{}
	done   sync.WaitGroup
}

// newPusher returns nil, and logs why, when push is off.
func newPusher(cfg PushConfig, clear func([]string)) *pusher {
	if cfg.URL == "" {
		log.Print("push is off: RELAY_PUSH_URL is not set")
		return nil
	}
	if err := checkPushURL(cfg.URL); err != nil {
		log.Printf("push gateway URL must be https; push is off: %v", err)
		return nil
	}
	data, err := os.ReadFile(cfg.KeyPath)
	key := strings.TrimSpace(string(data))
	if cfg.KeyPath == "" || err != nil || key == "" {
		log.Print("push gateway key not readable; push is off")
		return nil
	}
	scale := cfg.Scale
	if scale <= 0 {
		scale = 1
	} else if scale != 1 {
		log.Print("RELAY_TEST_PUSH_SCALE is set: push batching and backoff are scaled; never in production")
	}
	p := &pusher{
		url: cfg.URL,
		key: key,
		client: &http.Client{
			Timeout: pushTimeout,
			// The relay calls exactly the configured URL.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		window: time.Duration(float64(pushWindow) * scale),
		scale:  scale,
		clear:  clear,
		queued: map[string]bool{},
		wake:   make(chan struct{}, 1),
		stop:   make(chan struct{}),
	}
	p.done.Add(1)
	go p.run()
	log.Print("push is on: each wake-up sends the gateway a device's push token and the time")
	return p
}

// checkPushURL accepts https, and http only to a loopback host for tests.
func checkPushURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("not an absolute URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("scheme %q to a non-loopback host", u.Scheme)
}

// add queues tokens; one already waiting is not queued twice.
func (p *pusher) add(tokens []string) {
	if p == nil || len(tokens) == 0 {
		return
	}
	p.mu.Lock()
	for _, t := range tokens {
		if p.queued[t] {
			continue
		}
		if len(p.queue) >= pushQueueMax {
			delete(p.queued, p.queue[0])
			p.queue = p.queue[1:]
		}
		p.queue = append(p.queue, t)
		p.queued[t] = true
	}
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// take empties the queue in calls of at most pushBatchMax tokens.
func (p *pusher) take() [][]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var batches [][]string
	for len(p.queue) > 0 {
		n := min(len(p.queue), pushBatchMax)
		batches = append(batches, p.queue[:n:n])
		p.queue = p.queue[n:]
	}
	p.queue = nil
	p.queued = map[string]bool{}
	return batches
}

// run sends the queue a window after its first token, so sends are at least a
// window apart and every token of the window goes in one batch.
func (p *pusher) run() {
	defer p.done.Done()
	for {
		select {
		case <-p.wake:
		case <-p.stop:
			return
		}
		select {
		case <-time.After(p.window):
		case <-p.stop:
			return
		}
		for _, batch := range p.take() {
			p.done.Add(1)
			go func() {
				defer p.done.Done()
				p.send(batch)
			}()
		}
	}
}

// close stops sending; batches still waiting are dropped.
func (p *pusher) close() {
	if p == nil {
		return
	}
	close(p.stop)
	p.done.Wait()
}

// send delivers one batch, retrying per C11, and clears the tokens the
// gateway calls invalid. It logs counts and statuses only.
func (p *pusher) send(batch []string) {
	for attempt := 0; ; attempt++ {
		status, retryAfter, invalid, err := p.call(batch)
		switch {
		case err == nil && status == http.StatusOK:
			p.forget(batch, invalid)
			log.Printf("push: %d tokens sent, status 200, %d invalid", len(batch), len(invalid))
			return
		case err != nil:
			log.Printf("push: %d tokens, call failed (attempt %d)", len(batch), attempt+1)
		default:
			log.Printf("push: %d tokens, status %d (attempt %d)", len(batch), status, attempt+1)
		}
		retry := err != nil || status == http.StatusTooManyRequests || status >= 500
		if !retry || attempt >= len(pushBackoff) {
			log.Printf("push batch dropped: %d tokens", len(batch))
			return
		}
		wait := time.Duration(float64(pushBackoff[attempt]) * p.scale)
		if status == http.StatusTooManyRequests && retryAfter > 0 {
			wait = min(retryAfter, pushRetryAfter)
		}
		select {
		case <-time.After(wait):
		case <-p.stop:
			return
		}
	}
}

// call makes one POST and returns the status, a Retry-After and the invalid tokens.
func (p *pusher) call(batch []string) (int, time.Duration, []string, error) {
	body, err := json.Marshal(map[string][]string{"tokens": batch})
	if err != nil {
		return 0, 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return 0, 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, 0, nil, err
	}
	defer resp.Body.Close()
	var retryAfter time.Duration
	if secs, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && secs > 0 {
		retryAfter = time.Duration(secs) * time.Second
	}
	var answer struct {
		Invalid []string `json:"invalid"`
	}
	if resp.StatusCode == http.StatusOK {
		json.NewDecoder(io.LimitReader(resp.Body, pushAnswerMax)).Decode(&answer) // a bad answer clears nothing
	}
	return resp.StatusCode, retryAfter, answer.Invalid, nil
}

// forget clears the invalid tokens that were in the batch; the gateway cannot
// clear a token the relay did not send it.
func (p *pusher) forget(batch, invalid []string) {
	sent := make(map[string]bool, len(batch))
	for _, t := range batch {
		sent[t] = true
	}
	var gone []string
	for _, t := range invalid {
		if sent[t] {
			gone = append(gone, t)
			delete(sent, t)
		}
	}
	if len(gone) > 0 {
		p.clear(gone)
	}
}

// clearPush forgets push tokens the gateway reported invalid, on every
// device that holds them, as PUT /push with null does.
func (s *Service) clearPush(tokens []string) {
	err := inTx(context.Background(), s.db, func(tx *sql.Tx) error {
		for _, t := range tokens {
			if _, err := tx.Exec(`UPDATE devices SET push = NULL WHERE push = ?`, t); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("push: %d invalid tokens not cleared: %v", len(tokens), err)
	}
}

// pushTokens are the push tokens to wake for a message from sender: the
// room's other devices of kind device, not revoked, never the sender's own.
func pushTokens(tx *sql.Tx, roomID, sender string) ([]string, error) {
	rows, err := tx.Query(`SELECT DISTINCT push FROM devices
		WHERE room = ? AND kind = 'device' AND revoked = 0 AND push IS NOT NULL AND id != ?
		AND push NOT IN (SELECT push FROM devices WHERE id = ? AND push IS NOT NULL)`, roomID, sender, sender)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}
