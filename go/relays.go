package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
)

const httpTimeout = 10 * time.Second

var httpClient = &http.Client{
	Timeout:   httpTimeout,
	Transport: &http.Transport{DisableKeepAlives: true},
}

// Relay is a relay the host application uses, with the project key that
// creates channels.
type Relay struct {
	// URL is the guests' URL of the relay.
	URL string
	// HostURL is the URL the host itself reaches the relay by, or empty to use
	// URL. It follows PROTOCOL.md section 2.3 rather than the guest policy.
	HostURL string
	// Key is the project key that creates channels.
	Key string
}

// hostURL is where the host creates, deletes and opens its own channels.
func (r Relay) hostURL() string {
	if r.HostURL != "" {
		return r.HostURL
	}
	return r.URL
}

// hostURLAllowed is PROTOCOL.md section 2.3 for the URL the host reaches a
// relay by for itself: wss anywhere, or ws only to loopback, a private literal
// address, or a plain name without dots (a container or compose service name).
func hostURLAllowed(raw string) bool {
	if utf8.RuneCountInString(raw) > 2048 {
		return false
	}
	parts, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if parts.Scheme != "wss" && parts.Scheme != "ws" {
		return false
	}
	if parts.Host == "" || parts.User != nil || parts.RawQuery != "" || parts.Fragment != "" {
		return false
	}
	host := parts.Hostname()
	if host == "" {
		return false
	}
	if port := parts.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return false
		}
	}
	if parts.Scheme == "wss" {
		return true
	}
	if strings.ContainsRune(host, '%') {
		return false
	}
	address := net.ParseIP(host)
	if address == nil {
		// A dotless name is a container or compose service name, not a LAN host.
		return !strings.ContainsRune(host, '.')
	}
	if ipv4 := address.To4(); ipv4 != nil {
		// An IPv4-mapped IPv6 address is not a literal IPv4 address.
		if strings.ContainsRune(host, ':') {
			return false
		}
		return ipv4[0] == 127 ||
			ipv4[0] == 10 ||
			(ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31) ||
			(ipv4[0] == 192 && ipv4[1] == 168)
	}
	if len(address) != net.IPv6len {
		return false
	}
	if address.Equal(net.IPv6loopback) {
		return true
	}
	return address[0]&0xfe == 0xfc
}

type credentials struct {
	channel    string
	hostToken  string
	guestToken string
}

// urlAllowed is PROTOCOL.md section 8.1: the relay URLs a guest and a host may
// exchange.
func urlAllowed(raw string) bool {
	if utf8.RuneCountInString(raw) > 2048 {
		return false
	}
	parts, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if parts.Scheme != "wss" && parts.Scheme != "ws" {
		return false
	}
	if parts.Host == "" || parts.User != nil || parts.RawQuery != "" || parts.Fragment != "" {
		return false
	}
	host := parts.Hostname()
	if host == "" {
		return false
	}
	if port := parts.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return false
		}
	}
	if parts.Scheme == "wss" {
		return true
	}
	if strings.ContainsRune(host, '%') {
		return false
	}
	address := net.ParseIP(host)
	if address == nil {
		return false
	}
	if ipv4 := address.To4(); ipv4 != nil {
		// An IPv4-mapped IPv6 address is not a literal IPv4 address.
		if strings.ContainsRune(host, ':') {
			return false
		}
		return ipv4[0] == 10 ||
			(ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31) ||
			(ipv4[0] == 192 && ipv4[1] == 168)
	}
	return len(address) == net.IPv6len && address[0]&0xfe == 0xfc
}

func wsURL(base, channel string) string {
	return strings.TrimSuffix(base, "/") + "/v1/ws/" + channel
}

func httpURL(base, path string) (string, error) {
	parts, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	switch parts.Scheme {
	case "ws":
		parts.Scheme = "http"
	case "wss":
		parts.Scheme = "https"
	}
	parts.Path = strings.TrimSuffix(parts.Path, "/") + path
	parts.RawPath = ""
	parts.RawQuery = ""
	parts.Fragment = ""
	return parts.String(), nil
}

// createChannel is POST /v1/channels with the relay's project key
// (PROTOCOL.md section 2.3).
func createChannel(ctx context.Context, relay Relay) (credentials, error) {
	endpoint, err := httpURL(relay.hostURL(), "/v1/channels")
	if err != nil {
		return credentials{}, err
	}
	status, body, err := relayRequest(ctx, http.MethodPost, endpoint, relay.Key, http.NoBody)
	if err != nil {
		return credentials{}, err
	}
	if status != http.StatusCreated {
		return credentials{}, fmt.Errorf("creating a channel failed with HTTP %d", status)
	}
	value, err := parseJSON(string(body))
	if err != nil {
		return credentials{}, errors.New("the relay answered invalid JSON")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return credentials{}, errors.New("the relay answered invalid JSON")
	}
	channel, okChannel := isB64URL(object["channel"], 22)
	hostToken, okHost := isB64URL(object["host_token"], 43)
	guestToken, okGuest := isB64URL(object["guest_token"], 43)
	if !okChannel || !okHost || !okGuest {
		return credentials{}, errors.New("the relay answered invalid credentials")
	}
	return credentials{channel: channel, hostToken: hostToken, guestToken: guestToken}, nil
}

// deleteChannel deletes a channel. False means the relay no longer had it.
func deleteChannel(ctx context.Context, base, channel, hostToken string) (bool, error) {
	endpoint, err := httpURL(base, "/v1/channels/"+channel)
	if err != nil {
		return false, err
	}
	status, _, err := relayRequest(ctx, http.MethodDelete, endpoint, hostToken, nil)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("deleting a channel failed with HTTP %d", status)
	}
}

func relayRequest(ctx context.Context, method, endpoint, bearer string, body io.Reader) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	response, err := httpClient.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("the relay answered nothing: %w", err)
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("the relay answered nothing: %w", err)
	}
	return response.StatusCode, answer, nil
}

// socket is one authenticated L0 socket, carrying L1 frames.
type socket struct {
	url   string
	token string
	mu    sync.Mutex
	conn  *websocket.Conn
}

func newSocket(base, channel, token string) *socket {
	return &socket{url: wsURL(base, channel), token: token}
}

// Open connects, sends auth and waits for ready.
func (s *socket) Open(ctx context.Context) error {
	conn, _, err := websocket.Dial(ctx, s.url, nil)
	if err != nil {
		return socketError(ctx, err)
	}
	// Lengths are checked by the protocol reader, so the relay's own 1 MiB
	// frame limit is the only bound this client needs.
	conn.SetReadLimit(-1)
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
	auth, err := json.Marshal(struct {
		Auth string `json:"auth"`
	}{Auth: s.token})
	if err != nil {
		return err
	}
	if err := conn.Write(ctx, websocket.MessageText, auth); err != nil {
		return socketError(ctx, err)
	}
	for {
		messageType, data, err := conn.Read(ctx)
		if err != nil {
			return socketError(ctx, err)
		}
		if messageType != websocket.MessageBinary || len(data) == 0 || data[0] != 0x00 {
			return violation("the relay sent a frame before ready")
		}
		if systemEvent(data) == "ready" {
			return nil
		}
	}
}

// Recv returns the next L1 frame, skipping presence events.
func (s *socket) Recv(ctx context.Context) ([]byte, error) {
	for {
		messageType, data, err := s.read(ctx)
		if err != nil {
			return nil, err
		}
		if messageType != websocket.MessageBinary {
			return nil, violation("the relay sent a text frame")
		}
		if len(data) == 0 {
			return nil, violation("the relay sent an unknown frame")
		}
		switch data[0] {
		case 0x00:
			continue
		case 0x01:
			return bytes.Clone(data[1:]), nil
		default:
			return nil, violation("the relay sent an unknown frame")
		}
	}
}

func (s *socket) read(ctx context.Context) (websocket.MessageType, []byte, error) {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return 0, nil, &socketClosedError{code: 1006}
	}
	messageType, data, err := conn.Read(ctx)
	if err != nil {
		return 0, nil, socketError(ctx, err)
	}
	return messageType, data, nil
}

// SendAll writes complete L1 frames under one lock, so two senders cannot
// interleave the fragments or nonces of one session.
func (s *socket) SendAll(ctx context.Context, frames [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return &socketClosedError{code: 1006}
	}
	for _, item := range frames {
		data := make([]byte, 1+len(item))
		data[0] = 0x01
		copy(data[1:], item)
		if err := s.conn.Write(ctx, websocket.MessageBinary, data); err != nil {
			return socketError(ctx, err)
		}
	}
	return nil
}

// Close drops the socket immediately; the relay is not waited for.
func (s *socket) Close() {
	s.mu.Lock()
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()
	if conn != nil {
		_ = conn.CloseNow()
	}
}

func socketError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if status := websocket.CloseStatus(err); status >= 0 {
		return &socketClosedError{code: int(status)}
	}
	return &socketClosedError{code: 1006}
}

func systemEvent(frame []byte) string {
	var value struct {
		Event string `json:"event"`
	}
	if json.Unmarshal(frame[1:], &value) != nil {
		return ""
	}
	return value.Event
}

type backoff struct {
	delay time.Duration
}

func newBackoff() *backoff {
	return &backoff{delay: time.Second}
}

func (b *backoff) next() time.Duration {
	delay := b.delay
	b.delay = min(2*b.delay, 60*time.Second)
	return delay
}

func (b *backoff) reset() {
	b.delay = time.Second
}

// secondsUntilUTCMidnight is how long a relay over its daily byte quota stays
// unusable.
func secondsUntilUTCMidnight() time.Duration {
	now := time.Now().UTC()
	tomorrow := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	return tomorrow.Sub(now)
}
