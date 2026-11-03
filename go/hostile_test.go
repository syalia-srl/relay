package relay_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	relay "github.com/syalia-srl/relay/go"
)

type fault struct {
	action string
	delay  time.Duration
}

type hostileProxy struct {
	address    string
	target     string
	httpTarget string
	listener   net.Listener
	server     *http.Server
	url        string

	mu           sync.Mutex
	faults       map[string][]fault
	held         map[string][]byte
	upstream     map[*websocket.Conn]*websocket.Conn
	httpRequests int
	websockets   int
}

func newHostileProxy(t *testing.T, address, target, httpTarget string) *hostileProxy {
	t.Helper()
	listener, err := net.Listen("tcp", address+":0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &hostileProxy{
		address:    address,
		target:     target,
		httpTarget: httpTarget,
		listener:   listener,
		url:        "ws://" + listener.Addr().String(),
		faults:     map[string][]fault{"up": {}, "down": {}},
		held:       map[string][]byte{"up": nil, "down": nil},
		upstream:   make(map[*websocket.Conn]*websocket.Conn),
	}
	proxy.server = &http.Server{Handler: http.HandlerFunc(proxy.handle)}
	go proxy.server.Serve(listener)
	t.Cleanup(proxy.stop)
	return proxy
}

func (p *hostileProxy) arm(direction, action string, delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.faults[direction] = append(p.faults[direction], fault{action: action, delay: delay})
}

func (p *hostileProxy) stop() {
	_ = p.server.Close()
	p.mu.Lock()
	connections := make([]*websocket.Conn, 0, len(p.upstream))
	for client, upstream := range p.upstream {
		connections = append(connections, client, upstream)
	}
	p.mu.Unlock()
	for _, connection := range connections {
		connection.CloseNow()
	}
}

func (p *hostileProxy) counts() (httpRequests, websockets int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.httpRequests, p.websockets
}

func (p *hostileProxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "" {
		client, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		p.mu.Lock()
		p.websockets++
		p.mu.Unlock()
		client.SetReadLimit(-1)
		upstream, _, err := websocket.Dial(r.Context(), p.target+r.URL.RequestURI(), nil)
		if err != nil {
			client.CloseNow()
			return
		}
		upstream.SetReadLimit(-1)
		p.mu.Lock()
		p.upstream[client] = upstream
		p.mu.Unlock()
		var pipes sync.WaitGroup
		pipes.Add(2)
		go func() {
			defer pipes.Done()
			p.pipe(client, upstream, "up")
		}()
		go func() {
			defer pipes.Done()
			p.pipe(upstream, client, "down")
		}()
		pipes.Wait()
		p.mu.Lock()
		delete(p.upstream, client)
		p.mu.Unlock()
		client.CloseNow()
		upstream.CloseNow()
		return
	}
	p.mu.Lock()
	p.httpRequests++
	p.mu.Unlock()
	request, err := http.NewRequestWithContext(r.Context(), r.Method, p.httpTarget+r.URL.RequestURI(), r.Body)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	request.Header = r.Header.Clone()
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer response.Body.Close()
	for name, values := range response.Header {
		w.Header()[name] = values
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func (p *hostileProxy) pipe(source, destination *websocket.Conn, direction string) {
	ctx := context.Background()
	for {
		messageType, data, err := source.Read(ctx)
		if err != nil {
			return
		}
		if messageType != websocket.MessageBinary || len(data) == 0 || data[0] != 0x01 {
			if destination.Write(ctx, messageType, data) != nil {
				return
			}
			continue
		}
		p.mu.Lock()
		held := p.held[direction]
		if held != nil {
			p.held[direction] = nil
			p.mu.Unlock()
			if destination.Write(ctx, websocket.MessageBinary, data) != nil {
				return
			}
			if destination.Write(ctx, websocket.MessageBinary, held) != nil {
				return
			}
			continue
		}
		var armed *fault
		if len(p.faults[direction]) > 0 {
			value := p.faults[direction][0]
			p.faults[direction] = p.faults[direction][1:]
			armed = &value
		}
		p.mu.Unlock()
		if armed == nil {
			if destination.Write(ctx, websocket.MessageBinary, data) != nil {
				return
			}
			continue
		}
		switch armed.action {
		case "drop":
		case "duplicate":
			if destination.Write(ctx, websocket.MessageBinary, data) != nil {
				return
			}
			if destination.Write(ctx, websocket.MessageBinary, data) != nil {
				return
			}
		case "reorder":
			p.mu.Lock()
			p.held[direction] = data
			p.mu.Unlock()
		case "delay":
			time.Sleep(armed.delay)
			if destination.Write(ctx, websocket.MessageBinary, data) != nil {
				return
			}
		case "relabel":
			if destination.Write(ctx, websocket.MessageBinary, []byte{0x01, 0x05}) != nil {
				return
			}
		case "flip":
			copyOfData := append([]byte(nil), data...)
			copyOfData[3] ^= 0x01
			if destination.Write(ctx, websocket.MessageBinary, copyOfData) != nil {
				return
			}
		case "oversize":
			// A system frame larger than any L1 frame. Before the read limit the
			// client skips it and stays connected, so the test sees no reconnect.
			oversized := make([]byte, 70_000)
			oversized[0] = 0x00
			if destination.Write(ctx, websocket.MessageBinary, oversized) != nil {
				return
			}
		default:
			if destination.Write(ctx, websocket.MessageBinary, data) != nil {
				return
			}
		}
	}
}

func TestHostileRelay(t *testing.T) {
	for _, action := range []string{"drop", "duplicate", "reorder", "delay", "relabel", "flip", "oversize"} {
		t.Run(action, func(t *testing.T) {
			directory := t.TempDir()
			process := startRelay(t, filepath.Join(directory, "relay"))
			proxy := newHostileProxy(t, process.address, process.url, process.http)
			ctx, cancel := timeoutContext(t, 60*time.Second)
			defer cancel()
			host, err := relay.OpenHost(ctx, relay.FileStore(filepath.Join(directory, "host")), []relay.Relay{
				{URL: proxy.url, Key: operatorKey},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			pairing, err := host.Pair(ctx, "pixel-7")
			if err != nil {
				t.Fatal(err)
			}
			guest, err := relay.OpenGuest(ctx, relay.FileStore(filepath.Join(directory, "guest")), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer guest.Close()
			link, err := guest.Pair(ctx, pairing.Payload())
			if err != nil {
				t.Fatal(err)
			}
			device, err := pairing.Confirm(ctx, link.Code())
			if err != nil {
				t.Fatal(err)
			}
			if err := link.Bound(ctx); err != nil {
				t.Fatal(err)
			}
			received := newHostInbox(host)
			replies := newGuestInbox(link)
			if err := link.Send(ctx, []byte("sync")); err != nil {
				t.Fatal(err)
			}
			waitFor(t, func() bool { return received.has([]byte("sync")) })
			if err := device.Send(ctx, []byte("sync")); err != nil {
				t.Fatal(err)
			}
			waitFor(t, func() bool { return replies.has([]byte("sync")) })

			if action == "oversize" {
				// Only the host's socket gets the oversized frame: the guest sends
				// next, so the damaged down frame is the one the host reads.
				_, sockets := proxy.counts()
				proxy.arm("down", action, 300*time.Millisecond)
				_ = link.Send(ctx, []byte("one"))
				waitFor(t, func() bool {
					_, now := proxy.counts()
					return now > sockets
				})
			} else {
				proxy.arm("up", action, 300*time.Millisecond)
				proxy.arm("down", action, 300*time.Millisecond)
				_ = link.Send(ctx, []byte("one"))
				_ = device.Send(ctx, []byte("two"))
			}
			sendUntil(t, func(message []byte) error { return link.Send(ctx, message) }, []byte("after"),
				func() bool { return received.has([]byte("after")) })
			sendUntil(t, func(message []byte) error { return device.Send(ctx, message) }, []byte("after"),
				func() bool { return replies.has([]byte("after")) })

			sent := [][]byte{[]byte("sync"), []byte("one"), []byte("two"), []byte("after")}
			known := func(message []byte) bool {
				for _, candidate := range sent {
					if string(candidate) == string(message) {
						return true
					}
				}
				return false
			}
			for _, item := range received.snapshot() {
				if !known(item.message) {
					t.Fatalf("a changed message reached the host: %q", item.message)
				}
			}
			for _, message := range replies.snapshot() {
				if !known(message) {
					t.Fatalf("a changed message reached the guest: %q", message)
				}
			}
			if !received.has([]byte("after")) || !replies.has([]byte("after")) {
				t.Fatal("the messages after the fault did not arrive both ways")
			}
			if err := guest.Close(); err != nil && !errors.Is(err, relay.ErrClosed) {
				t.Fatal(err)
			}
		})
	}
}
