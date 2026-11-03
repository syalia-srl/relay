package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	connectTimeout     = 1500 * time.Millisecond
	upgradeInterval    = 60 * time.Second
	goneRounds         = 3
	unpairTimeout      = 10 * time.Second
	guestInboxCapacity = 64
)

var (
	errReconnect = errors.New("reconnect to the relays")
	errDone      = errors.New("the link reached a final state")
	errAttempt   = errors.New("the socket attempt failed")
)

// PairedHost is a host this guest paired with. Recv returns ErrRevoked when the
// host revokes it.
type PairedHost struct {
	guest      *Guest
	ctx        context.Context
	cancel     context.CancelFunc
	dev        string
	hostPublic []byte
	static     StaticKey
	private    []byte
	expires    int64

	mu          sync.Mutex
	relays      []relayEntry
	psk         []byte
	state       string
	err         error
	code        string
	pendingCode string
	ready       bool
	session     *session
	socket      *socket
	connecting  *socket
	unpairing   bool
	paused      map[string]time.Time
	inbox       chan []byte
	changed     chan struct{}
	done        chan struct{}
	doneOnce    sync.Once
	expiryStop  context.CancelFunc

	stopOnce sync.Once
	wg       sync.WaitGroup
}

func newPairedHost(guest *Guest, dev string, hostPublic []byte, relays []relayEntry, static StaticKey, private []byte, expires int64, state string) *PairedHost {
	ctx, cancel := context.WithCancel(guest.ctx)
	return &PairedHost{
		guest:      guest,
		ctx:        ctx,
		cancel:     cancel,
		dev:        dev,
		hostPublic: bytes.Clone(hostPublic),
		relays:     append([]relayEntry(nil), relays...),
		static:     static,
		private:    bytes.Clone(private),
		expires:    expires,
		state:      state,
		paused:     make(map[string]time.Time),
		inbox:      make(chan []byte, guestInboxCapacity),
		changed:    make(chan struct{}),
		done:       make(chan struct{}),
	}
}

// Code is the six digits the person types into the host, once the host has the
// key.
func (p *PairedHost) Code() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.code
}

// Bound returns once the device channels carry a session.
func (p *PairedHost) Bound(ctx context.Context) error {
	err := p.wait(ctx, func() bool {
		return (p.ready && p.state == "bound") || p.terminalLocked()
	})
	if err != nil {
		return err
	}
	p.mu.Lock()
	terminal := p.terminalLocked()
	state := p.state
	p.mu.Unlock()
	if terminal {
		return p.terminalError()
	}
	if state == "closed" {
		return ErrClosed
	}
	return nil
}

// Send sends one message to the host, waiting until the device channels carry a
// session.
func (p *PairedHost) Send(ctx context.Context, message []byte) error {
	for {
		if err := p.wait(ctx, func() bool {
			return (p.ready && p.state == "bound") || p.terminalLocked()
		}); err != nil {
			return err
		}
		p.mu.Lock()
		terminal := p.terminalLocked()
		state := p.state
		session := p.session
		socket := p.socket
		p.mu.Unlock()
		if terminal {
			return p.terminalError()
		}
		if state == "closed" {
			return ErrClosed
		}
		if session == nil || socket == nil {
			continue
		}
		err := session.Send(ctx, socket, kindApplication, message)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, closed := closedStatus(err); !closed {
			return err
		}
		p.mu.Lock()
		p.ready = false
		p.mu.Unlock()
		p.notify()
	}
}

// Recv waits for one message from the host.
func (p *PairedHost) Recv(ctx context.Context) ([]byte, error) {
	for {
		p.mu.Lock()
		if len(p.inbox) > 0 {
			message := <-p.inbox
			p.mu.Unlock()
			return message, nil
		}
		if p.terminalLocked() {
			err := p.terminalErrorLocked()
			p.mu.Unlock()
			return nil, err
		}
		changed := p.changed
		p.mu.Unlock()
		select {
		case message := <-p.inbox:
			return message, nil
		case <-changed:
		case <-p.guest.ctx.Done():
			return nil, ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Unpair sends close and waits for closed, then forgets this host.
func (p *PairedHost) Unpair(ctx context.Context) error {
	p.mu.Lock()
	if p.state == "pairing" {
		// No key is pending at the host yet, so there is nothing to close.
		p.state = "closed"
		if p.expiryStop != nil {
			p.expiryStop()
			p.expiryStop = nil
		}
		p.mu.Unlock()
		p.stop()
		p.notify()
		p.wg.Wait()
		p.guest.forget(p)
		return nil
	}
	paired := p.state == "pending" || p.state == "bound"
	terminal := p.terminalLocked()
	p.unpairing = !terminal
	session := p.session
	socket := p.socket
	ready := p.ready
	p.mu.Unlock()
	if terminal {
		p.stop()
		p.wg.Wait()
		p.guest.forget(p)
		return nil
	}
	if paired && session != nil && socket != nil && ready {
		_ = session.Send(p.ctx, socket, kindControl, encodeControl("close", nil))
	}
	timer := time.NewTimer(unpairTimeout)
	defer timer.Stop()
wait:
	for {
		p.mu.Lock()
		done := p.terminalLocked()
		changed := p.changed
		p.mu.Unlock()
		if done {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			// PROTOCOL.md §9.1 keeps the key until closed; a guest whose host is
			// unreachable still has to be able to unpair, so it forgets locally.
			p.mu.Lock()
			if !p.terminalLocked() {
				p.state = "closed"
			}
			p.mu.Unlock()
			p.notify()
			break wait
		}
	}
	p.stop()
	p.wg.Wait()
	p.guest.forget(p)
	return nil
}

func (p *PairedHost) terminalLocked() bool {
	return p.state == "closed" || p.state == "revoked" || p.state == "failed"
}

func (p *PairedHost) terminalErrorLocked() error {
	switch p.state {
	case "revoked":
		return ErrRevoked
	case "failed":
		if p.err != nil {
			return p.err
		}
		return fmt.Errorf("%w: the pairing failed", ErrPairingFailed)
	case "closed":
		return ErrClosed
	default:
		return nil
	}
}

func (p *PairedHost) terminalError() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.terminalErrorLocked()
}

func (p *PairedHost) notify() {
	p.mu.Lock()
	if p.terminalLocked() {
		p.doneOnce.Do(func() { close(p.done) })
	}
	changed := p.changed
	p.changed = make(chan struct{})
	p.mu.Unlock()
	close(changed)
}

// wait runs predicate with p.mu held and waits for a state change.
func (p *PairedHost) wait(ctx context.Context, predicate func() bool) error {
	for {
		p.mu.Lock()
		if predicate() {
			p.mu.Unlock()
			return nil
		}
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-changed:
		case <-p.guest.ctx.Done():
			return ErrClosed
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *PairedHost) deliver(message []byte) {
	p.mu.Lock()
	if p.terminalLocked() {
		p.mu.Unlock()
		return
	}
	inbox := p.inbox
	done := p.done
	p.mu.Unlock()
	select {
	case inbox <- bytes.Clone(message):
	case <-done:
	case <-p.ctx.Done():
	}
}

func (p *PairedHost) start() {
	p.wg.Add(1)
	go p.run()
	if p.expires != 0 {
		ctx, cancel := context.WithCancel(p.ctx)
		p.mu.Lock()
		p.expiryStop = cancel
		p.mu.Unlock()
		p.wg.Add(1)
		go p.expire(ctx)
	}
}

func (p *PairedHost) stop() {
	p.stopOnce.Do(func() {
		p.cancel()
		p.mu.Lock()
		sockets := []*socket{p.socket, p.connecting}
		p.socket = nil
		p.session = nil
		p.connecting = nil
		p.mu.Unlock()
		for _, socket := range sockets {
			if socket != nil {
				socket.Close()
			}
		}
	})
}

func (p *PairedHost) expire(ctx context.Context) {
	defer p.wg.Done()
	timer := time.NewTimer(time.Until(time.Unix(p.expires+60, 0)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return
	}
	p.fail(fmt.Errorf("%w: the pairing payload expired", ErrPairingFailed))
}

func (p *PairedHost) fail(err error) {
	p.mu.Lock()
	if p.terminalLocked() {
		p.mu.Unlock()
		return
	}
	p.state = "failed"
	p.err = err
	if p.expiryStop != nil {
		p.expiryStop()
		p.expiryStop = nil
	}
	p.mu.Unlock()
	p.guest.forget(p)
	p.notify()
	p.cancel()
}

func (p *PairedHost) gone() {
	p.mu.Lock()
	bound := p.state == "bound"
	p.mu.Unlock()
	if !bound {
		p.fail(fmt.Errorf("%w: every relay lost the channel", ErrPairingFailed))
		return
	}
	p.mu.Lock()
	if !p.terminalLocked() {
		p.state = "revoked"
	}
	if p.expiryStop != nil {
		p.expiryStop()
		p.expiryStop = nil
	}
	p.mu.Unlock()
	p.guest.forget(p)
	p.notify()
	p.cancel()
}

func (p *PairedHost) run() {
	defer p.wg.Done()
	retry := newBackoff()
	gone := 0
	for !p.terminal() && p.ctx.Err() == nil {
		established := false
		allGone := true
		p.mu.Lock()
		relays := append([]relayEntry(nil), p.relays...)
		p.mu.Unlock()
		for position := 0; position < len(relays); position++ {
			if p.terminal() || p.ctx.Err() != nil {
				return
			}
			entry := relays[position]
			if p.pausedUntil(entry.URL).After(time.Now()) {
				allGone = false
				continue
			}
			ok, err := p.tryRelay(entry, position, retry)
			if !ok {
				if isChannelGone(err) {
					continue
				}
				if code, closed := closedStatus(err); closed && code == 4429 {
					p.pause(entry.URL)
				}
				allGone = false
				continue
			}
			established = true
			if errors.Is(err, errDone) {
				return
			}
			break
		}
		if p.terminal() || p.ctx.Err() != nil {
			return
		}
		if established {
			gone = 0
			continue
		}
		if allGone && len(relays) > 0 {
			gone++
			if gone >= goneRounds {
				p.gone()
				return
			}
		} else {
			gone = 0
		}
		if !sleepContext(p.ctx, retry.next()) {
			return
		}
	}
}

func (p *PairedHost) tryRelay(entry relayEntry, position int, retry *backoff) (established bool, err error) {
	var socket *socket
	defer func() {
		if value := recover(); value != nil {
			logPanic(value)
			err = errAttempt
		}
		if socket != nil {
			p.clearSocket(socket)
			socket.Close()
		}
	}()
	socket, session, err := p.connect(entry)
	if err != nil {
		socket = nil
		return false, err
	}
	established = true
	retry.reset()
	err = p.serve(socket, session, position)
	return established, err
}

func (p *PairedHost) connect(entry relayEntry) (socket *socket, session *session, err error) {
	socket = newSocket(entry.URL, entry.Channel, entry.Token)
	ok := false
	p.mu.Lock()
	p.connecting = socket
	p.mu.Unlock()
	defer func() {
		if value := recover(); value != nil {
			logPanic(value)
			err = errAttempt
			ok = false
		}
		p.mu.Lock()
		if p.connecting == socket {
			p.connecting = nil
		}
		p.mu.Unlock()
		if !ok && socket != nil {
			socket.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(p.ctx, connectTimeout)
	defer cancel()
	if err := socket.Open(ctx); err != nil {
		return nil, nil, err
	}
	p.mu.Lock()
	state := p.state
	hostPublic := bytes.Clone(p.hostPublic)
	psk := bytes.Clone(p.psk)
	dev := p.dev
	p.mu.Unlock()
	pattern := "IKpsk1"
	frameType := byte(framePair)
	if state == "pending" || state == "bound" {
		pattern = "KK"
		frameType = frameConnect
		psk = nil
	}
	handshake, err := newHandshake(pattern, true, prologue(dev, entry.Channel), p.static, hostPublic, psk, nil)
	if err != nil {
		return nil, nil, err
	}
	message, err := handshake.writeMessage(nil)
	if err != nil {
		return nil, nil, err
	}
	if err := socket.SendAll(ctx, [][]byte{frame(frameType, message)}); err != nil {
		return nil, nil, err
	}
	answer, err := socket.Recv(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(answer) != 49 || answer[0] != frameAccept {
		return nil, nil, violation("expected an accept frame")
	}
	if _, err := handshake.readMessage(answer[1:]); err != nil {
		return nil, nil, err
	}
	if state == "pairing" {
		p.mu.Lock()
		if p.state == "pairing" {
			p.pendingCode = pairingCode(handshake.handshakeHash())
		}
		p.mu.Unlock()
	}
	session, err = newInitiatorSession(handshake)
	if err != nil {
		return nil, nil, err
	}
	// PROTOCOL.md §6.1: the guest's first transport frame is a ping.
	if err := session.Send(p.ctx, socket, kindControl, encodeControl("ping", nil)); err != nil {
		return nil, nil, err
	}
	ok = true
	return socket, session, nil
}

func (p *PairedHost) serve(socket *socket, session *session, position int) error {
	current := socket
	defer func() {
		p.clearSocket(current)
		current.Close()
	}()
	p.mu.Lock()
	p.socket = socket
	p.session = session
	p.ready = false
	p.mu.Unlock()
	p.notify()
	deadline := time.Now().Add(upgradeInterval)
	for !p.terminal() && p.ctx.Err() == nil {
		var incoming []byte
		if position > 0 {
			wait := time.Until(deadline)
			if wait < 100*time.Millisecond {
				wait = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(p.ctx, wait)
			data, err := socket.Recv(ctx)
			cancel()
			if errors.Is(err, context.DeadlineExceeded) && p.ctx.Err() == nil {
				deadline = time.Now().Add(upgradeInterval)
				movedSocket, movedSession, movedPosition := p.earlier(position)
				if movedSocket == nil {
					continue
				}
				p.mu.Lock()
				p.ready = false
				p.socket = movedSocket
				p.session = movedSession
				p.mu.Unlock()
				previous := current
				socket, session, position = movedSocket, movedSession, movedPosition
				current = movedSocket
				previous.Close()
				continue
			}
			if err != nil {
				return err
			}
			incoming = data
		} else {
			data, err := socket.Recv(p.ctx)
			if err != nil {
				return err
			}
			incoming = data
		}
		if err := p.receive(socket, session, incoming); err != nil {
			return err
		}
	}
	return nil
}

func (p *PairedHost) earlier(position int) (*socket, *session, int) {
	p.mu.Lock()
	relays := append([]relayEntry(nil), p.relays...)
	p.mu.Unlock()
	for earlier := 0; earlier < position; earlier++ {
		entry := relays[earlier]
		if p.pausedUntil(entry.URL).After(time.Now()) {
			continue
		}
		socket, session, err := p.connect(entry)
		if err != nil {
			continue
		}
		return socket, session, earlier
	}
	return nil, nil, 0
}

func (p *PairedHost) receive(socket *socket, session *session, incoming []byte) error {
	if len(incoming) == 0 {
		return errReconnect
	}
	body := incoming[1:]
	if incoming[0] == frameAbort {
		if len(body) == 0 {
			return errReconnect
		}
		p.abort(socket)
		return errReconnect
	}
	if incoming[0] != frameTransport {
		p.abort(socket)
		return errReconnect
	}
	kind, message, more, err := session.Decrypt(body)
	if err != nil {
		p.abort(socket)
		return errReconnect
	}
	if !more {
		return p.process(socket, session, kind, message)
	}
	return nil
}

func (p *PairedHost) process(socket *socket, session *session, kind byte, message []byte) error {
	if kind == kindApplication {
		p.mu.Lock()
		bound := p.state == "bound"
		p.mu.Unlock()
		// PROTOCOL.md §5.4: a pending guest has no access of any kind.
		if !bound {
			p.abort(socket)
			return errReconnect
		}
		p.deliver(message)
		return nil
	}
	control, err := parseControl(string(message), "guest")
	if err != nil {
		p.abort(socket)
		return errReconnect
	}
	if control == nil {
		return nil
	}
	switch control.op {
	case "ping":
		if err := session.Send(p.ctx, socket, kindControl, encodeControl("pong", nil)); err != nil {
			return err
		}
	case "pong":
		p.onPong(socket, session)
	case "relays":
		p.mu.Lock()
		p.relays = append([]relayEntry(nil), control.relays...)
		p.state = "bound"
		for i := range p.psk {
			p.psk[i] = 0
		}
		p.psk = nil
		p.ready = false
		p.mu.Unlock()
		p.guest.persist(p)
		p.notify()
		// PROTOCOL.md §8.3: replace the list and start over at step 1.
		return errReconnect
	case "closed":
		p.finish("closed", nil)
		p.guest.forget(p)
		return errDone
	case "revoked":
		p.finish("revoked", nil)
		p.guest.forget(p)
		return errDone
	}
	return nil
}

func (p *PairedHost) finish(state string, err error) {
	p.mu.Lock()
	if p.terminalLocked() {
		p.mu.Unlock()
		return
	}
	p.state = state
	p.err = err
	if p.expiryStop != nil {
		p.expiryStop()
		p.expiryStop = nil
	}
	p.mu.Unlock()
	p.notify()
	p.cancel()
}

func (p *PairedHost) onPong(socket *socket, session *session) {
	p.mu.Lock()
	p.ready = true
	if p.state == "pairing" {
		// The host sends pong only after promoting the key (PROTOCOL.md §5.3).
		p.code = p.pendingCode
		p.pendingCode = ""
		p.state = "pending"
		if p.expiryStop != nil {
			p.expiryStop()
			p.expiryStop = nil
		}
	}
	unpairing := p.unpairing
	p.mu.Unlock()
	if unpairing {
		_ = session.Send(p.ctx, socket, kindControl, encodeControl("close", nil))
	}
	p.notify()
}

func (p *PairedHost) abort(socket *socket) {
	_ = socket.SendAll(p.ctx, [][]byte{frame(frameAbort, nil)})
}

func (p *PairedHost) clearSocket(socket *socket) {
	p.mu.Lock()
	if p.socket == socket {
		p.socket = nil
		p.session = nil
		p.ready = false
	}
	p.mu.Unlock()
	p.notify()
}

func (p *PairedHost) terminal() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.terminalLocked()
}

func (p *PairedHost) pausedUntil(url string) time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.paused[url]
}

func (p *PairedHost) pause(url string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paused[url] = time.Now().Add(secondsUntilUTCMidnight())
}

// Guest is the side that pairs with a host, then carries messages to it.
type Guest struct {
	ctx    context.Context
	cancel context.CancelFunc
	store  Store
	saveMu sync.Mutex
	key    StaticKey

	mu     sync.Mutex
	closed bool
	hosts  map[string]*PairedHost
	all    []*PairedHost

	closeOnce sync.Once
}

type storedHost struct {
	Dev    string       `json:"dev"`
	Host   string       `json:"host"`
	Relays []relayEntry `json:"relays"`
	Static string       `json:"static,omitempty"`
}

type storedGuestState struct {
	V     int          `json:"v"`
	Hosts []storedHost `json:"hosts"`
}

// OpenGuest opens the guest whose state the store holds. key is nil to draw and
// keep one key per pairing, or a StaticKey to keep the private half elsewhere.
func OpenGuest(ctx context.Context, store Store, key StaticKey) (*Guest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	guestCtx, cancel := context.WithCancel(context.Background())
	guest := &Guest{
		ctx:    guestCtx,
		cancel: cancel,
		store:  store,
		key:    key,
		hosts:  make(map[string]*PairedHost),
	}
	state, firstRun, err := loadState(store)
	if err != nil {
		cancel()
		return nil, err
	}
	if firstRun {
		return guest, nil
	}
	if err := guest.loadHosts(state); err != nil {
		cancel()
		return nil, err
	}
	guest.mu.Lock()
	hosts := make([]*PairedHost, 0, len(guest.hosts))
	for _, link := range guest.hosts {
		hosts = append(hosts, link)
	}
	guest.mu.Unlock()
	for _, link := range hosts {
		if !guest.startLink(link) {
			break
		}
	}
	return guest, nil
}

func (g *Guest) loadHosts(state map[string]any) error {
	rawHosts, ok := state["hosts"].([]any)
	if !ok {
		return errors.New("the state file has no host list")
	}
	for _, raw := range rawHosts {
		item, ok := raw.(map[string]any)
		if !ok {
			return errors.New("the state file is damaged")
		}
		dev, okDev := item["dev"].(string)
		hostHex, okHost := isHex64(item["host"])
		rawRelays, okRelays := item["relays"].([]any)
		if !okDev || !okHost || !okRelays {
			return errors.New("the state file is damaged")
		}
		relays := make([]relayEntry, 0, len(rawRelays))
		for _, rawRelay := range rawRelays {
			entry, ok := relayEntryFromJSON(rawRelay)
			if !ok || !urlAllowed(entry.URL) {
				return errors.New("the state file has a bad relay entry")
			}
			relays = append(relays, entry)
		}
		privateHex := ""
		if rawPrivate, present := item["static"]; present && rawPrivate != nil {
			text, ok := isHex64(rawPrivate)
			if !ok {
				return errors.New("the state file is damaged")
			}
			privateHex = text
		}
		var static StaticKey
		var private []byte
		if g.key != nil {
			if privateHex != "" {
				return errors.New("this state already holds a guest key")
			}
			static = g.key
		} else {
			if privateHex == "" {
				return errors.New("this state was paired with a native key; pass it to open")
			}
			private, _ = hex.DecodeString(privateHex)
			memory, err := memoryKeyFromPrivate(private)
			if err != nil {
				return errors.New("the state file is damaged")
			}
			static = memory
		}
		hostPublic, _ := hex.DecodeString(hostHex)
		link := newPairedHost(g, dev, hostPublic, relays, static, private, 0, "bound")
		g.hosts[dev] = link
	}
	return nil
}

// Hosts lists the paired hosts, each the same object Pair returned.
func (g *Guest) Hosts() []*PairedHost {
	g.mu.Lock()
	defer g.mu.Unlock()
	hosts := make([]*PairedHost, 0, len(g.hosts))
	for _, link := range g.hosts {
		hosts = append(hosts, link)
	}
	return hosts
}

// Pair makes first contact with a host, from the payload it showed.
func (g *Guest) Pair(ctx context.Context, text string) (*PairedHost, error) {
	parsed, err := parsePayload(text, unixNow())
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, ErrClosed
	}
	if g.key != nil && len(g.hosts) > 0 {
		// PROTOCOL.md §3: one gs serves one pairing, and a native key cannot mint
		// another, so a second pairing needs its own Guest.
		g.mu.Unlock()
		return nil, errors.New("this guest key is already paired; a fresh key pairs again")
	}
	g.mu.Unlock()

	var static StaticKey
	var private []byte
	if g.key != nil {
		static = g.key
	} else {
		memory, err := generateMemoryKey()
		if err != nil {
			return nil, err
		}
		static = memory
		private = memory.privateBytes()
	}
	link := newPairedHost(g, parsed.dev, parsed.hostPublic, parsed.relays, static, private, parsed.expires, "pairing")
	link.psk = bytes.Clone(parsed.psk)
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		link.stop()
		return nil, ErrClosed
	}
	if g.key != nil && len(g.hosts) > 0 {
		g.mu.Unlock()
		link.stop()
		return nil, errors.New("this guest key is already paired; a fresh key pairs again")
	}
	g.hosts[link.dev] = link
	g.mu.Unlock()
	if !g.startLink(link) {
		link.stop()
		link.wg.Wait()
		g.forget(link)
		return nil, ErrClosed
	}
	if err := link.wait(ctx, func() bool {
		return link.code != "" || link.terminalLocked()
	}); err != nil {
		link.stop()
		link.wg.Wait()
		g.forget(link)
		return nil, err
	}
	if link.terminal() {
		err := link.terminalError()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: the pairing ended before the host showed a code", ErrPairingFailed)
	}
	return link, nil
}

// Close stops every connection. Paired hosts stay in the store.
func (g *Guest) Close() error {
	g.closeOnce.Do(func() {
		g.mu.Lock()
		g.closed = true
		links := append([]*PairedHost(nil), g.all...)
		g.mu.Unlock()
		g.cancel()
		for _, link := range links {
			link.stop()
		}
		for _, link := range links {
			link.wg.Wait()
		}
	})
	return nil
}

func (g *Guest) startLink(link *PairedHost) bool {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return false
	}
	link.start()
	g.all = append(g.all, link)
	g.mu.Unlock()
	return true
}

func (g *Guest) forget(link *PairedHost) {
	g.mu.Lock()
	removed := false
	if g.hosts[link.dev] == link {
		delete(g.hosts, link.dev)
		removed = true
	}
	g.mu.Unlock()
	if removed {
		_ = g.save()
	}
}

func (g *Guest) persist(link *PairedHost) {
	g.mu.Lock()
	current := g.hosts[link.dev] == link
	g.mu.Unlock()
	if current {
		_ = g.save()
	}
}

func (g *Guest) save() error {
	g.saveMu.Lock()
	defer g.saveMu.Unlock()
	g.mu.Lock()
	state := storedGuestState{
		V:     stateVersion,
		Hosts: make([]storedHost, 0, len(g.hosts)),
	}
	for _, link := range g.hosts {
		link.mu.Lock()
		// A pairing that a restart interrupts starts over from a new payload.
		if link.state == "bound" {
			stored := storedHost{
				Dev:    link.dev,
				Host:   hex.EncodeToString(link.hostPublic),
				Relays: append([]relayEntry(nil), link.relays...),
			}
			if link.private != nil {
				stored.Static = hex.EncodeToString(link.private)
			}
			state.Hosts = append(state.Hosts, stored)
		}
		link.mu.Unlock()
	}
	g.mu.Unlock()
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return g.store.Save(data)
}

func sleepContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
