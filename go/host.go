package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	pairingLifetime      = 300 * time.Second
	confirmationLifetime = 600 * time.Second
	maxPending           = 4
	maxUnmatchedCodes    = 3
	socketTimeout        = 10 * time.Second
	inboxCapacity        = 64
)

type inboxItem struct {
	device  *Device
	message []byte
}

type candidate struct {
	guest   []byte
	session *session
	code    string
}

type channel struct {
	id         string
	url        string
	hostURL    string
	hostToken  string
	guestToken string
	dev        string
	pairing    bool
	device     *Device
	stopCh     chan struct{}
	stopOnce   sync.Once

	mu        sync.Mutex
	guest     []byte
	session   *session
	candidate *candidate
	socket    *socket
}

func newChannel(credentials credentials, url, hostURL, dev string, pairing bool) *channel {
	return &channel{
		id:         credentials.channel,
		url:        url,
		hostURL:    hostURL,
		hostToken:  credentials.hostToken,
		guestToken: credentials.guestToken,
		dev:        dev,
		pairing:    pairing,
		stopCh:     make(chan struct{}),
	}
}

func (c *channel) stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
		c.mu.Lock()
		socket := c.socket
		c.socket = nil
		c.mu.Unlock()
		if socket != nil {
			socket.Close()
		}
	})
}

func (c *channel) stopped() bool {
	select {
	case <-c.stopCh:
		return true
	default:
		return false
	}
}

func (c *channel) sessionAndSocket() (*session, *socket) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session, c.socket
}

// Device is a bound guest. Its id and name are the host's and Connected is live.
type Device struct {
	host     *Host
	id       string
	name     string
	guest    []byte
	mu       sync.Mutex
	channels map[string]*channel
	current  *channel
	changed  chan struct{}
}

func newDevice(host *Host, id, name string, guest []byte) *Device {
	return &Device{
		host:     host,
		id:       id,
		name:     name,
		guest:    bytes.Clone(guest),
		channels: make(map[string]*channel),
		changed:  make(chan struct{}),
	}
}

func (d *Device) ID() string { return d.id }

func (d *Device) Name() string { return d.name }

func (d *Device) Connected() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.current != nil
}

func (d *Device) Send(ctx context.Context, message []byte) error {
	return d.host.sendDevice(ctx, d, message)
}

func (d *Device) notifyLocked() {
	close(d.changed)
	d.changed = make(chan struct{})
}

func (d *Device) setCurrent(ch *channel) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.current = ch
	d.notifyLocked()
}

func (d *Device) clearCurrent(ch *channel) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.current == ch {
		d.current = nil
		d.notifyLocked()
	}
}

func (d *Device) resetCurrent() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.current = nil
	d.notifyLocked()
}

func (d *Device) snapshot() (*channel, chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.current, d.changed
}

func (d *Device) channelList() []*channel {
	d.mu.Lock()
	defer d.mu.Unlock()
	channels := make([]*channel, 0, len(d.channels))
	for _, ch := range d.channels {
		channels = append(channels, ch)
	}
	return channels
}

func (d *Device) channelCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.channels)
}

func (d *Device) removeChannel(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.channels, id)
}

// Pairing is one open pairing: its payload and the code a person types.
type Pairing struct {
	host     *Host
	dev      string
	name     string
	psk      []byte
	expires  int64
	payload  string
	channels []*channel

	pending      map[string]string
	unmatched    int
	confirming   bool
	bound        bool
	boundKey     []byte
	expiryStop   context.CancelFunc
	deadlineStop context.CancelFunc
}

// Device returns the device id this pairing binds, to find it again with
// Host.Pairing.
func (p *Pairing) Device() string {
	return p.dev
}

// Payload is the JSON of PROTOCOL.md section 4, for a QR or copied text.
func (p *Pairing) Payload() string {
	p.host.mu.Lock()
	defer p.host.mu.Unlock()
	return p.payload
}

// Confirm binds the pending key whose code the person typed (PROTOCOL.md §5.5).
func (p *Pairing) Confirm(ctx context.Context, code string) (*Device, error) {
	return p.host.confirm(ctx, p, code)
}

// Host is the long-lived side: one static key and many bound devices.
type Host struct {
	ctx    context.Context
	cancel context.CancelFunc

	store   Store
	saveMu  sync.Mutex
	private []byte
	static  *memoryKey
	relays  []Relay

	mu       sync.Mutex
	closed   bool
	devices  map[string]*Device
	pairings map[string]*Pairing
	ids      map[string]struct{}
	faulty   map[string]bool
	paused   map[string]time.Time
	inbox    chan inboxItem
	wg       sync.WaitGroup

	closeOnce sync.Once
	closeErr  error
}

type storedChannel struct {
	URL        string `json:"url"`
	Channel    string `json:"channel"`
	HostToken  string `json:"host_token"`
	GuestToken string `json:"guest_token"`
}

type storedDevice struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Guest    string          `json:"guest"`
	Channels []storedChannel `json:"channels"`
}

type storedHostState struct {
	V       int            `json:"v"`
	Static  string         `json:"static"`
	Devices []storedDevice `json:"devices"`
}

// OpenHost opens the host whose state the store holds, drawing its static key
// on the first run.
func OpenHost(ctx context.Context, store Store, relays []Relay) (*Host, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(relays) == 0 {
		return nil, errors.New("a host needs at least one relay")
	}
	for _, relay := range relays {
		if !urlAllowed(relay.URL) {
			return nil, fmt.Errorf("relay URL fails the policy of PROTOCOL.md §8.1: %s", relay.URL)
		}
		if relay.HostURL != "" && !hostURLAllowed(relay.HostURL) {
			return nil, fmt.Errorf("host URL fails the policy of PROTOCOL.md §2.3: %s", relay.HostURL)
		}
	}
	state, firstRun, err := loadState(store)
	if err != nil {
		return nil, err
	}
	var private []byte
	if firstRun {
		private = randomBytes(32)
	} else {
		staticHex, ok := isHex64(state["static"])
		if !ok {
			return nil, errors.New("the state file is damaged")
		}
		private, _ = hex.DecodeString(staticHex)
	}
	static, err := memoryKeyFromPrivate(private)
	if err != nil {
		return nil, err
	}
	hostCtx, cancel := context.WithCancel(context.Background())
	host := &Host{
		ctx:      hostCtx,
		cancel:   cancel,
		store:    store,
		private:  private,
		static:   static,
		relays:   append([]Relay(nil), relays...),
		devices:  make(map[string]*Device),
		pairings: make(map[string]*Pairing),
		ids:      make(map[string]struct{}),
		faulty:   make(map[string]bool),
		paused:   make(map[string]time.Time),
		inbox:    make(chan inboxItem, inboxCapacity),
	}
	if firstRun {
		if err := host.save(); err != nil {
			cancel()
			return nil, err
		}
	} else if err := host.loadDevices(state); err != nil {
		cancel()
		return nil, err
	}
	host.mu.Lock()
	devices := make([]*Device, 0, len(host.devices))
	for _, device := range host.devices {
		devices = append(devices, device)
	}
	host.mu.Unlock()
	for _, device := range devices {
		for _, item := range device.channelList() {
			host.startChannel(item)
		}
	}
	return host, nil
}

func (h *Host) loadDevices(state map[string]any) error {
	rawDevices, ok := state["devices"].([]any)
	if !ok {
		return errors.New("the state file has no device list")
	}
	for _, raw := range rawDevices {
		item, ok := raw.(map[string]any)
		if !ok {
			return errors.New("the state file is damaged")
		}
		id, okID := item["id"].(string)
		name, okName := item["name"].(string)
		guestHex, okGuest := isHex64(item["guest"])
		rawChannels, okChannels := item["channels"].([]any)
		if !okID || !okName || !okGuest || !okChannels {
			return errors.New("the state file is damaged")
		}
		guest, _ := hex.DecodeString(guestHex)
		device := newDevice(h, id, name, guest)
		for _, rawChannel := range rawChannels {
			stored, ok := rawChannel.(map[string]any)
			if !ok {
				return errors.New("the state file is damaged")
			}
			urlText, okURL := stored["url"].(string)
			if !okURL {
				return errors.New("the state file is damaged")
			}
			if !urlAllowed(urlText) {
				continue
			}
			channelID, okChannel := isB64URL(stored["channel"], 22)
			hostToken, okHost := isB64URL(stored["host_token"], 43)
			guestToken, okGuest := isB64URL(stored["guest_token"], 43)
			if !okChannel || !okHost || !okGuest {
				return errors.New("the state file is damaged")
			}
			hostURL := urlText
			for _, configured := range h.relays {
				if configured.URL == urlText {
					hostURL = configured.hostURL()
					break
				}
			}
			item := newChannel(credentials{
				channel:    channelID,
				hostToken:  hostToken,
				guestToken: guestToken,
			}, urlText, hostURL, id, false)
			item.guest = bytes.Clone(guest)
			item.device = device
			device.channels[channelID] = item
			h.ids[channelID] = struct{}{}
		}
		h.devices[id] = device
	}
	return nil
}

// Devices lists the bound devices.
func (h *Host) Devices() []*Device {
	h.mu.Lock()
	defer h.mu.Unlock()
	devices := make([]*Device, 0, len(h.devices))
	for _, device := range h.devices {
		devices = append(devices, device)
	}
	return devices
}

// Pairing returns the open pairing for a device, so another request can confirm
// it.
func (h *Host) Pairing(device string) (*Pairing, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, ErrClosed
	}
	pairing, ok := h.pairings[device]
	if !ok || pairing.bound {
		return nil, fmt.Errorf("%w: the pairing has ended", ErrPairingFailed)
	}
	return pairing, nil
}

// Pair opens one pairing on every usable relay and builds its payload
// (PROTOCOL.md §5.2).
func (h *Host) Pair(ctx context.Context, name string) (*Pairing, error) {
	h.mu.Lock()
	closed := h.closed
	h.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	pairing := &Pairing{
		host:    h,
		dev:     randomHex(8),
		name:    name,
		psk:     randomBytes(32),
		expires: time.Now().Unix() + int64(pairingLifetime/time.Second),
		pending: make(map[string]string),
	}
	channels, err := h.createChannels(ctx, pairing.dev, true, nil)
	if err != nil {
		h.deleteChannels(context.Background(), channels)
		return nil, err
	}
	if len(channels) == 0 {
		return nil, errors.New("no relay created a pairing channel")
	}
	entries := make([]relayEntry, 0, len(channels))
	for _, item := range channels {
		entries = append(entries, relayEntry{URL: item.url, Channel: item.id, Token: item.guestToken})
	}
	pairing.channels = channels
	pairing.payload = encodePayload(payload{
		dev:        pairing.dev,
		hostPublic: h.static.PublicKey(),
		psk:        pairing.psk,
		expires:    pairing.expires,
		relays:     entries,
	})
	h.mu.Lock()
	if h.closed {
		h.releaseIDsLocked(channels)
		h.mu.Unlock()
		h.deleteChannels(context.Background(), channels)
		return nil, ErrClosed
	}
	h.pairings[pairing.dev] = pairing
	h.mu.Unlock()
	for _, item := range channels {
		h.startChannel(item)
	}
	h.startPairingExpiry(pairing)
	return pairing, nil
}

// Revoke sends revoked, then deletes the device's channels (PROTOCOL.md §10.5).
func (h *Host) Revoke(ctx context.Context, device *Device) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return ErrClosed
	}
	if h.devices[device.id] != device {
		h.mu.Unlock()
		return nil
	}
	h.mu.Unlock()
	if current, _ := device.snapshot(); current != nil {
		if session, socket := current.sessionAndSocket(); session != nil && socket != nil {
			_ = session.Send(ctx, socket, kindControl, encodeControl("revoked", nil))
		}
	}
	h.removeDevice(device.id)
	return nil
}

// Recv waits for one message from any bound device. After Close it still
// returns the messages already received, then ErrClosed.
func (h *Host) Recv(ctx context.Context) (*Device, []byte, error) {
	select {
	case item := <-h.inbox:
		return item.device, item.message, nil
	case <-h.ctx.Done():
		select {
		case item := <-h.inbox:
			return item.device, item.message, nil
		default:
			return nil, nil, ErrClosed
		}
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

// Close stops every socket and waits for every goroutine the host started.
func (h *Host) Close() error {
	h.closeOnce.Do(func() {
		h.closeErr = h.closeAll()
	})
	return h.closeErr
}

func (h *Host) closeAll() error {
	h.mu.Lock()
	h.closed = true
	var ephemeral, permanent []*channel
	for _, pairing := range h.pairings {
		h.cancelPairingLocked(pairing)
		ephemeral = append(ephemeral, pairing.channels...)
	}
	h.pairings = make(map[string]*Pairing)
	for _, device := range h.devices {
		permanent = append(permanent, device.channelList()...)
	}
	h.mu.Unlock()
	h.cancel()
	h.stopChannels(append(ephemeral, permanent...))
	h.wg.Wait()
	h.deleteChannels(context.Background(), ephemeral)
	return nil
}

func (h *Host) sendDevice(ctx context.Context, device *Device, message []byte) error {
	for {
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			return ErrClosed
		}
		if h.devices[device.id] != device {
			h.mu.Unlock()
			return errors.New("the device is not bound")
		}
		empty := device.channelCount() == 0
		h.mu.Unlock()
		if empty {
			return errors.New("the device has no channel left")
		}
		current, changed := device.snapshot()
		if current != nil {
			session, socket := current.sessionAndSocket()
			if session != nil && socket != nil {
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
			}
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		case <-h.ctx.Done():
			return ErrClosed
		}
	}
}

func (h *Host) confirm(ctx context.Context, pairing *Pairing, code string) (*Device, error) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, ErrClosed
	}
	if h.pairings[pairing.dev] != pairing || pairing.bound {
		h.mu.Unlock()
		return nil, fmt.Errorf("%w: the pairing has ended", ErrPairingFailed)
	}
	if pairing.confirming {
		h.mu.Unlock()
		return nil, fmt.Errorf("%w: this pairing is already being confirmed", ErrPairingFailed)
	}
	typed := strings.TrimSpace(code)
	matches := make([][]byte, 0, 1)
	for key, pendingCode := range pairing.pending {
		if subtle.ConstantTimeCompare([]byte(pendingCode), []byte(typed)) == 1 {
			matches = append(matches, []byte(key))
		}
	}
	if len(matches) != 1 {
		if len(matches) == 0 {
			pairing.unmatched++
			if pairing.unmatched < maxUnmatchedCodes {
				triesLeft := maxUnmatchedCodes - pairing.unmatched
				h.mu.Unlock()
				return nil, &WrongCodeError{TriesLeft: triesLeft}
			}
		}
		h.mu.Unlock()
		h.endPairing(pairing)
		if len(matches) > 0 {
			return nil, fmt.Errorf("%w: two pending keys have that code", ErrPairingFailed)
		}
		return nil, fmt.Errorf("%w: too many wrong codes", ErrPairingFailed)
	}
	guest := bytes.Clone(matches[0])
	pairing.confirming = true
	h.mu.Unlock()

	channels, err := h.createChannels(ctx, pairing.dev, false, guest)
	h.mu.Lock()
	pairing.confirming = false
	if h.pairings[pairing.dev] != pairing {
		h.releaseIDsLocked(channels)
		h.mu.Unlock()
		h.deleteChannels(context.Background(), channels)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: the pairing has ended", ErrPairingFailed)
	}
	if err != nil {
		h.releaseIDsLocked(channels)
		h.mu.Unlock()
		h.deleteChannels(context.Background(), channels)
		return nil, err
	}
	if len(channels) == 0 {
		h.mu.Unlock()
		h.endPairing(pairing)
		return nil, fmt.Errorf("%w: no relay created a device channel", ErrPairingFailed)
	}
	device := newDevice(h, pairing.dev, pairing.name, guest)
	for _, item := range channels {
		item.guest = bytes.Clone(guest)
		item.device = device
		device.channels[item.id] = item
	}
	oldChannels := append([]*channel(nil), pairing.channels...)
	h.devices[pairing.dev] = device
	pairing.bound = true
	pairing.boundKey = bytes.Clone(guest)
	pairing.pending = make(map[string]string)
	for i := range pairing.psk {
		pairing.psk[i] = 0
	}
	h.cancelPairingLocked(pairing)
	h.mu.Unlock()

	// PROTOCOL.md §5.5: forget the other pending keys and their sessions.
	for _, item := range oldChannels {
		item.mu.Lock()
		item.candidate = nil
		sameGuest := bytes.Equal(item.guest, guest)
		item.mu.Unlock()
		if !sameGuest {
			h.abortChannel(item)
		}
	}
	if err := h.save(); err != nil {
		return nil, err
	}
	for _, item := range channels {
		h.startChannel(item)
	}
	h.startPairingDeadline(pairing)
	for _, item := range oldChannels {
		item.mu.Lock()
		bound := bytes.Equal(item.guest, guest)
		item.mu.Unlock()
		if bound {
			if session, socket := item.sessionAndSocket(); session != nil && socket != nil {
				h.sendRelays(pairing, item)
				break
			}
		}
	}
	return device, nil
}

func (h *Host) startPairingExpiry(pairing *Pairing) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(h.ctx)
	pairing.expiryStop = cancel
	h.wg.Add(1)
	h.mu.Unlock()
	go func() {
		defer h.wg.Done()
		timer := time.NewTimer(time.Until(time.Unix(pairing.expires, 0)))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return
		}
		h.mu.Lock()
		current := h.pairings[pairing.dev] == pairing && !pairing.bound
		h.mu.Unlock()
		if current {
			h.endPairing(pairing)
		}
	}()
}

func (h *Host) startPairingDeadline(pairing *Pairing) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(h.ctx)
	pairing.deadlineStop = cancel
	h.wg.Add(1)
	h.mu.Unlock()
	go func() {
		defer h.wg.Done()
		timer := time.NewTimer(confirmationLifetime)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return
		}
		h.mu.Lock()
		current := h.pairings[pairing.dev] == pairing
		h.mu.Unlock()
		if current {
			// PROTOCOL.md §5.5: the guest never reached its device channels.
			h.endPairing(pairing)
		}
	}()
}

func (h *Host) cancelPairingLocked(pairing *Pairing) {
	if pairing.expiryStop != nil {
		pairing.expiryStop()
		pairing.expiryStop = nil
	}
	if pairing.deadlineStop != nil {
		pairing.deadlineStop()
		pairing.deadlineStop = nil
	}
}

func (h *Host) endPairing(pairing *Pairing) {
	h.mu.Lock()
	if h.pairings[pairing.dev] != pairing {
		h.mu.Unlock()
		return
	}
	delete(h.pairings, pairing.dev)
	h.cancelPairingLocked(pairing)
	channels := append([]*channel(nil), pairing.channels...)
	var device *Device
	if pairing.bound {
		device = h.devices[pairing.dev]
		if device != nil {
			delete(h.devices, pairing.dev)
			channels = append(channels, device.channelList()...)
		}
	}
	h.releaseIDsLocked(channels)
	h.mu.Unlock()
	if device != nil {
		device.resetCurrent()
		_ = h.save()
	}
	h.stopChannels(channels)
	h.deleteChannels(context.Background(), channels)
}

// finishPairing drops the pairing channels once the guest reached a device
// channel.
func (h *Host) finishPairing(pairing *Pairing) {
	h.mu.Lock()
	if h.pairings[pairing.dev] != pairing {
		h.mu.Unlock()
		return
	}
	delete(h.pairings, pairing.dev)
	h.cancelPairingLocked(pairing)
	channels := append([]*channel(nil), pairing.channels...)
	h.releaseIDsLocked(channels)
	h.mu.Unlock()
	h.stopChannels(channels)
	h.deleteChannels(context.Background(), channels)
}

func (h *Host) removeDevice(dev string) {
	h.mu.Lock()
	device := h.devices[dev]
	if device == nil {
		h.mu.Unlock()
		return
	}
	delete(h.devices, dev)
	channels := device.channelList()
	if pairing := h.pairings[dev]; pairing != nil {
		delete(h.pairings, dev)
		h.cancelPairingLocked(pairing)
		channels = append(channels, pairing.channels...)
	}
	h.releaseIDsLocked(channels)
	h.mu.Unlock()
	device.resetCurrent()
	_ = h.save()
	h.stopChannels(channels)
	h.deleteChannels(context.Background(), channels)
}

func (h *Host) releaseIDsLocked(channels []*channel) {
	for _, item := range channels {
		delete(h.ids, item.id)
	}
}

func (h *Host) usableRelaysLocked() []Relay {
	now := time.Now()
	relays := make([]Relay, 0, len(h.relays))
	for _, relay := range h.relays {
		if h.faulty[relay.URL] || h.paused[relay.URL].After(now) {
			continue
		}
		relays = append(relays, relay)
	}
	return relays
}

func (h *Host) createChannels(ctx context.Context, dev string, pairing bool, guest []byte) ([]*channel, error) {
	h.mu.Lock()
	relays := h.usableRelaysLocked()
	h.mu.Unlock()
	results := make([]credentials, len(relays))
	failures := make([]error, len(relays))
	var wg sync.WaitGroup
	for index, relay := range relays {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[index], failures[index] = createChannel(ctx, relay)
		}()
	}
	wg.Wait()
	contextError := ctx.Err()
	channels := make([]*channel, 0, len(relays))
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		for index, relay := range relays {
			if failures[index] == nil {
				channels = append(channels, newChannel(results[index], relay.URL, relay.hostURL(), dev, pairing))
			}
		}
		return channels, ErrClosed
	}
	for index, relay := range relays {
		if failures[index] != nil {
			continue
		}
		credentials := results[index]
		// PROTOCOL.md §3.1: a channel id the host already holds, on any relay,
		// is a failed creation.
		if _, held := h.ids[credentials.channel]; held {
			continue
		}
		h.ids[credentials.channel] = struct{}{}
		item := newChannel(credentials, relay.URL, relay.hostURL(), dev, pairing)
		item.guest = bytes.Clone(guest)
		channels = append(channels, item)
	}
	if contextError != nil {
		h.releaseIDsLocked(channels)
		h.mu.Unlock()
		return channels, contextError
	}
	h.mu.Unlock()
	return channels, nil
}

func (h *Host) startChannel(item *channel) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.wg.Add(1)
	h.mu.Unlock()
	go h.runChannel(item)
}

func (h *Host) runChannel(item *channel) {
	defer h.wg.Done()
	retry := newBackoff()
	for {
		if h.stopped(item) {
			return
		}
		h.mu.Lock()
		faulty := h.faulty[item.url]
		pausedUntil := h.paused[item.url]
		h.mu.Unlock()
		if faulty {
			return
		}
		if wait := time.Until(pausedUntil); wait > 0 {
			if !sleepUntil(h.ctx, item.stopCh, wait) {
				return
			}
			continue
		}
		switch h.runSocket(item, retry) {
		case outcomeGone:
			h.forgetChannel(item)
			return
		case outcomeFault:
			h.fault(item.url, item)
			return
		case outcomePause:
			continue
		}
		if h.stopped(item) {
			return
		}
		if !sleepUntil(h.ctx, item.stopCh, retry.next()) {
			return
		}
	}
}

type outcome int

const (
	outcomeRetry outcome = iota
	outcomeGone
	outcomeFault
	outcomePause
)

func (h *Host) runSocket(item *channel, retry *backoff) (result outcome) {
	var socket *socket
	defer func() {
		// A panic, like any other failure, costs this attempt and not the channel.
		if value := recover(); value != nil {
			logPanic(value)
		}
		if socket != nil {
			socket.Close()
		}
		item.mu.Lock()
		item.socket = nil
		item.mu.Unlock()
		h.dropSession(item)
	}()
	socket = newSocket(item.hostURL, item.id, item.hostToken)
	openCtx, cancel := context.WithTimeout(h.ctx, socketTimeout)
	err := socket.Open(openCtx)
	cancel()
	if err != nil {
		return h.socketOutcome(item, err)
	}
	// stop() closes the socket the channel holds, which ends the Recv below.
	item.mu.Lock()
	item.socket = socket
	item.mu.Unlock()
	if item.stopped() {
		return outcomeRetry
	}
	retry.reset()
	for {
		data, err := socket.Recv(h.ctx)
		if err != nil {
			return h.socketOutcome(item, err)
		}
		if err := h.handle(item, socket, data); err != nil {
			return h.socketOutcome(item, err)
		}
	}
}

func (h *Host) socketOutcome(item *channel, err error) outcome {
	if code, ok := closedStatus(err); ok {
		switch code {
		case 4401, 4410:
			return outcomeGone
		case 4400, 4413:
			return outcomeFault
		case 4429:
			h.pause(item.url)
			return outcomePause
		}
	}
	return outcomeRetry
}

func isChannelGone(err error) bool {
	code, ok := closedStatus(err)
	return ok && (code == 4401 || code == 4410)
}

func (h *Host) stopped(item *channel) bool {
	if item.stopped() {
		return true
	}
	select {
	case <-h.ctx.Done():
		return true
	default:
		return false
	}
}

func (h *Host) dropSession(item *channel) {
	item.mu.Lock()
	item.session = nil
	item.candidate = nil
	device := item.device
	item.mu.Unlock()
	if device != nil {
		device.clearCurrent(item)
	}
}

func (h *Host) handle(item *channel, socket *socket, data []byte) error {
	if len(data) == 0 {
		h.abort(item, socket, false)
		return nil
	}
	body := data[1:]
	switch data[0] {
	case framePair:
		return h.onPair(item, socket, body)
	case frameConnect:
		return h.onConnect(item, socket, body)
	case frameTransport:
		return h.onTransport(item, socket, body)
	case frameAbort:
		if len(body) != 0 {
			h.abort(item, socket, false)
			return nil
		}
		item.mu.Lock()
		item.candidate = nil
		item.mu.Unlock()
		h.dropSession(item)
		return nil
	default:
		// accept, or an unknown type: the host never receives either.
		h.abort(item, socket, false)
		return nil
	}
}

func (h *Host) onPair(item *channel, socket *socket, body []byte) error {
	h.mu.Lock()
	pairing := h.pairings[item.dev]
	usable := item.pairing && pairing != nil && !pairing.bound &&
		time.Now().Unix() <= pairing.expires && len(body) == 96 &&
		len(pairing.pending) < maxPending
	var psk []byte
	if usable {
		psk = bytes.Clone(pairing.psk)
	}
	h.mu.Unlock()
	if !usable {
		h.abort(item, socket, true)
		return nil
	}
	handshake, err := newHandshake("IKpsk1", false, prologue(item.dev, item.id), h.static, nil, psk, nil)
	if err == nil {
		_, err = handshake.readMessage(body)
	}
	if err != nil {
		h.abort(item, socket, true)
		return nil
	}
	guest := bytes.Clone(handshake.remoteStatic)
	if guest == nil {
		h.abort(item, socket, true)
		return nil
	}
	h.mu.Lock()
	pairing = h.pairings[item.dev]
	if pairing == nil || pairing.bound || time.Now().Unix() > pairing.expires {
		h.mu.Unlock()
		h.abort(item, socket, true)
		return nil
	}
	if _, pending := pairing.pending[string(guest)]; pending || len(pairing.pending) >= maxPending {
		h.mu.Unlock()
		h.abort(item, socket, true)
		return nil
	}
	h.mu.Unlock()
	answer, err := handshake.writeMessage(nil)
	if err != nil {
		h.abort(item, socket, true)
		return nil
	}
	session, err := newResponderSession(handshake)
	if err != nil {
		h.abort(item, socket, true)
		return nil
	}
	item.mu.Lock()
	item.candidate = &candidate{
		guest:   guest,
		session: session,
		code:    pairingCode(handshake.handshakeHash()),
	}
	item.mu.Unlock()
	return socket.SendAll(h.ctx, [][]byte{frame(frameAccept, answer)})
}

func (h *Host) onConnect(item *channel, socket *socket, body []byte) error {
	if len(body) != 48 {
		h.abort(item, socket, true)
		return nil
	}
	var keys [][]byte
	if item.pairing {
		h.mu.Lock()
		pairing := h.pairings[item.dev]
		if pairing != nil {
			if pairing.bound {
				keys = append(keys, bytes.Clone(pairing.boundKey))
			} else {
				for key := range pairing.pending {
					keys = append(keys, []byte(key))
				}
			}
		}
		h.mu.Unlock()
	} else {
		h.mu.Lock()
		device := h.devices[item.dev]
		h.mu.Unlock()
		if device != nil {
			keys = append(keys, bytes.Clone(device.guest))
		}
	}
	for _, key := range keys {
		if key == nil {
			continue
		}
		handshake, err := newHandshake("KK", false, prologue(item.dev, item.id), h.static, key, nil, nil)
		if err == nil {
			_, err = handshake.readMessage(body)
		}
		if err != nil {
			continue
		}
		answer, err := handshake.writeMessage(nil)
		if err != nil {
			continue
		}
		session, err := newResponderSession(handshake)
		if err != nil {
			continue
		}
		item.mu.Lock()
		item.candidate = &candidate{guest: bytes.Clone(key), session: session}
		item.mu.Unlock()
		return socket.SendAll(h.ctx, [][]byte{frame(frameAccept, answer)})
	}
	h.abort(item, socket, true)
	return nil
}

func (h *Host) onTransport(item *channel, socket *socket, body []byte) error {
	if len(body) < minTransport || len(body) > maxTransport {
		h.abort(item, socket, false)
		return nil
	}
	item.mu.Lock()
	currentCandidate := item.candidate
	item.mu.Unlock()
	if currentCandidate != nil {
		kind, message, more, err := currentCandidate.session.Decrypt(body)
		if err == nil {
			return h.promote(item, socket, currentCandidate, kind, message, more)
		}
		if !isTagFailure(err) {
			h.abort(item, socket, false)
			return nil
		}
	}
	item.mu.Lock()
	current := item.session
	item.mu.Unlock()
	if current == nil {
		h.abort(item, socket, false)
		return nil
	}
	kind, message, more, err := current.Decrypt(body)
	if err != nil {
		h.abort(item, socket, false)
		return nil
	}
	// PROTOCOL.md §6.3: the current session decrypted it, so the candidate goes.
	item.mu.Lock()
	item.candidate = nil
	item.mu.Unlock()
	if !more {
		return h.process(item, socket, current, kind, message)
	}
	return nil
}

func (h *Host) promote(item *channel, socket *socket, expected *candidate, kind byte, message []byte, more bool) error {
	// PROTOCOL.md §6.1: a promoted candidate's first frame is a ping.
	if more || kind != kindControl {
		h.abort(item, socket, false)
		return nil
	}
	control, err := parseControl(string(message), "host")
	if err != nil || control == nil || control.op != "ping" {
		h.abort(item, socket, false)
		return nil
	}
	item.mu.Lock()
	if item.candidate != expected {
		item.mu.Unlock()
		h.abort(item, socket, false)
		return nil
	}
	item.candidate = nil
	item.session = expected.session
	item.guest = bytes.Clone(expected.guest)
	item.mu.Unlock()

	if item.pairing {
		h.mu.Lock()
		pairing := h.pairings[item.dev]
		if pairing == nil {
			h.mu.Unlock()
			h.abort(item, socket, false)
			return nil
		}
		bound := pairing.bound
		var boundKey []byte
		if bound {
			boundKey = bytes.Clone(pairing.boundKey)
		} else if _, pending := pairing.pending[string(expected.guest)]; !pending {
			// PROTOCOL.md §5.3: one pairing holds at most four pending keys.
			if len(pairing.pending) >= maxPending || expected.code == "" {
				h.mu.Unlock()
				h.abort(item, socket, false)
				return nil
			}
			pairing.pending[string(expected.guest)] = expected.code
		}
		h.mu.Unlock()
		if bound && bytes.Equal(expected.guest, boundKey) {
			// PROTOCOL.md §5.5: the guest may have missed the list on the socket
			// it had at confirmation, so every promotion carries it.
			h.sendRelays(pairing, item)
		}
	}
	if err := expected.session.Send(h.ctx, socket, kindControl, encodeControl("pong", nil)); err != nil {
		return err
	}
	if !item.pairing {
		h.promotedDevice(item)
	}
	return nil
}

func (h *Host) promotedDevice(item *channel) {
	device := item.device
	if device == nil {
		h.mu.Lock()
		device = h.devices[item.dev]
		h.mu.Unlock()
	}
	if device == nil {
		return
	}
	device.setCurrent(item)
	h.mu.Lock()
	pairing := h.pairings[item.dev]
	h.mu.Unlock()
	if pairing != nil && pairing.bound {
		h.finishPairing(pairing)
	}
}

func (h *Host) process(item *channel, socket *socket, session *session, kind byte, message []byte) error {
	if kind == kindApplication {
		if item.pairing {
			h.abort(item, socket, false)
			return nil
		}
		h.deliver(item.dev, message)
		return nil
	}
	control, err := parseControl(string(message), "host")
	if err != nil {
		h.abort(item, socket, false)
		return nil
	}
	if control == nil {
		return nil
	}
	switch control.op {
	case "ping":
		return session.Send(h.ctx, socket, kindControl, encodeControl("pong", nil))
	case "close":
		_ = session.Send(h.ctx, socket, kindControl, encodeControl("closed", nil))
		if item.pairing {
			h.mu.Lock()
			pairing := h.pairings[item.dev]
			h.mu.Unlock()
			if pairing != nil {
				h.endPairing(pairing)
			}
		} else {
			h.removeDevice(item.dev)
		}
	}
	return nil
}

func (h *Host) abort(item *channel, socket *socket, keepCurrent bool) {
	item.mu.Lock()
	item.candidate = nil
	item.mu.Unlock()
	if !keepCurrent {
		h.dropSession(item)
	}
	_ = socket.SendAll(h.ctx, [][]byte{frame(frameAbort, nil)})
}

func (h *Host) abortChannel(item *channel) {
	item.mu.Lock()
	item.candidate = nil
	session := item.session
	socket := item.socket
	item.mu.Unlock()
	if session != nil && socket != nil {
		_ = socket.SendAll(h.ctx, [][]byte{frame(frameAbort, nil)})
	}
	h.dropSession(item)
}

func (h *Host) sendRelays(pairing *Pairing, item *channel) {
	h.mu.Lock()
	device := h.devices[pairing.dev]
	h.mu.Unlock()
	if device == nil {
		return
	}
	entries := make([]relayEntry, 0)
	for _, other := range device.channelList() {
		entries = append(entries, relayEntry{URL: other.url, Channel: other.id, Token: other.guestToken})
	}
	session, socket := item.sessionAndSocket()
	if session == nil || socket == nil {
		return
	}
	_ = session.Send(h.ctx, socket, kindControl, encodeControl("relays", entries))
}

func (h *Host) deliver(dev string, message []byte) {
	h.mu.Lock()
	device := h.devices[dev]
	h.mu.Unlock()
	if device == nil {
		return
	}
	select {
	case h.inbox <- inboxItem{device: device, message: bytes.Clone(message)}:
	case <-h.ctx.Done():
	}
}

func (h *Host) forgetChannel(item *channel) {
	item.stop()
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	save := false
	if item.pairing {
		if pairing := h.pairings[item.dev]; pairing != nil {
			for index, other := range pairing.channels {
				if other == item {
					pairing.channels = append(pairing.channels[:index], pairing.channels[index+1:]...)
					break
				}
			}
		}
	} else if device := h.devices[item.dev]; device != nil {
		device.removeChannel(item.id)
		save = true
	}
	delete(h.ids, item.id)
	h.mu.Unlock()
	if save {
		_ = h.save()
	}
}

func (h *Host) pause(url string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.paused[url] = time.Now().Add(secondsUntilUTCMidnight())
}

func (h *Host) fault(url string, current *channel) {
	h.mu.Lock()
	h.faulty[url] = true
	var channels []*channel
	for _, pairing := range h.pairings {
		channels = append(channels, pairing.channels...)
	}
	for _, device := range h.devices {
		channels = append(channels, device.channelList()...)
	}
	h.mu.Unlock()
	for _, item := range channels {
		if item.url == url && item != current {
			item.stop()
		}
	}
}

func (h *Host) stopChannels(channels []*channel) {
	for _, item := range channels {
		item.stop()
	}
}

func (h *Host) deleteChannels(ctx context.Context, channels []*channel) {
	if len(channels) == 0 {
		return
	}
	deleteCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, item := range channels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = deleteChannel(deleteCtx, item.hostURL, item.id, item.hostToken)
		}()
	}
	wg.Wait()
}

func (h *Host) save() error {
	h.saveMu.Lock()
	defer h.saveMu.Unlock()
	h.mu.Lock()
	state := storedHostState{
		V:       stateVersion,
		Static:  hex.EncodeToString(h.private),
		Devices: make([]storedDevice, 0, len(h.devices)),
	}
	for _, device := range h.devices {
		stored := storedDevice{
			ID:    device.id,
			Name:  device.name,
			Guest: hex.EncodeToString(device.guest),
		}
		for _, item := range device.channelList() {
			stored.Channels = append(stored.Channels, storedChannel{
				URL:        item.url,
				Channel:    item.id,
				HostToken:  item.hostToken,
				GuestToken: item.guestToken,
			})
		}
		state.Devices = append(state.Devices, stored)
	}
	h.mu.Unlock()
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return h.store.Save(data)
}

func randomBytes(length int) []byte {
	out := make([]byte, length)
	if _, err := rand.Read(out); err != nil {
		panic(err)
	}
	return out
}

func randomHex(length int) string {
	return hex.EncodeToString(randomBytes(length))
}

func sleepUntil(ctx context.Context, stopped <-chan struct{}, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	case <-stopped:
		return false
	}
}
