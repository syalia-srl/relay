package relay_test

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	relay "github.com/syalia-srl/relay/go"
)

type hostMessage struct {
	device  string
	message []byte
}

type hostInbox struct {
	mu       sync.Mutex
	messages []hostMessage
}

func newHostInbox(host *relay.Host) *hostInbox {
	inbox := &hostInbox{}
	go func() {
		for {
			device, message, err := host.Recv(context.Background())
			if err != nil {
				return
			}
			inbox.mu.Lock()
			inbox.messages = append(inbox.messages, hostMessage{device: device.ID(), message: bytes.Clone(message)})
			inbox.mu.Unlock()
		}
	}()
	return inbox
}

func (i *hostInbox) has(message []byte) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, received := range i.messages {
		if bytes.Equal(received.message, message) {
			return true
		}
	}
	return false
}

func (i *hostInbox) snapshot() []hostMessage {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]hostMessage(nil), i.messages...)
}

type guestInbox struct {
	mu       sync.Mutex
	messages [][]byte
}

func newGuestInbox(link *relay.PairedHost) *guestInbox {
	inbox := &guestInbox{}
	go func() {
		for {
			message, err := link.Recv(context.Background())
			if err != nil {
				return
			}
			inbox.mu.Lock()
			inbox.messages = append(inbox.messages, bytes.Clone(message))
			inbox.mu.Unlock()
		}
	}()
	return inbox
}

func (i *guestInbox) has(message []byte) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, received := range i.messages {
		if bytes.Equal(received, message) {
			return true
		}
	}
	return false
}

func (i *guestInbox) snapshot() [][]byte {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([][]byte(nil), i.messages...)
}

func waitFor(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("the condition never held")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func sendUntil(t *testing.T, send func([]byte) error, message []byte, delivered func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !delivered() {
		if time.Now().After(deadline) {
			t.Fatal("the message never arrived")
		}
		_ = send(message)
		time.Sleep(50 * time.Millisecond)
	}
}

func unpairAll(t *testing.T, guest *relay.Guest) {
	t.Helper()
	for _, link := range guest.Hosts() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_ = link.Unpair(ctx)
		cancel()
	}
}

func timeoutContext(t *testing.T, duration time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), duration)
}
