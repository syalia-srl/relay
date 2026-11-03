package relay_test

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	relay "github.com/syalia-srl/relay/go"
)

// TestHostUsesItsOwnRelayURL gives the host a loopback URL for its own HTTP and
// socket traffic while the guests receive the relay's private address.
func TestHostUsesItsOwnRelayURL(t *testing.T) {
	directory := t.TempDir()
	process := startRelay(t, filepath.Join(directory, "relay"))
	proxy := newHostileProxy(t, "127.0.0.1", process.url, process.http)
	ctx, cancel := timeoutContext(t, 30*time.Second)
	defer cancel()

	host, err := relay.OpenHost(ctx, relay.FileStore(filepath.Join(directory, "host")), []relay.Relay{
		{URL: process.url, HostURL: proxy.url, Key: operatorKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	pairing, err := host.Pair(ctx, "pixel-7")
	if err != nil {
		t.Fatal(err)
	}
	httpRequests, _ := proxy.counts()
	if httpRequests == 0 {
		t.Fatal("the host did not create its channel through its host URL")
	}
	waitFor(t, func() bool {
		_, websockets := proxy.counts()
		return websockets > 0
	})

	var document struct {
		Relays []struct {
			URL string `json:"url"`
		} `json:"relays"`
	}
	if err := json.Unmarshal([]byte(pairing.Payload()), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Relays) == 0 {
		t.Fatal("the pairing payload has no relay")
	}
	for _, entry := range document.Relays {
		if entry.URL != process.url {
			t.Fatalf("the pairing payload carries %q, want only the guest URL %q", entry.URL, process.url)
		}
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
	if err := link.Send(ctx, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return received.has([]byte("ping")) })
	if err := device.Send(ctx, []byte("pong")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return replies.has([]byte("pong")) })
}

func TestHostURLChecksSection23(t *testing.T) {
	directory := t.TempDir()
	ctx, cancel := timeoutContext(t, 5*time.Second)
	defer cancel()
	if _, err := relay.OpenHost(ctx, relay.FileStore(filepath.Join(directory, "bad")), []relay.Relay{
		{URL: "wss://relay.example", HostURL: "ws://relay.example", Key: "key"},
	}); err == nil {
		t.Fatal("a ws:// host URL to a dotted name was accepted")
	}
	host, err := relay.OpenHost(ctx, relay.FileStore(filepath.Join(directory, "good")), []relay.Relay{
		{URL: "wss://relay.example", HostURL: "ws://relay:8010", Key: "key"},
	})
	if err != nil {
		t.Fatalf("a ws:// host URL to a dotless name was refused: %v", err)
	}
	host.Close()
}
