package relay_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	relay "github.com/syalia-srl/relay/go"
)

func TestTheAPIExamples(t *testing.T) {
	directory := t.TempDir()
	process := startRelay(t, filepath.Join(directory, "relay"))
	ctx, cancel := timeoutContext(t, 20*time.Second)
	defer cancel()

	host, err := relay.OpenHost(ctx, relay.FileStore(filepath.Join(directory, "host")), []relay.Relay{
		{URL: process.url, Key: operatorKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	pairing, err := host.Pair(ctx, "pixel-7")
	if err != nil {
		t.Fatal(err)
	}
	payload := pairing.Payload()

	guest, err := relay.OpenGuest(ctx, relay.FileStore(filepath.Join(directory, "guest")), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()

	paired, err := guest.Pair(ctx, payload)
	if err != nil {
		t.Fatal(err)
	}
	if code := paired.Code(); len(code) != 6 {
		t.Fatalf("code is %q", code)
	}
	pairing, err = host.Pairing(pairing.Device())
	if err != nil {
		t.Fatal(err)
	}
	device, err := pairing.Confirm(ctx, paired.Code())
	if err != nil {
		t.Fatal(err)
	}
	if err := paired.Bound(ctx); err != nil {
		t.Fatal(err)
	}

	if err := paired.Send(ctx, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	receivedDevice, message, err := host.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if receivedDevice.ID() != device.ID() || string(message) != "ping" {
		t.Fatalf("host received %q from %s", message, receivedDevice.ID())
	}
	if err := device.Send(ctx, []byte("pong")); err != nil {
		t.Fatal(err)
	}
	answer, err := paired.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(answer) != "pong" {
		t.Fatalf("guest received %q", answer)
	}
	if err := host.Revoke(ctx, device); err != nil {
		t.Fatal(err)
	}
}

func pair(t *testing.T, relayURL, directory string) (*relay.Host, *relay.Guest, *relay.Device, *relay.PairedHost) {
	t.Helper()
	ctx, cancel := timeoutContext(t, 20*time.Second)
	defer cancel()
	host, err := relay.OpenHost(ctx, relay.FileStore(filepath.Join(directory, "host")), []relay.Relay{
		{URL: relayURL, Key: operatorKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	pairing, err := host.Pair(ctx, "pixel-7")
	if err != nil {
		host.Close()
		t.Fatal(err)
	}
	guest, err := relay.OpenGuest(ctx, relay.FileStore(filepath.Join(directory, "guest")), nil)
	if err != nil {
		host.Close()
		t.Fatal(err)
	}
	link, err := guest.Pair(ctx, pairing.Payload())
	if err != nil {
		guest.Close()
		host.Close()
		t.Fatal(err)
	}
	if code := link.Code(); len(code) != 6 {
		t.Fatalf("code is %q", code)
	}
	// A web application confirms in a later request, finding the pairing by id.
	pairing, err = host.Pairing(pairing.Device())
	if err != nil {
		guest.Close()
		host.Close()
		t.Fatal(err)
	}
	device, err := pairing.Confirm(ctx, link.Code())
	if err != nil {
		guest.Close()
		host.Close()
		t.Fatal(err)
	}
	if err := link.Bound(ctx); err != nil {
		guest.Close()
		host.Close()
		t.Fatal(err)
	}
	return host, guest, device, link
}

func TestPairAndSendBothWays(t *testing.T) {
	directory := t.TempDir()
	process := startRelay(t, filepath.Join(directory, "relay"))
	host, guest, device, link := pair(t, process.url, directory)
	defer host.Close()
	defer guest.Close()

	// The host's inbox exists from OpenHost, so this early message is kept.
	if err := link.Send(context.Background(), []byte("early")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	received := newHostInbox(host)
	replies := newGuestInbox(link)
	waitFor(t, func() bool { return device.Connected() })
	waitFor(t, func() bool { return received.has([]byte("early")) })

	if err := link.Send(context.Background(), []byte("ping")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return received.has([]byte("ping")) })
	if err := device.Send(context.Background(), []byte("pong")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return replies.has([]byte("pong")) })

	big := make([]byte, 200_000)
	for index := range big {
		big[index] = byte(index % 251)
	}
	if err := link.Send(context.Background(), big); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return received.has(big) })
	if err := device.Send(context.Background(), big); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return replies.has(big) })

	for _, name := range []string{"host", "guest"} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("%s is mode %o, want 600", name, mode)
		}
	}
	unpairAll(t, guest)
}

func TestRestartBothSides(t *testing.T) {
	directory := t.TempDir()
	process := startRelay(t, filepath.Join(directory, "relay"))
	host, guest, _, link := pair(t, process.url, directory)
	received := newHostInbox(host)
	if err := link.Send(context.Background(), []byte("before")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return received.has([]byte("before")) })
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	if err := guest.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := timeoutContext(t, 30*time.Second)
	defer cancel()
	host, err := relay.OpenHost(ctx, relay.FileStore(filepath.Join(directory, "host")), []relay.Relay{
		{URL: process.url, Key: operatorKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	guest, err = relay.OpenGuest(ctx, relay.FileStore(filepath.Join(directory, "guest")), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()

	devices := host.Devices()
	if len(devices) != 1 || devices[0].Name() != "pixel-7" {
		t.Fatalf("devices after restart are %+v", devices)
	}
	hosts := guest.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("guest has %d hosts after restart", len(hosts))
	}
	link = hosts[0]
	if err := link.Bound(ctx); err != nil {
		t.Fatal(err)
	}
	received = newHostInbox(host)
	replies := newGuestInbox(link)
	if err := link.Send(ctx, []byte("after")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return received.has([]byte("after")) })
	if err := devices[0].Send(ctx, []byte("back")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return replies.has([]byte("back")) })
	unpairAll(t, guest)
}

func TestRevoke(t *testing.T) {
	directory := t.TempDir()
	process := startRelay(t, filepath.Join(directory, "relay"))
	host, guest, device, link := pair(t, process.url, directory)
	defer host.Close()
	defer guest.Close()

	ctx, cancel := timeoutContext(t, 10*time.Second)
	defer cancel()
	if err := host.Revoke(ctx, device); err != nil {
		t.Fatal(err)
	}
	if _, err := link.Recv(ctx); !errors.Is(err, relay.ErrRevoked) {
		t.Fatalf("Recv error is %v, want ErrRevoked", err)
	}
	if len(host.Devices()) != 0 {
		t.Fatalf("host still has %d devices", len(host.Devices()))
	}
	if len(guest.Hosts()) != 0 {
		t.Fatalf("guest still has %d hosts", len(guest.Hosts()))
	}
}

func TestUnpairForgetsBothSides(t *testing.T) {
	directory := t.TempDir()
	process := startRelay(t, filepath.Join(directory, "relay"))
	host, guest, _, _ := pair(t, process.url, directory)
	unpairAll(t, guest)
	waitFor(t, func() bool { return len(host.Devices()) == 0 })
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	if err := guest.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := timeoutContext(t, 10*time.Second)
	defer cancel()
	host, err := relay.OpenHost(ctx, relay.FileStore(filepath.Join(directory, "host")), []relay.Relay{
		{URL: process.url, Key: operatorKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	guest, err = relay.OpenGuest(ctx, relay.FileStore(filepath.Join(directory, "guest")), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	if len(host.Devices()) != 0 || len(guest.Hosts()) != 0 {
		t.Fatalf("host has %d devices and guest has %d hosts", len(host.Devices()), len(guest.Hosts()))
	}
}

func TestWrongCodes(t *testing.T) {
	directory := t.TempDir()
	process := startRelay(t, filepath.Join(directory, "relay"))
	ctx, cancel := timeoutContext(t, 20*time.Second)
	defer cancel()
	host, err := relay.OpenHost(ctx, relay.FileStore(filepath.Join(directory, "host")), []relay.Relay{
		{URL: process.url, Key: operatorKey},
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
	wrong := "000000"
	if link.Code() == wrong {
		wrong = "111111"
	}
	var wrongCode *relay.WrongCodeError
	if _, err := pairing.Confirm(ctx, "١٢٣٤٥٦"); !errors.As(err, &wrongCode) || wrongCode.TriesLeft != 2 {
		t.Fatalf("non-ASCII code returned %v, want a WrongCodeError with 2 tries left", err)
	}
	if _, err := pairing.Confirm(ctx, wrong); !errors.As(err, &wrongCode) {
		t.Fatalf("second wrong code returned %v, want WrongCodeError", err)
	}
	if _, err := pairing.Confirm(ctx, wrong); !errors.Is(err, relay.ErrPairingFailed) {
		t.Fatalf("third wrong code returned %v, want ErrPairingFailed", err)
	}
	if _, err := host.Pairing(pairing.Device()); !errors.Is(err, relay.ErrPairingFailed) {
		t.Fatalf("Pairing after a failure returned %v, want ErrPairingFailed", err)
	}
	if err := guest.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSecondConcurrentConfirmIsRefused(t *testing.T) {
	directory := t.TempDir()
	process := startRelay(t, filepath.Join(directory, "relay"))
	host, guest, _, _ := pair(t, process.url, directory)
	defer host.Close()
	defer guest.Close()

	pairing := mustOpenPairing(t, host, "second")
	ctx, cancel := timeoutContext(t, 20*time.Second)
	defer cancel()
	secondGuest, err := relay.OpenGuest(ctx, relay.FileStore(filepath.Join(directory, "second-guest")), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer secondGuest.Close()
	secondLink, err := secondGuest.Pair(ctx, pairing.Payload())
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		device *relay.Device
		err    error
	}
	first := make(chan result, 1)
	go func() {
		device, err := pairing.Confirm(ctx, secondLink.Code())
		first <- result{device: device, err: err}
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := pairing.Confirm(ctx, secondLink.Code()); !errors.Is(err, relay.ErrPairingFailed) {
		t.Fatalf("second confirm returned %v, want ErrPairingFailed", err)
	}
	answer := <-first
	if answer.err != nil {
		t.Fatal(answer.err)
	}
	if err := secondLink.Bound(ctx); err != nil {
		t.Fatal(err)
	}
	if !answer.device.Connected() {
		t.Fatal("the first confirm did not bind a connected device")
	}
	unpairAll(t, secondGuest)
}

func mustOpenPairing(t *testing.T, host *relay.Host, name string) *relay.Pairing {
	t.Helper()
	ctx, cancel := timeoutContext(t, 10*time.Second)
	defer cancel()
	pairing, err := host.Pair(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	return pairing
}

func TestMovesToTheSecondRelay(t *testing.T) {
	directory := t.TempDir()
	first := startRelay(t, filepath.Join(directory, "first"))
	second := startRelay(t, filepath.Join(directory, "second"))
	ctx, cancel := timeoutContext(t, 60*time.Second)
	defer cancel()
	host, err := relay.OpenHost(ctx, relay.FileStore(filepath.Join(directory, "host")), []relay.Relay{
		{URL: first.url, Key: operatorKey},
		{URL: second.url, Key: operatorKey},
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
	if err := link.Send(ctx, []byte("on the first")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return received.has([]byte("on the first")) })

	first.stop(t)
	sendUntil(t, func(message []byte) error { return link.Send(ctx, message) }, []byte("on the second"),
		func() bool { return received.has([]byte("on the second")) })
	if err := device.Send(ctx, []byte("back again")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return replies.has([]byte("back again")) })
	unpairAll(t, guest)
}
