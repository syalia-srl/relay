package rooms

import (
	"fmt"
	"slices"
	"testing"
)

func TestCheckPushURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://push.example/v1/wake":  true,
		"http://127.0.0.1:8020/v1/wake": true,
		"http://[::1]:8020/v1/wake":     true,
		"http://localhost/v1/wake":      true,
		"http://push.example/v1/wake":   false,
		"http://10.0.0.1/v1/wake":       false,
		"ftp://127.0.0.1/x":             false,
		"/v1/wake":                      false,
		"not a url":                     false,
	} {
		if got := checkPushURL(raw) == nil; got != ok {
			t.Errorf("checkPushURL(%q) ok = %v, want %v", raw, got, ok)
		}
	}
}

func testPusher() *pusher {
	return &pusher{queued: map[string]bool{}, wake: make(chan struct{}, 1)}
}

func TestPusherQueueDedupsAndSplits(t *testing.T) {
	p := testPusher()
	p.add([]string{"a", "b"})
	p.add([]string{"b", "a", "c"})
	var many []string
	for i := range 1000 {
		many = append(many, fmt.Sprintf("t%04d", i))
	}
	p.add(many)
	batches := p.take()
	if len(batches) != 3 || len(batches[0]) != 500 || len(batches[1]) != 500 || len(batches[2]) != 3 {
		t.Fatalf("batch sizes %d", len(batches))
	}
	if !slices.Equal(batches[0][:4], []string{"a", "b", "c", "t0000"}) {
		t.Fatalf("order %v", batches[0][:4])
	}
	if len(p.take()) != 0 {
		t.Fatal("take left tokens behind")
	}
	// Once taken, a token can be queued again for the next window.
	p.add([]string{"a"})
	if b := p.take(); len(b) != 1 || b[0][0] != "a" {
		t.Fatalf("requeue %v", b)
	}
}

func TestPusherQueueDropsTheOldestAtTheCap(t *testing.T) {
	p := testPusher()
	var tokens []string
	for i := range pushQueueMax + 2 {
		tokens = append(tokens, fmt.Sprintf("t%05d", i))
	}
	p.add(tokens)
	var all []string
	for _, b := range p.take() {
		all = append(all, b...)
	}
	if len(all) != pushQueueMax || all[0] != "t00002" || all[len(all)-1] != tokens[len(tokens)-1] {
		t.Fatalf("kept %d, first %s", len(all), all[0])
	}
}

func TestPusherForgetsOnlyTokensItSent(t *testing.T) {
	var cleared []string
	p := &pusher{clear: func(tokens []string) { cleared = tokens }}
	p.forget([]string{"a", "b"}, []string{"b", "z", "b"})
	if !slices.Equal(cleared, []string{"b"}) {
		t.Fatalf("cleared %v", cleared)
	}
}
