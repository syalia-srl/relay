package relay_test

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestNoGoroutinesLeakAfterClose(t *testing.T) {
	directory := t.TempDir()
	process := startRelay(t, filepath.Join(directory, "relay"))
	baseline := runtime.NumGoroutine()
	host, guest, _, _ := pair(t, process.url, directory)
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	if err := guest.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline+2 {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines remain after Close, started from %d", runtime.NumGoroutine(), baseline)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
