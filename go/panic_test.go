package relay

import (
	"strings"
	"sync/atomic"
	"testing"
)

func TestPanicLogfReceivesTheStack(t *testing.T) {
	var called atomic.Bool
	var message atomic.Value
	previous := PanicLogf
	PanicLogf = func(format string, _ ...any) {
		called.Store(true)
		message.Store(format)
	}
	defer func() { PanicLogf = previous }()

	func() {
		defer func() {
			if value := recover(); value != nil {
				logPanic(value)
			}
		}()
		panic("boom")
	}()

	if !called.Load() {
		t.Fatal("the recovered panic was not logged")
	}
	if format, _ := message.Load().(string); !strings.Contains(format, "panic") || !strings.Contains(format, "%s") {
		t.Fatalf("the panic log does not carry the value and the stack: %q", format)
	}
}
