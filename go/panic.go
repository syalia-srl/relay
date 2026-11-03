package relay

import (
	"log"
	"runtime/debug"
)

// PanicLogf reports a panic recovered in a connection loop, with its stack. It
// defaults to log.Printf. Set it before opening a host or guest to route panics
// to the application's logger, or set it to nil to keep them silent.
var PanicLogf = log.Printf

func logPanic(value any) {
	if PanicLogf != nil {
		PanicLogf("relay: recovered panic: %v\n%s", value, debug.Stack())
	}
}
