// Command relay is the E2E message relay: it creates channels and moves bytes
// between their two sides, and keeps the mailbox of rooms.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/syalia-srl/relay/server/internal/relay"
	"github.com/syalia-srl/relay/server/internal/rooms"
)

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("relay: ")

	cfg := relay.ConfigFromEnv()
	srv, err := relay.New(cfg)
	if err != nil {
		log.Fatalf("cannot start: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", srv.Handler())
	roomsPath := os.Getenv("RELAY_ROOMS_PATH")
	if roomsPath == "" {
		roomsPath = "/data/rooms.db"
	}
	mailbox, err := rooms.Open(rooms.Config{
		Path:           roomsPath,
		TestClock:      os.Getenv("RELAY_TEST_CLOCK"),
		MaxPendingAuth: cfg.MaxPendingAuth,
		Push:           pushConfig(),
	}, srv.Keys)
	if err != nil {
		// Channels keep working; every room route answers 503.
		log.Printf("rooms store not writable; rooms are off: %v", err)
		mux.Handle("/v1/rooms", rooms.Unavailable())
		mux.Handle("/v1/rooms/", rooms.Unavailable())
	} else {
		mailbox.Register(mux)
		mailbox.Sweep()
	}

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           rooms.CORS(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// SIGHUP re-reads the keys file; a bad file keeps the keys in use.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := srv.ReloadKeys(); err != nil {
				log.Printf("keys not reloaded: %v", err)
			} else if mailbox != nil {
				mailbox.Sweep() // an operator key that left makes its rooms read-only now
			}
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	done := make(chan struct{})
	go func() {
		<-stop
		log.Print("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpSrv.Shutdown(ctx) // stop accepting; upgraded sockets are not waited for
		srv.Shutdown()        // so close them with 1001, then save the store
		if mailbox != nil {
			mailbox.Close()
		}
		close(done)
	}()

	go func() {
		ticker := time.NewTicker(cfg.SweepEvery)
		defer ticker.Stop()
		for range ticker.C {
			srv.Sweep()
			if mailbox != nil {
				mailbox.Sweep()
			}
		}
	}()

	// Store changes are coalesced; write them at most once a second.
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			srv.SaveIfDirty()
		}
	}()

	log.Printf("listening on %s", cfg.Addr)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
	<-done
}

// pushConfig reads the push gateway settings (ROOMS.md 3.7). Turning push on
// sends the gateway's operator, for each wake-up, a device's push token and
// the time; never a room id, a sender or any content.
func pushConfig() rooms.PushConfig {
	cfg := rooms.PushConfig{
		URL:     strings.TrimSpace(os.Getenv("RELAY_PUSH_URL")),
		KeyPath: os.Getenv("RELAY_PUSH_KEY_PATH"),
	}
	// RELAY_TEST_PUSH_SCALE is test-only: it scales the batch window and backoff.
	if v := os.Getenv("RELAY_TEST_PUSH_SCALE"); v != "" {
		if scale, err := strconv.ParseFloat(v, 64); err == nil && scale > 0 {
			cfg.Scale = scale
		}
	}
	return cfg
}
