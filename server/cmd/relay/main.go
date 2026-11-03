// Command relay is the E2E message relay: it creates channels and moves bytes
// between their two sides.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/syalia-srl/relay/server/internal/relay"
)

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("relay: ")

	cfg := relay.ConfigFromEnv()
	srv, err := relay.New(cfg)
	if err != nil {
		log.Fatalf("cannot start: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// SIGHUP re-reads the keys file; a bad file keeps the keys in use.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := srv.ReloadKeys(); err != nil {
				log.Printf("keys not reloaded: %v", err)
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
		close(done)
	}()

	go func() {
		ticker := time.NewTicker(cfg.SweepEvery)
		defer ticker.Stop()
		for range ticker.C {
			srv.Sweep()
		}
	}()

	log.Printf("listening on %s", cfg.Addr)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
	<-done
}
