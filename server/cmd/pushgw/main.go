// Command pushgw is the push gateway of contract C11: relays send it batches
// of push tokens, and it sends each token one data-only FCM message. It learns
// a token and the time of each wake-up; never a room, a sender or any content.
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

	"github.com/syalia-srl/relay/server/internal/pushgw"
)

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("pushgw: ")

	addr := os.Getenv("PUSHGW_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8020"
	}
	fcm, err := pushgw.NewFCM(os.Getenv("PUSHGW_FCM_CREDENTIALS"), os.Getenv("PUSHGW_FCM_ENDPOINT"))
	if err != nil {
		log.Fatalf("cannot start: %v", err)
	}
	keys, err := pushgw.LoadKeys(os.Getenv("PUSHGW_KEYS_PATH"))
	if err != nil {
		// A missing file refuses every key, the safe default.
		log.Printf("no keys: %v; every call is refused", err)
	} else {
		log.Printf("keys loaded: %d", keys.Count())
	}

	// SIGHUP re-reads the keys file; a bad file keeps the keys in use.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := keys.Reload(); err != nil {
				log.Printf("keys not reloaded: %v", err)
			} else {
				log.Printf("keys loaded: %d", keys.Count())
			}
		}
	}()

	srv := &http.Server{
		Addr:              addr,
		Handler:           pushgw.NewServer(keys, fcm).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	log.Printf("listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
}
