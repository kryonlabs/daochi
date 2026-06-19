package main

import (
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func main() {
	cfg := loadConfig()
	store, err := OpenStore(cfg.DBPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	verifier, err := NewVerifier()
	if err != nil {
		if errors.Is(err, ErrVerifierUnavailable) {
			log.Fatalf("ML-DSA-44 verifier unavailable: build with CGO_ENABLED=1 and liboqs installed")
		}
		log.Fatalf("create verifier: %v", err)
	}

	handler := NewServer(cfg, store, verifier).Routes()
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(os.Stderr, "http: ", log.LstdFlags),
	}

	slog.Info("lyra sync server listening", "addr", cfg.Addr, "base_url", cfg.BaseURL, "db", cfg.DBPath)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}
