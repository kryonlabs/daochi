package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func localHTTPURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

func main() {
	cfg := loadConfig()
	if len(os.Args) > 1 && os.Args[1] == "inspect" {
		if err := runInspect(context.Background(), os.Args[2:], InspectOptions{DBPath: cfg.DBPath}); err != nil {
			log.Fatalf("inspect: %v", err)
		}
		return
	}

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

	daochi := NewServer(cfg, store, verifier)
	runtimeContext, stopRuntime := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopRuntime()
	var workers sync.WaitGroup
	if cfg.TokenDirectPurchasesEnabled {
		workers.Add(1)
		go func() {
			defer workers.Done()
			daochi.runMoneroInvoiceReconciler(runtimeContext, time.Minute)
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		daochi.runNodeSync(runtimeContext)
	}()
	handler := daochi.Routes()
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(os.Stderr, "http: ", log.LstdFlags),
	}
	go func() {
		<-runtimeContext.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			slog.Error("HTTP shutdown failed", "error", err)
		}
	}()

	slog.Info("Daochi sync server listening", "url", localHTTPURL(cfg.Addr), "addr", cfg.Addr, "base_url", cfg.BaseURL, "db", cfg.DBPath)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("serve failed", "error", err)
	}
	stopRuntime()
	workers.Wait()
}
