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
	"strings"
	"sync"
	"syscall"
	"time"
)

func baselineLocalHTTPURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// Original startup flow at 527dafa, with explicit native dependencies for comparison.
func baselineStartupRun(cfg Config, arguments []string, create VerifierFactory, signer SignPrivateKey) {
	if len(cfg.NodeIdentityPrivateKey) == 0 {
		nodeKey := NodeIdentity_LoadOrCreateKey(cfg.NodeIdentityKeyFile)
		if nodeKey.Error != nil {
			log.Fatalf("load node identity: %v", nodeKey.Error)
		}
		cfg.NodeIdentityPrivateKey = nodeKey.Value
	}
	if len(arguments) > 1 && arguments[1] == "inspect" {
		if err := Inspect_Run(context.Background(), arguments[2:], InspectOptions{DBPath: cfg.DBPath}); err != nil {
			log.Fatalf("inspect: %v", err)
		}
		return
	}

	opened := Store_Open(cfg.DBPath)
	store, err := opened.Value, opened.Error
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	created := create()
	verifier, err := created.Value, created.Error
	if err != nil {
		if errors.Is(err, ErrVerifierUnavailable) {
			log.Fatalf("ML-DSA-44 verifier unavailable: build with CGO_ENABLED=1 and liboqs installed")
		}
		log.Fatalf("create verifier: %v", err)
	}

	daochi := Server_New(cfg, store, verifier, signer)
	runtimeContext, stopRuntime := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopRuntime()
	var workers sync.WaitGroup
	// The reconciler must run whenever a wallet is configured: even with
	// purchases disabled it settles confirmed deposits and sweeps late
	// invoice payments that arrived after expiry.
	if cfg.TokenDirectPurchasesEnabled || strings.TrimSpace(cfg.MoneroWalletRPCURL) != "" {
		workers.Add(1)
		go func() {
			defer workers.Done()
			MoneroInvoices_Run(daochi.monero(), runtimeContext, time.Minute)
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		Mesh_Run(daochi.mesh(), runtimeContext)
	}()
	workers.Add(1)
	go func() {
		defer workers.Done()
		Discovery_Run(&daochi.Cfg, &daochi.Node, runtimeContext, Discovery_Register, Discovery_Shutdown)
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

	slog.Info("Daochi sync server listening", "url", baselineLocalHTTPURL(cfg.Addr), "addr", cfg.Addr, "base_url", cfg.BaseURL, "db", cfg.DBPath)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("serve failed", "error", err)
	}
	stopRuntime()
	workers.Wait()
}

func baselineStartupMain() {
	cfg := Config_Load()
	if len(cfg.NodeIdentityPrivateKey) == 0 {
		key := NodeIdentity_LoadOrCreateKey(cfg.NodeIdentityKeyFile)
		if key.Error != nil {
			log.Fatalf("load node identity: %v", key.Error)
		}
		cfg.NodeIdentityPrivateKey = key.Value
	}
	baselineStartupRun(cfg, os.Args, createVerifier, signAccountProof)
}

func baselineStartWorkers(server *Server, ctx context.Context, group *WorkerGroup, workers Workers) {
	if server.Cfg.TokenDirectPurchasesEnabled || strings.TrimSpace(server.Cfg.MoneroWalletRPCURL) != "" {
		group.Add(1)
		go func() {
			defer group.Done()
			workers.Invoices(server, ctx)
		}()
	}
	group.Add(1)
	go func() {
		defer group.Done()
		workers.Mesh(server, ctx)
	}()
	group.Add(1)
	go func() {
		defer group.Done()
		workers.Discovery(server, ctx)
	}()
}

func baselineShutdownOnCancel(server *HTTPServer, ctx context.Context, shutdown Shutdown) {
	<-ctx.Done()
	shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := shutdown(server, shutdownContext); err != nil {
		slog.Error("HTTP shutdown failed", "error", err)
	}
}

func baselineServe(server *HTTPServer, cfg Config, ctx context.Context, stop context.CancelFunc, group *WorkerGroup, listen Listen, shutdown Shutdown) {
	go baselineShutdownOnCancel(server, ctx, shutdown)
	slog.Info("Daochi sync server listening", "url", baselineLocalHTTPURL(cfg.Addr), "addr", cfg.Addr, "base_url", cfg.BaseURL, "db", cfg.DBPath)
	if err := listen(server); err != nil && err != http.ErrServerClosed {
		slog.Error("serve failed", "error", err)
	}
	stop()
	group.Wait()
}
