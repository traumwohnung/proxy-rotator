package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chiware "github.com/go-chi/chi/v5/middleware"

	proxykit "proxy-kit"
	"proxy-kit/utils"
)

const (
	// proxyReadHeaderTimeout guards against slow-header / Slowloris attacks on
	// the proxy port. CONNECT tunnels are not affected — the timeout only applies
	// until the first request line + headers are received.
	proxyReadHeaderTimeout = 10 * time.Second

	// adminReadHeaderTimeout is tighter since the admin API only handles small
	// JSON requests and should never receive large or slow bodies.
	adminReadHeaderTimeout = 5 * time.Second

	// adminMaxBodyBytes caps request bodies on the admin API.
	adminMaxBodyBytes = 64 * 1024 // 64 KiB

	// shutdownTimeout is how long graceful shutdown waits for in-flight
	// connections to drain before forcibly closing them.
	shutdownTimeout = 30 * time.Second
)

func RunServer(cfg *Config, srv *Server, apiKey string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- Admin API (separate listener, optional) ---
	if apiKey != "" && cfg.AdminAddr != "" {
		adminSrv := buildAdminServer(cfg.AdminAddr, srv.Sessions, apiKey)
		go func() {
			slog.Info("admin API listening", "addr", cfg.AdminAddr)
			if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("admin server error", "err", err)
			}
		}()
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			adminSrv.Shutdown(shutCtx) //nolint:errcheck
		}()
	} else if apiKey != "" {
		slog.Warn("API_KEY set but admin_addr not configured — admin API disabled")
	}

	// --- SOCKS5 listener (background) ---
	if cfg.Socks5Addr != "" {
		go func() {
			slog.Info("SOCKS5 proxy listening", "addr", cfg.Socks5Addr)
			if err := proxykit.ListenSOCKS5(cfg.Socks5Addr, srv.Pipeline); err != nil {
				slog.Error("SOCKS5 server error", "err", err)
			}
		}()
	}

	// --- HTTP proxy (main listener) ---
	// Use the proxy handler directly — chi doesn't route the CONNECT method.
	// ReadHeaderTimeout guards against Slowloris; no ReadTimeout/WriteTimeout
	// because CONNECT tunnels are long-lived bidirectional streams.
	httpSrv := &http.Server{
		Addr:              cfg.BindAddr,
		Handler:           proxykit.HTTPProxyHandler(srv.Pipeline),
		ReadHeaderTimeout: proxyReadHeaderTimeout,
	}

	go func() {
		<-ctx.Done()
		slog.Info("shutdown signal received, draining connections")
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		httpSrv.Shutdown(shutCtx) //nolint:errcheck
	}()

	slog.Info("HTTP proxy listening", "addr", cfg.BindAddr)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func buildAdminServer(addr string, sessions *utils.SessionManager, apiKey string) *http.Server {
	r := chi.NewRouter()
	r.Use(chiware.Recoverer)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, adminMaxBodyBytes)
			next.ServeHTTP(w, r)
		})
	})
	r.Route("/api", func(r chi.Router) {
		r.Get("/sessions", bearerAuth(apiKey, handleListSessions(sessions)))
		r.Get("/sessions/{username}", bearerAuth(apiKey, handleGetSession(sessions)))
		r.Post("/sessions/{username}/rotate", bearerAuth(apiKey, handleForceRotate(sessions)))
	})
	return &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: adminReadHeaderTimeout,
		IdleTimeout:       60 * time.Second,
	}
}
