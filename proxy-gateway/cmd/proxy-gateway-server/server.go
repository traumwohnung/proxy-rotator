package main

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chiware "github.com/go-chi/chi/v5/middleware"

	"proxy-gateway/core"
	"proxy-gateway/gateway"
)

func RunServer(cfg *Config, pipeline core.Handler, sessions *core.StickyHandler, apiKey string) error {
	r := chi.NewRouter()
	r.Use(chiware.Recoverer)

	if apiKey != "" && sessions != nil {
		r.Route("/api", func(r chi.Router) {
			r.Get("/sessions", bearerAuth(apiKey, handleListSessions(sessions)))
			r.Get("/sessions/{key}", bearerAuth(apiKey, handleGetSession(sessions)))
			r.Post("/sessions/{key}/rotate", bearerAuth(apiKey, handleForceRotate(sessions)))
		})
		slog.Info("API endpoints enabled")
	}

	proxyHandler := gateway.HTTPHandler(pipeline)
	r.HandleFunc("/*", proxyHandler.ServeHTTP)
	r.HandleFunc("/", proxyHandler.ServeHTTP)

	// Start SOCKS5 listener in a goroutine if configured.
	if cfg.Socks5Addr != "" {
		go func() {
			if err := gateway.RunSOCKS5(cfg.Socks5Addr, pipeline); err != nil {
				slog.Error("SOCKS5 server error", "err", err)
			}
		}()
	}

	slog.Info("HTTP proxy gateway listening", "addr", cfg.BindAddr)
	return http.ListenAndServe(cfg.BindAddr, r)
}
