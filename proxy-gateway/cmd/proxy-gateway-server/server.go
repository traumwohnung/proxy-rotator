package main

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chiware "github.com/go-chi/chi/v5/middleware"

	"proxy-gateway/core"
	"proxy-gateway/gateway"
	"proxy-gateway/middleware"
)

func RunServer(bindAddr string, pipeline core.Handler, sessions *middleware.StickyHandler, apiKey string) error {
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

	slog.Info("proxy gateway listening", "addr", bindAddr)
	return http.ListenAndServe(bindAddr, r)
}
