package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"proxy-gateway/middleware"
)

type apiError struct {
	Error string `json:"error"`
}

func bearerAuth(apiKey string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token != apiKey {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "Invalid or missing API key"})
			return
		}
		next(w, r)
	}
}

func handleListSessions(sessions *middleware.StickyHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list := sessions.ListSessions()
		if list == nil {
			list = []middleware.SessionInfo{}
		}
		writeJSON(w, http.StatusOK, list)
	}
}

func handleGetSession(sessions *middleware.StickyHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := chi.URLParam(r, "key")
		info := sessions.GetSession(key)
		if info == nil {
			writeJSON(w, http.StatusNotFound, apiError{Error: fmt.Sprintf("no active session for %q", key)})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func handleForceRotate(sessions *middleware.StickyHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := chi.URLParam(r, "key")
		info, err := sessions.ForceRotate(r.Context(), key)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
			return
		}
		if info == nil {
			writeJSON(w, http.StatusNotFound, apiError{Error: fmt.Sprintf("no active session for %q", key)})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
