package proxygatewayclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	proxygatewayclient "github.com/traumwohnung/proxy-gateway/proxy-gateway-client-go"
)

func newTestServer(t *testing.T, sessions []proxygatewayclient.SessionInfo) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/sessions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sessions)
	})

	mux.HandleFunc("GET /api/sessions/{username}", func(w http.ResponseWriter, r *http.Request) {
		want := sessions[0].Username
		if r.PathValue("username") != want {
			http.Error(w, `{"error":"no active session"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sessions[0])
	})

	mux.HandleFunc("POST /api/sessions/{username}/rotate", func(w http.ResponseWriter, r *http.Request) {
		want := sessions[0].Username
		if r.PathValue("username") != want {
			http.Error(w, `{"error":"no active session"}`, http.StatusNotFound)
			return
		}
		updated := sessions[0]
		updated.LastRotationAt = time.Now().UTC()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	})

	return httptest.NewServer(mux)
}

var testSession = proxygatewayclient.SessionInfo{
	SessionID:      1,
	Username:       "eyJzZXQiOiJyZXNpZGVudGlhbCIsIm1pbnV0ZXMiOjYwfQ==",
	ProxySet:       "residential",
	Upstream:       "198.51.100.1:6658",
	CreatedAt:      time.Now().UTC(),
	NextRotationAt: time.Now().Add(time.Hour).UTC(),
	LastRotationAt: time.Now().UTC(),
	Metadata:       map[string]any{"platform": "myapp"},
}

func TestListSessions(t *testing.T) {
	srv := newTestServer(t, []proxygatewayclient.SessionInfo{testSession})
	defer srv.Close()

	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL, APIKey: "test"})
	sessions, err := c.ListSessions(context.Background())
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].ProxySet != "residential" {
		t.Errorf("expected proxy_set=residential, got %q", sessions[0].ProxySet)
	}
}

func TestGetSession(t *testing.T) {
	srv := newTestServer(t, []proxygatewayclient.SessionInfo{testSession})
	defer srv.Close()

	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL, APIKey: "test"})

	got, err := c.GetSession(context.Background(), testSession.Username)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got == nil {
		t.Fatal("expected session, got nil")
	}
	if got.Upstream != testSession.Upstream {
		t.Errorf("expected upstream %q, got %q", testSession.Upstream, got.Upstream)
	}

	// Non-existent username → nil, nil
	missing, err := c.GetSession(context.Background(), "notexist")
	if err != nil {
		t.Fatalf("GetSession (missing): %v", err)
	}
	if missing != nil {
		t.Error("expected nil for missing session")
	}
}

func TestForceRotate(t *testing.T) {
	srv := newTestServer(t, []proxygatewayclient.SessionInfo{testSession})
	defer srv.Close()

	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL, APIKey: "test"})

	got, err := c.ForceRotate(context.Background(), testSession.Username)
	if err != nil {
		t.Fatalf("ForceRotate: %v", err)
	}
	if got == nil {
		t.Fatal("expected session after rotate, got nil")
	}

	// Non-existent username → nil, nil
	missing, err := c.ForceRotate(context.Background(), "notexist")
	if err != nil {
		t.Fatalf("ForceRotate (missing): %v", err)
	}
	if missing != nil {
		t.Error("expected nil for missing session")
	}
}
