package proxygatewayclient_test

import (
	"testing"

	proxygatewayclient "github.com/traumwohnung/proxy-gateway/proxy-gateway-client-go"
)

func TestBuildAndParseUsername(t *testing.T) {
	params := proxygatewayclient.UsernameParams{
		Set:     "residential",
		Minutes: 60,
		Meta:    map[string]any{"platform": "myapp", "user": "alice"},
	}

	username, err := proxygatewayclient.BuildUsername(params)
	if err != nil {
		t.Fatalf("BuildUsername: %v", err)
	}
	if username == "" {
		t.Fatal("expected non-empty username")
	}

	parsed, err := proxygatewayclient.ParseUsername(username)
	if err != nil {
		t.Fatalf("ParseUsername: %v", err)
	}
	if parsed.Set != params.Set {
		t.Errorf("set: got %q, want %q", parsed.Set, params.Set)
	}
	if parsed.Minutes != params.Minutes {
		t.Errorf("minutes: got %d, want %d", parsed.Minutes, params.Minutes)
	}
}

func TestBuildUsername_Validation(t *testing.T) {
	_, err := proxygatewayclient.BuildUsername(proxygatewayclient.UsernameParams{Set: "", Minutes: 5})
	if err == nil {
		t.Error("expected error for empty set")
	}

	_, err = proxygatewayclient.BuildUsername(proxygatewayclient.UsernameParams{Set: "residential", Minutes: 9999})
	if err == nil {
		t.Error("expected error for minutes > 1440")
	}
}

func TestParseUsername_Invalid(t *testing.T) {
	_, err := proxygatewayclient.ParseUsername("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}

	// Valid base64 but not JSON
	_, err = proxygatewayclient.ParseUsername("aGVsbG8=") // "hello"
	if err == nil {
		t.Error("expected error for non-JSON payload")
	}
}
