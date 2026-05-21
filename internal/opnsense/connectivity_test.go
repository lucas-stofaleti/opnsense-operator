package opnsense

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckConnectivity(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh /api/core/system/status
	// Real response (HTTP 200):
	//   {"metadata":{"system":{"status":"ERROR","message":"No pending messages","title":"System"},...},"subsystems":{...}}
	// Note: the "status" field inside the response body reflects OPNsense system health,
	// not API connectivity. We only check HTTP 200 + valid JSON.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET request, got %s", r.Method)
		}
		if r.URL.Path != "/api/core/system/status" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}

		username, password, ok := r.BasicAuth()
		if !ok {
			t.Fatal("expected basic auth credentials")
		}
		if username != "key" || password != "secret" {
			t.Fatalf("unexpected credentials %q/%q", username, password)
		}

		writeJSON(t, w, http.StatusOK, map[string]any{
			"metadata": map[string]any{
				"system": map[string]string{
					"status":  "ERROR",
					"message": "No pending messages",
					"title":   "System",
				},
			},
			"subsystems": map[string]any{},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key", "secret", server.Client())

	if err := client.CheckConnectivity(context.Background()); err != nil {
		t.Fatalf("CheckConnectivity returned unexpected error: %v", err)
	}
}

func TestCheckConnectivityReturnsErrorOnAuthFailure(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   OPNSENSE_API_KEY=wrongkey OPNSENSE_API_SECRET=wrongsecret hack/opnsense-curl.sh /api/core/system/status
	// Real response (HTTP 401):
	//   {"status":401,"message":"Authentication Failed"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusUnauthorized, map[string]any{
			"status":  401,
			"message": "Authentication Failed",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "wrongkey", "wrongsecret", server.Client())

	err := client.CheckConnectivity(context.Background())
	if err == nil {
		t.Fatal("expected error on auth failure, got nil")
	}
}

func TestCheckConnectivityReturnsErrorOnInvalidJSON(t *testing.T) {
	t.Parallel()

	// Guard against a proxy or load balancer returning HTML on HTTP 200.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>not json</html>"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "key", "secret", server.Client())

	err := client.CheckConnectivity(context.Background())
	if err == nil {
		t.Fatal("expected error on invalid JSON response, got nil")
	}
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}
