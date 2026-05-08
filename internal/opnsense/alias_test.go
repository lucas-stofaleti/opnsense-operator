package opnsense

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetAliasUUIDByName(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh /api/firewall/alias/getAliasUUID/test
	// Real response:
	//   {"uuid":"c6b50d57-b441-4217-a2d1-b81313887fdc"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET request, got %s", r.Method)
		}
		if r.URL.Path != "/api/firewall/alias/getAliasUUID/test" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}

		username, password, ok := r.BasicAuth()
		if !ok {
			t.Fatal("expected basic auth credentials")
		}
		if username != "key" || password != "secret" {
			t.Fatalf("unexpected credentials %q/%q", username, password)
		}

		writeJSON(t, w, http.StatusOK, map[string]string{
			"uuid": "c6b50d57-b441-4217-a2d1-b81313887fdc",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key", "secret", server.Client())

	uuid, err := client.GetAliasUUIDByName(context.Background(), "test")
	if err != nil {
		t.Fatalf("GetAliasUUIDByName returned error: %v", err)
	}
	if uuid != "c6b50d57-b441-4217-a2d1-b81313887fdc" {
		t.Fatalf("expected uuid to match real response, got %q", uuid)
	}
}

func TestGetAliasUUIDByNameReturnsNotFound(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh /api/firewall/alias/getAliasUUID/definitely-missing-alias
	// Real response:
	//   []
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, []string{})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key", "secret", server.Client())

	_, err := client.GetAliasUUIDByName(context.Background(), "definitely-missing-alias")
	if err == nil {
		t.Fatal("expected not found error")
	}
	if err != ErrAliasNotFound {
		t.Fatalf("expected ErrAliasNotFound, got %v", err)
	}
}

func TestGetAliasUUIDByNameReturnsUnexpectedResponseWhenUUIDMissing(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key", "secret", server.Client())

	_, err := client.GetAliasUUIDByName(context.Background(), "test")
	if err == nil {
		t.Fatal("expected unexpected response error")
	}
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestCreateAlias(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{"alias":{"enabled":"1","name":"ca1778237031","type":"host","content":"198.51.100.10\n198.51.100.11","description":"created by probe"}}' /api/firewall/alias/addItem
	// Real response:
	//   {"result":"saved","uuid":"514ae60a-a270-47df-afdd-b9cdc6fb5c7f"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/api/firewall/alias/addItem" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}

		var payload map[string]map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request body: %v", err)
		}

		aliasPayload := payload["alias"]
		if aliasPayload["enabled"] != "1" {
			t.Fatalf("expected enabled to be \"1\", got %q", aliasPayload["enabled"])
		}
		if aliasPayload["name"] != "allow_dns" {
			t.Fatalf("expected name to match, got %q", aliasPayload["name"])
		}
		if aliasPayload["type"] != "host" {
			t.Fatalf("expected type to match, got %q", aliasPayload["type"])
		}
		if aliasPayload["content"] != "198.51.100.10\n198.51.100.11" {
			t.Fatalf("expected content to match, got %q", aliasPayload["content"])
		}
		if aliasPayload["description"] != "created by test" {
			t.Fatalf("expected description to match, got %q", aliasPayload["description"])
		}

		writeJSON(t, w, http.StatusOK, map[string]string{
			"result": "saved",
			"uuid":   "514ae60a-a270-47df-afdd-b9cdc6fb5c7f",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key", "secret", server.Client())

	uuid, err := client.CreateAlias(context.Background(), Alias{
		Enabled:     true,
		Name:        "allow_dns",
		Type:        "host",
		Content:     "198.51.100.10\n198.51.100.11",
		Description: "created by test",
	})
	if err != nil {
		t.Fatalf("CreateAlias returned error: %v", err)
	}
	if uuid != "514ae60a-a270-47df-afdd-b9cdc6fb5c7f" {
		t.Fatalf("expected uuid to match real response, got %q", uuid)
	}
}

func TestCreateAliasReturnsValidationError(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{"alias":{"enabled":"1","name":"test","type":"host","content":"198.51.100.20","description":"duplicate probe"}}' /api/firewall/alias/addItem
	// Real response:
	//   {"result":"failed","validations":{"alias.name":"An alias with this name already exists."}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"result": "failed",
			"validations": map[string]string{
				"alias.name": "An alias with this name already exists.",
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key", "secret", server.Client())

	_, err := client.CreateAlias(context.Background(), Alias{
		Enabled: true,
		Name:    "test",
		Type:    "host",
		Content: "198.51.100.20",
	})
	if err == nil {
		t.Fatal("expected validation error")
	}

	var validationErr *ValidationError
	if !AsValidationError(err, &validationErr) {
		t.Fatalf("expected ValidationError, got %T", err)
	}
	if validationErr.FieldErrors["alias.name"] != "An alias with this name already exists." {
		t.Fatalf("unexpected validation error map: %#v", validationErr.FieldErrors)
	}
}

func TestCreateAliasReturnsUnexpectedResponseWhenUUIDMissing(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{
			"result": "saved",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key", "secret", server.Client())

	_, err := client.CreateAlias(context.Background(), Alias{
		Enabled: true,
		Name:    "allow_dns",
		Type:    "host",
		Content: "198.51.100.20",
	})
	if err == nil {
		t.Fatal("expected unexpected response error")
	}
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestUpdateAlias(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{"alias":{"enabled":"1","name":"ca1778237031","type":"host","content":"203.0.113.10","description":"updated by probe"}}' /api/firewall/alias/setItem/514ae60a-a270-47df-afdd-b9cdc6fb5c7f
	// Real response:
	//   {"result":"saved"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/api/firewall/alias/setItem/514ae60a-a270-47df-afdd-b9cdc6fb5c7f" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}

		var payload map[string]map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request body: %v", err)
		}

		aliasPayload := payload["alias"]
		if aliasPayload["description"] != "updated by test" {
			t.Fatalf("expected description to match, got %q", aliasPayload["description"])
		}

		writeJSON(t, w, http.StatusOK, map[string]string{
			"result": "saved",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key", "secret", server.Client())

	err := client.UpdateAlias(context.Background(), "514ae60a-a270-47df-afdd-b9cdc6fb5c7f", Alias{
		Enabled:     true,
		Name:        "allow_dns",
		Type:        "host",
		Content:     "203.0.113.10",
		Description: "updated by test",
	})
	if err != nil {
		t.Fatalf("UpdateAlias returned error: %v", err)
	}
}

func TestUpdateAliasReturnsNotFound(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{"alias":{"enabled":"1","name":"missinguuid","type":"host","content":"198.51.100.50","description":"missing uuid probe"}}' /api/firewall/alias/setItem/11111111-1111-1111-1111-111111111111
	// Real response:
	//   {"result":"failed"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{
			"result": "failed",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key", "secret", server.Client())

	err := client.UpdateAlias(context.Background(), "11111111-1111-1111-1111-111111111111", Alias{
		Enabled: true,
		Name:    "allow_dns",
		Type:    "host",
		Content: "198.51.100.20",
	})
	if err == nil {
		t.Fatal("expected not found error")
	}
	if !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("expected ErrAliasNotFound, got %v", err)
	}
}

func TestDeleteAlias(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{}' /api/firewall/alias/delItem/514ae60a-a270-47df-afdd-b9cdc6fb5c7f
	// Real response:
	//   {"result":"deleted"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/api/firewall/alias/delItem/514ae60a-a270-47df-afdd-b9cdc6fb5c7f" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}

		writeJSON(t, w, http.StatusOK, map[string]string{
			"result": "deleted",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key", "secret", server.Client())

	if err := client.DeleteAlias(context.Background(), "514ae60a-a270-47df-afdd-b9cdc6fb5c7f"); err != nil {
		t.Fatalf("DeleteAlias returned error: %v", err)
	}
}

func TestDeleteAliasReturnsNotFound(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{}' /api/firewall/alias/delItem/11111111-1111-1111-1111-111111111111
	// Real response:
	//   {"result":"not found"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{
			"result": "not found",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key", "secret", server.Client())

	err := client.DeleteAlias(context.Background(), "11111111-1111-1111-1111-111111111111")
	if err == nil {
		t.Fatal("expected not found error")
	}
	if !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("expected ErrAliasNotFound, got %v", err)
	}
}

func TestReconfigureAliases(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{}' /api/firewall/alias/reconfigure
	// Real response:
	//   {"status":"ok"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/api/firewall/alias/reconfigure" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}

		writeJSON(t, w, http.StatusOK, map[string]string{
			"status": "ok",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key", "secret", server.Client())

	if err := client.ReconfigureAliases(context.Background()); err != nil {
		t.Fatalf("ReconfigureAliases returned error: %v", err)
	}
}

func TestReconfigureAliasesReturnsUnexpectedResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{
			"status": "failed",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "key", "secret", server.Client())

	err := client.ReconfigureAliases(context.Background())
	if err == nil {
		t.Fatal("expected unexpected response error")
	}
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestValidationErrorFormattingAndUnwrap(t *testing.T) {
	t.Parallel()

	err := &ValidationError{
		FieldErrors: map[string]string{
			"alias.content": "must not be empty",
			"alias.name":    "must be unique",
		},
	}

	expected := "opnsense validation failed: alias.content: must not be empty, alias.name: must be unique"
	if err.Error() != expected {
		t.Fatalf("expected formatted error %q, got %q", expected, err.Error())
	}
	if !errors.Is(err, ErrValidationFailed) {
		t.Fatalf("expected errors.Is to match ErrValidationFailed")
	}

	emptyErr := &ValidationError{}
	if emptyErr.Error() != ErrValidationFailed.Error() {
		t.Fatalf("expected empty validation error to match sentinel string, got %q", emptyErr.Error())
	}
}

func TestNewClientUsesDefaultHTTPClient(t *testing.T) {
	t.Parallel()

	client := NewClient("http://example.com/", "key", "secret", nil)
	if client.httpClient != http.DefaultClient {
		t.Fatal("expected default http client to be used when nil is passed")
	}
	if client.baseURL != "http://example.com" {
		t.Fatalf("expected baseURL to be trimmed, got %q", client.baseURL)
	}
}

func TestDecodeResultResponseInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := decodeResultResponse([]byte("{"))
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestDoJSONReturnsMarshalError(t *testing.T) {
	t.Parallel()

	client := NewClient("http://example.com", "key", "secret", http.DefaultClient)

	_, err := client.doJSON(context.Background(), http.MethodPost, "/api/firewall/alias/addItem", map[string]any{
		"invalid": func() {},
	})
	if err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestDoJSONReturnsRequestError(t *testing.T) {
	t.Parallel()

	client := NewClient("://bad-url", "key", "secret", http.DefaultClient)

	_, err := client.doJSON(context.Background(), http.MethodGet, "/api/firewall/alias/searchItem", nil)
	if err == nil {
		t.Fatal("expected request creation error")
	}
}

func TestDoJSONReturnsTransportError(t *testing.T) {
	t.Parallel()

	client := NewClient("http://example.com", "key", "secret", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		}),
	})

	_, err := client.doJSON(context.Background(), http.MethodGet, "/api/firewall/alias/searchItem", nil)
	if err == nil {
		t.Fatal("expected transport error")
	}
}

func TestDoJSONReturnsReadError(t *testing.T) {
	t.Parallel()

	client := NewClient("http://example.com", "key", "secret", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errReadCloser{err: errors.New("read failed")},
				Header:     make(http.Header),
			}, nil
		}),
	})

	_, err := client.doJSON(context.Background(), http.MethodGet, "/api/firewall/alias/searchItem", nil)
	if err == nil {
		t.Fatal("expected body read error")
	}
}

func TestDoJSONReturnsHTTPStatusError(t *testing.T) {
	t.Parallel()

	client := NewClient("http://example.com", "key", "secret", &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(bytes.NewBufferString("boom")),
				Header:     make(http.Header),
			}, nil
		}),
	})

	_, err := client.doJSON(context.Background(), http.MethodGet, "/api/firewall/alias/searchItem", nil)
	if err == nil {
		t.Fatal("expected http status error")
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, statusCode int, body any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Fatalf("encode response body: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type errReadCloser struct {
	err error
}

func (e errReadCloser) Read([]byte) (int, error) {
	return 0, e.err
}

func (e errReadCloser) Close() error {
	return nil
}
