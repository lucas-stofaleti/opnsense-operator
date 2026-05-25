package opnsense

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	testAPIKey    = "key"
	testAPISecret = "secret"
)

func TestCreateRule(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{"rule":{"enabled":"1","action":"pass","interface":"lan","direction":"in","ipprotocol":"inet","protocol":"TCP","source_net":"any","source_not":"0","source_port":"","destination_net":"192.168.1.0/24","destination_not":"0","destination_port":"443","sequence":"2500","log":"0","quick":"1","description":"Allow HTTPS [opnsense-operator:default/allow-https]"}}' /api/firewall/filter/addRule
	// Real response:
	//   {"result":"saved","uuid":"eb3c7d1b-4348-4b93-8a94-1efabf9225d2"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/api/firewall/filter/addRule" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}

		username, password, ok := r.BasicAuth()
		if !ok {
			t.Fatal("expected basic auth credentials")
		}
		if username != testAPIKey || password != testAPISecret {
			t.Fatalf("unexpected credentials %q/%q", username, password)
		}

		var payload map[string]map[string]string
		if err := decodeBody(r, &payload); err != nil {
			t.Fatalf("decode request body: %v", err)
		}

		rulePayload, ok := payload["rule"]
		if !ok {
			t.Fatal("expected rule wrapper in request body")
		}
		if rulePayload["enabled"] != "1" {
			t.Fatalf("expected enabled \"1\", got %q", rulePayload["enabled"])
		}
		if rulePayload["action"] != "pass" {
			t.Fatalf("expected action \"pass\", got %q", rulePayload["action"])
		}
		if rulePayload["interface"] != "lan" {
			t.Fatalf("expected interface \"lan\", got %q", rulePayload["interface"])
		}
		if rulePayload["description"] != "Allow HTTPS [opnsense-operator:default/allow-https]" {
			t.Fatalf("expected description to match, got %q", rulePayload["description"])
		}

		writeJSON(t, w, http.StatusOK, map[string]string{
			"result": "saved",
			"uuid":   "eb3c7d1b-4348-4b93-8a94-1efabf9225d2",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testAPIKey, testAPISecret, server.Client())

	uuid, err := client.CreateRule(context.Background(), FirewallRule{
		Enabled:         true,
		Action:          "pass",
		Interface:       "lan",
		Direction:       "in",
		IPProtocol:      "inet",
		Protocol:        "TCP",
		SourceNet:       "any",
		SourceNot:       false,
		SourcePort:      "",
		DestinationNet:  "192.168.1.0/24",
		DestinationNot:  false,
		DestinationPort: "443",
		Sequence:        "2500",
		Log:             false,
		Quick:           true,
		Description:     "Allow HTTPS [opnsense-operator:default/allow-https]",
	})
	if err != nil {
		t.Fatalf("CreateRule returned error: %v", err)
	}
	if uuid != "eb3c7d1b-4348-4b93-8a94-1efabf9225d2" {
		t.Fatalf("expected uuid %q, got %q", "eb3c7d1b-4348-4b93-8a94-1efabf9225d2", uuid)
	}
}

func TestCreateRuleValidationError(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{"rule":{"action":""}}' /api/firewall/filter/addRule
	// Real response:
	//   {"result":"failed","validations":{"rule.action":"Option [] not in list."}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"result": "failed",
			"validations": map[string]string{
				"rule.action": "Option [] not in list.",
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testAPIKey, testAPISecret, server.Client())

	_, err := client.CreateRule(context.Background(), FirewallRule{Action: ""})
	if err == nil {
		t.Fatal("expected validation error")
	}

	var validationErr *ValidationError
	if !AsValidationError(err, &validationErr) {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	if validationErr.FieldErrors["rule.action"] != "Option [] not in list." {
		t.Fatalf("unexpected field errors: %#v", validationErr.FieldErrors)
	}
}

func TestCreateRuleMissingWrapper(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{}' /api/firewall/filter/addRule
	// Real response:
	//   {"result":"failed"}
	// Note: no validations key present when the rule wrapper itself is missing.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{
			"result": "failed",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testAPIKey, testAPISecret, server.Client())

	_, err := client.CreateRule(context.Background(), FirewallRule{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrValidationFailed) {
		t.Fatalf("expected ErrValidationFailed, got %v", err)
	}
}

func TestCreateRuleUnexpectedResponseMissingUUID(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{
			"result": "saved",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testAPIKey, testAPISecret, server.Client())

	_, err := client.CreateRule(context.Background(), FirewallRule{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestCreateRuleTransportError(t *testing.T) {
	t.Parallel()

	client := NewClient("http://example.com", testAPIKey, testAPISecret, &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		}),
	})

	_, err := client.CreateRule(context.Background(), FirewallRule{})
	if err == nil {
		t.Fatal("expected transport error")
	}
}

func TestCreateRuleOmitsEmptySequence(t *testing.T) {
	t.Parallel()

	// OPNsense returns a validation error when sequence is sent as "" (empty string).
	// The payload must omit the field entirely so OPNsense auto-assigns a value.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]map[string]any
		if err := decodeBody(r, &payload); err != nil {
			t.Fatalf("decode request body: %v", err)
		}

		rulePayload := payload["rule"]
		if _, present := rulePayload["sequence"]; present {
			t.Fatalf("expected sequence to be omitted from request, got %v", rulePayload["sequence"])
		}

		writeJSON(t, w, http.StatusOK, map[string]string{
			"result": "saved",
			"uuid":   "eb3c7d1b-4348-4b93-8a94-1efabf9225d2",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testAPIKey, testAPISecret, server.Client())

	_, err := client.CreateRule(context.Background(), FirewallRule{Sequence: ""})
	if err != nil {
		t.Fatalf("CreateRule returned error: %v", err)
	}
}

// decodeBody is a test helper that decodes the JSON request body into v.
func decodeBody(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
