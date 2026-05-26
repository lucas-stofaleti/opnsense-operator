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

func TestGetRule(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh /api/firewall/filter/getRule/eb3c7d1b-4348-4b93-8a94-1efabf9225d2
	// Real response (abbreviated):
	//   {"rule":{"enabled":"1","sequence":"2500","action":{"pass":{"value":"Pass","selected":1},...},
	//   "interface":{"lan":{"value":"LAN","selected":1},...},"direction":{"in":{"value":"In","selected":1},...},
	//   "ipprotocol":{"inet":{"value":"IPv4","selected":1},...},"protocol":{"TCP":{"value":"TCP","selected":1},...},
	//   "source_net":"any","source_not":"0","source_port":"","destination_net":"192.168.1.0/24",
	//   "destination_not":"0","destination_port":"443","log":"0","quick":"1",
	//   "description":"Allow HTTPS [opnsense-operator:default/allow-https]"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET request, got %s", r.Method)
		}
		if r.URL.Path != "/api/firewall/filter/getRule/eb3c7d1b-4348-4b93-8a94-1efabf9225d2" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}

		writeJSON(t, w, http.StatusOK, map[string]any{
			"rule": map[string]any{
				"enabled":  "1",
				"sequence": "2500",
				"action": map[string]any{
					"pass":   map[string]any{"value": "Pass", "selected": 1},
					"block":  map[string]any{"value": "Block", "selected": 0},
					"reject": map[string]any{"value": "Reject", "selected": 0},
				},
				"interface": map[string]any{
					"lan": map[string]any{"value": "LAN", "selected": 1},
					"wan": map[string]any{"value": "WAN", "selected": 0},
				},
				"direction": map[string]any{
					"in":  map[string]any{"value": "In", "selected": 1},
					"out": map[string]any{"value": "Out", "selected": 0},
					"any": map[string]any{"value": "Both", "selected": 0},
				},
				"ipprotocol": map[string]any{
					"inet":   map[string]any{"value": "IPv4", "selected": 1},
					"inet6":  map[string]any{"value": "IPv6", "selected": 0},
					"inet46": map[string]any{"value": "IPv4+IPv6", "selected": 0},
				},
				"protocol": map[string]any{
					"any": map[string]any{"value": "any", "selected": 0},
					"TCP": map[string]any{"value": "TCP", "selected": 1},
					"UDP": map[string]any{"value": "UDP", "selected": 0},
				},
				"source_net":       "any",
				"source_not":       "0",
				"source_port":      "",
				"destination_net":  "192.168.1.0/24",
				"destination_not":  "0",
				"destination_port": "443",
				"log":              "0",
				"quick":            "1",
				"description":      "Allow HTTPS [opnsense-operator:default/allow-https]",
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testAPIKey, testAPISecret, server.Client())

	rule, err := client.GetRule(context.Background(), "eb3c7d1b-4348-4b93-8a94-1efabf9225d2")
	if err != nil {
		t.Fatalf("GetRule returned error: %v", err)
	}

	if !rule.Enabled {
		t.Error("expected Enabled=true")
	}
	if rule.Action != "pass" {
		t.Errorf("expected Action=%q, got %q", "pass", rule.Action)
	}
	if rule.Interface != "lan" {
		t.Errorf("expected Interface=%q, got %q", "lan", rule.Interface)
	}
	if rule.Direction != "in" {
		t.Errorf("expected Direction=%q, got %q", "in", rule.Direction)
	}
	if rule.IPProtocol != "inet" {
		t.Errorf("expected IPProtocol=%q, got %q", "inet", rule.IPProtocol)
	}
	if rule.Protocol != "TCP" {
		t.Errorf("expected Protocol=%q, got %q", "TCP", rule.Protocol)
	}
	if rule.SourceNet != "any" {
		t.Errorf("expected SourceNet=%q, got %q", "any", rule.SourceNet)
	}
	if rule.SourceNot {
		t.Error("expected SourceNot=false")
	}
	if rule.SourcePort != "" {
		t.Errorf("expected SourcePort=%q, got %q", "", rule.SourcePort)
	}
	if rule.DestinationNet != "192.168.1.0/24" {
		t.Errorf("expected DestinationNet=%q, got %q", "192.168.1.0/24", rule.DestinationNet)
	}
	if rule.DestinationNot {
		t.Error("expected DestinationNot=false")
	}
	if rule.DestinationPort != "443" {
		t.Errorf("expected DestinationPort=%q, got %q", "443", rule.DestinationPort)
	}
	if rule.Sequence != "2500" {
		t.Errorf("expected Sequence=%q, got %q", "2500", rule.Sequence)
	}
	if rule.Log {
		t.Error("expected Log=false")
	}
	if !rule.Quick {
		t.Error("expected Quick=true")
	}
	if rule.Description != "Allow HTTPS [opnsense-operator:default/allow-https]" {
		t.Errorf("expected Description to match, got %q", rule.Description)
	}
}

func TestGetRuleNotFound(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh /api/firewall/filter/getRule/11111111-2222-3333-4444-555555555555
	// Real response:
	//   []
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	client := NewClient(server.URL, testAPIKey, testAPISecret, server.Client())

	_, err := client.GetRule(context.Background(), "11111111-2222-3333-4444-555555555555")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrFirewallRuleNotFound) {
		t.Fatalf("expected ErrFirewallRuleNotFound, got %v", err)
	}
}

func TestGetRuleUnexpectedResponseEmpty(t *testing.T) {
	t.Parallel()

	// Mock returns an empty object {} — not an array and not a valid rule.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{})
	}))
	defer server.Close()

	client := NewClient(server.URL, testAPIKey, testAPISecret, server.Client())

	_, err := client.GetRule(context.Background(), "11111111-2222-3333-4444-555555555555")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestGetRuleTransportError(t *testing.T) {
	t.Parallel()

	client := NewClient("http://example.com", testAPIKey, testAPISecret, &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		}),
	})

	_, err := client.GetRule(context.Background(), "eb3c7d1b-4348-4b93-8a94-1efabf9225d2")
	if err == nil {
		t.Fatal("expected transport error")
	}
}

func TestSearchRuleByManagedSuffixFound(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh '/api/firewall/filter/searchRule?searchPhrase=default/allow-https'
	// Real response:
	//   {"total":1,"rowCount":1,"current":1,"rows":[{"uuid":"eb3c7d1b-4348-4b93-8a94-1efabf9225d2","enabled":"1","sequence":"2500","action":"pass","interface":"","direction":"in","ipprotocol":"inet","protocol":"any","source_net":"any","source_not":"0","source_port":"","destination_net":"any","destination_not":"0","destination_port":"","quick":"1","log":"0","description":"Allow HTTPS [opnsense-operator:default/allow-https]"}]}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET request, got %s", r.Method)
		}
		if r.URL.Path != "/api/firewall/filter/searchRule" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("searchPhrase"); got != "default/allow-https" {
			t.Fatalf("expected searchPhrase=%q, got %q", "default/allow-https", got)
		}

		writeJSON(t, w, http.StatusOK, map[string]any{
			"total":    1,
			"rowCount": 1,
			"current":  1,
			"rows": []map[string]any{
				{
					"uuid":        "eb3c7d1b-4348-4b93-8a94-1efabf9225d2",
					"description": "Allow HTTPS [opnsense-operator:default/allow-https]",
				},
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testAPIKey, testAPISecret, server.Client())

	uuids, err := client.SearchRuleByManagedSuffix(context.Background(), "default/allow-https")
	if err != nil {
		t.Fatalf("SearchRuleByManagedSuffix returned error: %v", err)
	}
	if len(uuids) != 1 {
		t.Fatalf("expected 1 UUID, got %d", len(uuids))
	}
	if uuids[0] != "eb3c7d1b-4348-4b93-8a94-1efabf9225d2" {
		t.Fatalf("expected uuid %q, got %q", "eb3c7d1b-4348-4b93-8a94-1efabf9225d2", uuids[0])
	}
}

func TestSearchRuleByManagedSuffixNotFound(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh '/api/firewall/filter/searchRule?searchPhrase=default/nonexistent'
	// Real response:
	//   {"total":0,"rowCount":0,"current":1,"rows":[]}
	// Note: empty result is NOT an error — the caller decides what to do with 0 results.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total":    0,
			"rowCount": 0,
			"current":  1,
			"rows":     []any{},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testAPIKey, testAPISecret, server.Client())

	uuids, err := client.SearchRuleByManagedSuffix(context.Background(), "default/nonexistent")
	if err != nil {
		t.Fatalf("expected no error for empty result, got %v", err)
	}
	if len(uuids) != 0 {
		t.Fatalf("expected empty slice, got %v", uuids)
	}
}

func TestSearchRuleByManagedSuffixMultiple(t *testing.T) {
	t.Parallel()

	// OPNsense uses a substring match, so multiple rules can share the same suffix.
	// The caller is responsible for handling the ambiguous N>1 case.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total":    2,
			"rowCount": 2,
			"current":  1,
			"rows": []map[string]any{
				{"uuid": "aaaaaaaa-0000-0000-0000-000000000001", "description": "Rule A [opnsense-operator:default/allow-https]"},
				{"uuid": "bbbbbbbb-0000-0000-0000-000000000002", "description": "Rule B [opnsense-operator:default/allow-https]"},
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testAPIKey, testAPISecret, server.Client())

	uuids, err := client.SearchRuleByManagedSuffix(context.Background(), "default/allow-https")
	if err != nil {
		t.Fatalf("SearchRuleByManagedSuffix returned error: %v", err)
	}
	if len(uuids) != 2 {
		t.Fatalf("expected 2 UUIDs, got %d", len(uuids))
	}
	if uuids[0] != "aaaaaaaa-0000-0000-0000-000000000001" {
		t.Errorf("expected first uuid %q, got %q", "aaaaaaaa-0000-0000-0000-000000000001", uuids[0])
	}
	if uuids[1] != "bbbbbbbb-0000-0000-0000-000000000002" {
		t.Errorf("expected second uuid %q, got %q", "bbbbbbbb-0000-0000-0000-000000000002", uuids[1])
	}
}

func TestSearchRuleByManagedSuffixTransportError(t *testing.T) {
	t.Parallel()

	client := NewClient("http://example.com", testAPIKey, testAPISecret, &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		}),
	})

	_, err := client.SearchRuleByManagedSuffix(context.Background(), "default/allow-https")
	if err == nil {
		t.Fatal("expected transport error")
	}
}

// decodeBody is a test helper that decodes the JSON request body into v.
func decodeBody(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
