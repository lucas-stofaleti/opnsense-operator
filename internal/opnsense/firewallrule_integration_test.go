//go:build integration

package opnsense

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestCreateRuleIntegration(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{"rule":{"enabled":"1","action":"pass","direction":"in","ipprotocol":"inet","protocol":"any","source_net":"any","source_not":"0","source_port":"","destination_net":"any","destination_not":"0","destination_port":"","sequence":"","log":"0","quick":"1","description":"ci-<timestamp> [opnsense-operator:default/ci-test]"}}' /api/firewall/filter/addRule
	//   hack/opnsense-curl.sh -X POST -d '{}' /api/firewall/filter/delRule/<uuid>
	//   hack/opnsense-curl.sh -X POST -d '{}' /api/firewall/filter/apply
	// Real responses:
	//   {"result":"saved","uuid":"eb3c7d1b-4348-4b93-8a94-1efabf9225d2"}
	//   {"result":"deleted"}
	//   {"status":"OK\n\n"}
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	suffix := "ci-" + time.Now().UTC().Format("150405")
	rule := FirewallRule{
		Enabled:        true,
		Action:         "pass",
		Direction:      "in",
		IPProtocol:     "inet",
		Protocol:       "any",
		SourceNet:      "any",
		DestinationNet: "any",
		Quick:          true,
		Description:    suffix + " [opnsense-operator:default/ci-test]",
	}

	uuid, err := client.CreateRule(ctx, rule)
	if err != nil {
		t.Fatalf("CreateRule returned error: %v", err)
	}
	if uuid == "" {
		t.Fatal("expected non-empty UUID from CreateRule")
	}

	deleted := false
	defer func() {
		if deleted {
			return
		}

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()

		// DeleteRule and ApplyFirewallRules are implemented in later chunks.
		// Use doJSON directly here so this test compiles and runs standalone.
		if _, err := client.doJSON(cleanupCtx, http.MethodPost, "/api/firewall/filter/delRule/"+uuid, map[string]string{}); err == nil {
			_, _ = client.doJSON(cleanupCtx, http.MethodPost, "/api/firewall/filter/apply", map[string]string{})
		}
	}()

	// Use doJSON directly for the same reason as above.
	if _, err := client.doJSON(ctx, http.MethodPost, "/api/firewall/filter/delRule/"+uuid, map[string]string{}); err != nil {
		t.Fatalf("delete rule returned error: %v", err)
	}
	deleted = true

	if _, err := client.doJSON(ctx, http.MethodPost, "/api/firewall/filter/apply", map[string]string{}); err != nil {
		t.Fatalf("apply returned error: %v", err)
	}
}
