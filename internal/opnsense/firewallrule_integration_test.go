//go:build integration

package opnsense

import (
	"context"
	"errors"
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

		// ApplyFirewallRules is now available; use it for cleanup.
		if err := client.DeleteRule(cleanupCtx, uuid); err == nil {
			_ = client.ApplyFirewallRules(cleanupCtx)
		}
	}()

	if err := client.DeleteRule(ctx, uuid); err != nil {
		t.Fatalf("delete rule returned error: %v", err)
	}
	deleted = true

	if err := client.ApplyFirewallRules(ctx); err != nil {
		t.Fatalf("apply returned error: %v", err)
	}
}

func TestGetRuleIntegration(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{"rule":{"enabled":"1","action":"pass","interface":"lan","direction":"in","ipprotocol":"inet","protocol":"TCP","source_net":"any","destination_net":"192.168.1.0/24","destination_port":"443","quick":"1","description":"ci-get-<timestamp> [opnsense-operator:default/ci-get-test]"}}' /api/firewall/filter/addRule
	//   hack/opnsense-curl.sh /api/firewall/filter/getRule/<uuid>
	// Real response: full rule model with select fields
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	suffix := "ci-get-" + time.Now().UTC().Format("150405")
	want := FirewallRule{
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
		Log:             false,
		Quick:           true,
		Description:     suffix + " [opnsense-operator:default/ci-get-test]",
	}

	uuid, err := client.CreateRule(ctx, want)
	if err != nil {
		t.Fatalf("CreateRule returned error: %v", err)
	}

	deleted := false
	defer func() {
		if deleted {
			return
		}

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()

		if err := client.DeleteRule(cleanupCtx, uuid); err == nil {
			_ = client.ApplyFirewallRules(cleanupCtx)
		}
	}()

	got, err := client.GetRule(ctx, uuid)
	if err != nil {
		t.Fatalf("GetRule returned error: %v", err)
	}

	if got.Enabled != want.Enabled {
		t.Errorf("Enabled: got %v, want %v", got.Enabled, want.Enabled)
	}
	if got.Action != want.Action {
		t.Errorf("Action: got %q, want %q", got.Action, want.Action)
	}
	if got.Interface != want.Interface {
		t.Errorf("Interface: got %q, want %q", got.Interface, want.Interface)
	}
	if got.Direction != want.Direction {
		t.Errorf("Direction: got %q, want %q", got.Direction, want.Direction)
	}
	if got.IPProtocol != want.IPProtocol {
		t.Errorf("IPProtocol: got %q, want %q", got.IPProtocol, want.IPProtocol)
	}
	if got.Protocol != want.Protocol {
		t.Errorf("Protocol: got %q, want %q", got.Protocol, want.Protocol)
	}
	if got.SourceNet != want.SourceNet {
		t.Errorf("SourceNet: got %q, want %q", got.SourceNet, want.SourceNet)
	}
	if got.SourceNot != want.SourceNot {
		t.Errorf("SourceNot: got %v, want %v", got.SourceNot, want.SourceNot)
	}
	if got.SourcePort != want.SourcePort {
		t.Errorf("SourcePort: got %q, want %q", got.SourcePort, want.SourcePort)
	}
	if got.DestinationNet != want.DestinationNet {
		t.Errorf("DestinationNet: got %q, want %q", got.DestinationNet, want.DestinationNet)
	}
	if got.DestinationNot != want.DestinationNot {
		t.Errorf("DestinationNot: got %v, want %v", got.DestinationNot, want.DestinationNot)
	}
	if got.DestinationPort != want.DestinationPort {
		t.Errorf("DestinationPort: got %q, want %q", got.DestinationPort, want.DestinationPort)
	}
	if got.Log != want.Log {
		t.Errorf("Log: got %v, want %v", got.Log, want.Log)
	}
	if got.Quick != want.Quick {
		t.Errorf("Quick: got %v, want %v", got.Quick, want.Quick)
	}
	if got.Description != want.Description {
		t.Errorf("Description: got %q, want %q", got.Description, want.Description)
	}

	if err := client.DeleteRule(ctx, uuid); err != nil {
		t.Fatalf("delete rule returned error: %v", err)
	}
	deleted = true

	if err := client.ApplyFirewallRules(ctx); err != nil {
		t.Fatalf("apply returned error: %v", err)
	}
}

func TestSearchRuleByManagedSuffixIntegration(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh '/api/firewall/filter/searchRule?searchPhrase=default/ci-search-test'
	// Real response:
	//   {"total":1,"rowCount":1,"current":1,"rows":[{"uuid":"<uuid>","description":"ci-search-<ts> [opnsense-operator:default/ci-search-test]",...}]}
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	suffix := "ci-search-" + time.Now().UTC().Format("150405")
	description := suffix + " [opnsense-operator:default/ci-search-test]"

	uuid, err := client.CreateRule(ctx, FirewallRule{
		Enabled:        true,
		Action:         "pass",
		Direction:      "in",
		IPProtocol:     "inet",
		Protocol:       "any",
		SourceNet:      "any",
		DestinationNet: "any",
		Quick:          true,
		Description:    description,
	})
	if err != nil {
		t.Fatalf("CreateRule returned error: %v", err)
	}

	deleted := false
	defer func() {
		if deleted {
			return
		}

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()

		if err := client.DeleteRule(cleanupCtx, uuid); err == nil {
			_ = client.ApplyFirewallRules(cleanupCtx)
		}
	}()

	uuids, err := client.SearchRuleByManagedSuffix(ctx, "default/ci-search-test")
	if err != nil {
		t.Fatalf("SearchRuleByManagedSuffix returned error: %v", err)
	}

	found := false
	for _, u := range uuids {
		if u == uuid {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected UUID %q in search results %v", uuid, uuids)
	}

	if err := client.DeleteRule(ctx, uuid); err != nil {
		t.Fatalf("delete rule returned error: %v", err)
	}
	deleted = true

	if err := client.ApplyFirewallRules(ctx); err != nil {
		t.Fatalf("apply returned error: %v", err)
	}
}

func TestUpdateRuleIntegration(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{"rule":{"destination_net":"10.0.0.0/8","destination_port":"8080","description":"ci-update-<ts>-updated [opnsense-operator:default/ci-update-test]"}}' /api/firewall/filter/setRule/<uuid>
	//   hack/opnsense-curl.sh /api/firewall/filter/getRule/<uuid>
	// Real response: {"result":"saved"}; getRule returns updated fields
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ts := time.Now().UTC().Format("150405")
	initial := FirewallRule{
		Enabled:         true,
		Action:          "pass",
		Direction:       "in",
		IPProtocol:      "inet",
		Protocol:        "TCP",
		SourceNet:       "any",
		DestinationNet:  "192.168.1.0/24",
		DestinationPort: "443",
		Quick:           true,
		Description:     "ci-update-" + ts + " [opnsense-operator:default/ci-update-test]",
	}

	uuid, err := client.CreateRule(ctx, initial)
	if err != nil {
		t.Fatalf("CreateRule returned error: %v", err)
	}

	deleted := false
	defer func() {
		if deleted {
			return
		}

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()

		if err := client.DeleteRule(cleanupCtx, uuid); err == nil {
			_ = client.ApplyFirewallRules(cleanupCtx)
		}
	}()

	updated := initial
	updated.DestinationNet = "10.0.0.0/8"
	updated.DestinationPort = "8080"
	updated.Description = "ci-update-" + ts + "-updated [opnsense-operator:default/ci-update-test]"

	if err := client.UpdateRule(ctx, uuid, updated); err != nil {
		t.Fatalf("UpdateRule returned error: %v", err)
	}

	got, err := client.GetRule(ctx, uuid)
	if err != nil {
		t.Fatalf("GetRule after UpdateRule returned error: %v", err)
	}

	if got.DestinationNet != updated.DestinationNet {
		t.Errorf("DestinationNet: got %q, want %q", got.DestinationNet, updated.DestinationNet)
	}
	if got.DestinationPort != updated.DestinationPort {
		t.Errorf("DestinationPort: got %q, want %q", got.DestinationPort, updated.DestinationPort)
	}
	if got.Description != updated.Description {
		t.Errorf("Description: got %q, want %q", got.Description, updated.Description)
	}

	if err := client.DeleteRule(ctx, uuid); err != nil {
		t.Fatalf("delete rule returned error: %v", err)
	}
	deleted = true

	if err := client.ApplyFirewallRules(ctx); err != nil {
		t.Fatalf("apply returned error: %v", err)
	}
}

func TestDeleteRuleIntegration(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{}' /api/firewall/filter/delRule/<uuid>
	// Real response:
	//   {"result":"deleted"}
	// Not-found: hack/opnsense-curl.sh -X POST -d '{}' /api/firewall/filter/delRule/00000000-0000-0000-0000-000000000000
	// Real response:
	//   {"result":"not found"}
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	suffix := "ci-del-" + time.Now().UTC().Format("150405")
	uuid, err := client.CreateRule(ctx, FirewallRule{
		Enabled:        true,
		Action:         "pass",
		Direction:      "in",
		IPProtocol:     "inet",
		Protocol:       "any",
		SourceNet:      "any",
		DestinationNet: "any",
		Quick:          true,
		Description:    suffix + " [opnsense-operator:default/ci-del-test]",
	})
	if err != nil {
		t.Fatalf("CreateRule returned error: %v", err)
	}

	deleted := false
	defer func() {
		if deleted {
			return
		}

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()

		// ApplyFirewallRules is now available; use it for cleanup.
		if err := client.DeleteRule(cleanupCtx, uuid); err == nil {
			_ = client.ApplyFirewallRules(cleanupCtx)
		}
	}()

	if err := client.DeleteRule(ctx, uuid); err != nil {
		t.Fatalf("DeleteRule returned error: %v", err)
	}
	deleted = true

	if err := client.ApplyFirewallRules(ctx); err != nil {
		t.Fatalf("apply returned error: %v", err)
	}

	// delRule removes the rule from the config model immediately (before apply),
	// so GetRule must return ErrFirewallRuleNotFound right away.
	_, err = client.GetRule(ctx, uuid)
	if !errors.Is(err, ErrFirewallRuleNotFound) {
		t.Fatalf("expected ErrFirewallRuleNotFound after delete, got: %v", err)
	}
}

func TestApplyFirewallRulesIntegration(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{}' /api/firewall/filter/apply
	// Real response:
	//   {"status":"OK\n\n"}
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	suffix := "ci-apply-" + time.Now().UTC().Format("150405")
	uuid, err := client.CreateRule(ctx, FirewallRule{
		Enabled:        true,
		Action:         "pass",
		Direction:      "in",
		IPProtocol:     "inet",
		Protocol:       "any",
		SourceNet:      "any",
		DestinationNet: "any",
		Quick:          true,
		Description:    suffix + " [opnsense-operator:default/ci-apply-test]",
	})
	if err != nil {
		t.Fatalf("CreateRule returned error: %v", err)
	}

	deleted := false
	defer func() {
		if deleted {
			return
		}

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()

		if err := client.DeleteRule(cleanupCtx, uuid); err == nil {
			_ = client.ApplyFirewallRules(cleanupCtx)
		}
	}()

	if err := client.ApplyFirewallRules(ctx); err != nil {
		t.Fatalf("ApplyFirewallRules returned error: %v", err)
	}

	// Rule should be visible via search after apply.
	uuids, err := client.SearchRuleByManagedSuffix(ctx, "default/ci-apply-test")
	if err != nil {
		t.Fatalf("SearchRuleByManagedSuffix returned error: %v", err)
	}
	found := false
	for _, u := range uuids {
		if u == uuid {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected UUID %q in search results %v after apply", uuid, uuids)
	}

	if err := client.DeleteRule(ctx, uuid); err != nil {
		t.Fatalf("DeleteRule returned error: %v", err)
	}
	deleted = true

	if err := client.ApplyFirewallRules(ctx); err != nil {
		t.Fatalf("ApplyFirewallRules (cleanup) returned error: %v", err)
	}
}
