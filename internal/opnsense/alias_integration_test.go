//go:build integration

package opnsense

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestAliasLifecycleIntegration(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh /api/firewall/alias/getAliasUUID/test
	//   hack/opnsense-curl.sh -X POST -d '{"alias":{"enabled":"1","name":"ca1778237031","type":"host","content":"198.51.100.10\n198.51.100.11","description":"created by probe"}}' /api/firewall/alias/addItem
	//   hack/opnsense-curl.sh -X POST -d '{"alias":{"enabled":"1","name":"ca1778237031","type":"host","content":"203.0.113.10","description":"updated by probe"}}' /api/firewall/alias/setItem/514ae60a-a270-47df-afdd-b9cdc6fb5c7f
	//   hack/opnsense-curl.sh -X POST -d '{}' /api/firewall/alias/reconfigure
	//   hack/opnsense-curl.sh -X POST -d '{}' /api/firewall/alias/delItem/514ae60a-a270-47df-afdd-b9cdc6fb5c7f
	// Real responses:
	//   {"uuid":"c6b50d57-b441-4217-a2d1-b81313887fdc"}
	//   {"result":"saved","uuid":"514ae60a-a270-47df-afdd-b9cdc6fb5c7f"}
	//   {"result":"saved"}
	//   {"status":"ok"}
	//   {"result":"deleted"}
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	aliasName := "ci" + time.Now().UTC().Format("150405")
	created := Alias{
		Enabled:     true,
		Name:        aliasName,
		Type:        "host",
		Content:     "198.51.100.10\n198.51.100.11",
		Description: "created by integration test",
	}

	uuid, err := client.CreateAlias(ctx, created)
	if err != nil {
		t.Fatalf("CreateAlias returned error: %v", err)
	}

	deleted := false
	defer func() {
		if deleted {
			return
		}

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()

		if err := client.DeleteAlias(cleanupCtx, uuid); err == nil {
			_ = client.ReconfigureAliases(cleanupCtx)
		}
	}()

	lookedUpUUID, err := client.GetAliasUUIDByName(ctx, aliasName)
	if err != nil {
		t.Fatalf("GetAliasUUIDByName returned error: %v", err)
	}
	if lookedUpUUID != uuid {
		t.Fatalf("expected looked up uuid %q to match created uuid %q", lookedUpUUID, uuid)
	}

	_, err = client.CreateAlias(ctx, created)
	if err == nil {
		t.Fatal("expected duplicate alias name to return a validation error")
	}

	var validationErr *ValidationError
	if !AsValidationError(err, &validationErr) {
		t.Fatalf("expected ValidationError, got %T", err)
	}
	if validationErr.FieldErrors["alias.name"] == "" {
		t.Fatalf("expected alias.name validation error, got %#v", validationErr.FieldErrors)
	}

	if err := client.UpdateAlias(ctx, uuid, Alias{
		Enabled:     true,
		Name:        aliasName,
		Type:        "host",
		Content:     "203.0.113.10",
		Description: "updated by integration test",
	}); err != nil {
		t.Fatalf("UpdateAlias returned error: %v", err)
	}

	if err := client.ReconfigureAliases(ctx); err != nil {
		t.Fatalf("ReconfigureAliases returned error: %v", err)
	}

	if err := client.DeleteAlias(ctx, uuid); err != nil {
		t.Fatalf("DeleteAlias returned error: %v", err)
	}
	deleted = true

	if err := client.ReconfigureAliases(ctx); err != nil {
		t.Fatalf("ReconfigureAliases after delete returned error: %v", err)
	}

	_, err = client.GetAliasUUIDByName(ctx, aliasName)
	if !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("expected ErrAliasNotFound after delete, got %v", err)
	}
}

func TestAliasMissingResourceIntegration(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{"alias":{"enabled":"1","name":"missinguuid","type":"host","content":"198.51.100.50","description":"missing uuid probe"}}' /api/firewall/alias/setItem/11111111-1111-1111-1111-111111111111
	//   hack/opnsense-curl.sh -X POST -d '{}' /api/firewall/alias/delItem/11111111-1111-1111-1111-111111111111
	// Real responses:
	//   {"result":"failed"}
	//   {"result":"not found"}
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	err := client.UpdateAlias(ctx, "11111111-1111-1111-1111-111111111111", Alias{
		Enabled:     true,
		Name:        "missinguuid",
		Type:        "host",
		Content:     "198.51.100.50",
		Description: "missing uuid probe",
	})
	if !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("expected ErrAliasNotFound from update missing alias, got %v", err)
	}

	err = client.DeleteAlias(ctx, "11111111-1111-1111-1111-111111111111")
	if !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("expected ErrAliasNotFound from delete missing alias, got %v", err)
	}
}

func TestAliasAllowsNonIPHostContentIntegration(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh -X POST -d '{"alias":{"enabled":"1","name":"ciinvalid","type":"host","content":"not-an-ip","description":"invalid content probe"}}' /api/firewall/alias/addItem
	//   hack/opnsense-curl.sh -X POST -d '{}' /api/firewall/alias/reconfigure
	// Real responses:
	//   {"result":"saved","uuid":"247fc267-9615-4641-9460-3a208214ab53"}
	//   {"status":"ok"}
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	aliasName := "ciinvalid" + time.Now().UTC().Format("150405")
	uuid, err := client.CreateAlias(ctx, Alias{
		Enabled:     true,
		Name:        aliasName,
		Type:        "host",
		Content:     "not-an-ip",
		Description: "invalid content probe",
	})
	if err != nil {
		t.Fatalf("CreateAlias returned error: %v", err)
	}

	deleted := false
	defer func() {
		if deleted {
			return
		}

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()

		if err := client.DeleteAlias(cleanupCtx, uuid); err == nil {
			_ = client.ReconfigureAliases(cleanupCtx)
		}
	}()

	if err := client.ReconfigureAliases(ctx); err != nil {
		t.Fatalf("ReconfigureAliases returned error: %v", err)
	}

	lookedUpUUID, err := client.GetAliasUUIDByName(ctx, aliasName)
	if err != nil {
		t.Fatalf("GetAliasUUIDByName returned error: %v", err)
	}
	if lookedUpUUID != uuid {
		t.Fatalf("expected looked up uuid %q to match created uuid %q", lookedUpUUID, uuid)
	}

	if err := client.DeleteAlias(ctx, uuid); err != nil {
		t.Fatalf("DeleteAlias returned error: %v", err)
	}
	deleted = true

	if err := client.ReconfigureAliases(ctx); err != nil {
		t.Fatalf("ReconfigureAliases after delete returned error: %v", err)
	}
}

func newIntegrationClient(t *testing.T) *Client {
	t.Helper()

	baseURL := os.Getenv("OPNSENSE_BASE_URL")
	apiKey := os.Getenv("OPNSENSE_API_KEY")
	apiSecret := os.Getenv("OPNSENSE_API_SECRET")
	if baseURL == "" || apiKey == "" || apiSecret == "" {
		t.Skip("OPNSENSE_BASE_URL, OPNSENSE_API_KEY, and OPNSENSE_API_SECRET must be set")
	}

	tlsConfig := &tls.Config{}
	if os.Getenv("OPNSENSE_INSECURE") == "true" {
		tlsConfig.InsecureSkipVerify = true
	}

	if caCertPath := os.Getenv("OPNSENSE_CA_CERT"); caCertPath != "" {
		caBundle, err := os.ReadFile(caCertPath)
		if err != nil {
			t.Fatalf("read OPNSENSE_CA_CERT: %v", err)
		}

		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(caBundle) {
			t.Fatal("append OPNSENSE_CA_CERT: no certificates were loaded")
		}
	}

	return NewClient(baseURL, apiKey, apiSecret, &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	})
}
