//go:build integration

package opnsense

import (
	"context"
	"testing"
	"time"
)

func TestCheckConnectivityIntegration(t *testing.T) {
	t.Parallel()

	// Verified with:
	//   hack/opnsense-curl.sh /api/core/system/status
	// Real response (HTTP 200):
	//   {"metadata":{"system":{"status":"ERROR","message":"No pending messages","title":"System"},...},"subsystems":{...}}
	// Note: the "status" field in the body reflects OPNsense system health, not API connectivity.
	// HTTP 200 + valid JSON is the only contract we enforce.
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := client.CheckConnectivity(ctx); err != nil {
		t.Fatalf("CheckConnectivity returned unexpected error: %v", err)
	}
}
