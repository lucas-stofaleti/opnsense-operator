---
name: opnsense-api
description: Verify and implement OPNsense REST API interactions. Use when adding or modifying any method in internal/opnsense/ that calls the OPNsense API.
compatibility: Requires OPNSENSE_BASE_URL, OPNSENSE_API_KEY, and OPNSENSE_API_SECRET to be set, and network access to the OPNsense VM.
---

# OPNsense API

## Workflow: always verify before implementing

Before writing any test or implementation for an OPNsense API endpoint:

1. Use `hack/opnsense-curl.sh` to send a real request against the local OPNsense VM
2. Capture the exact response shape — field names, types, nesting
3. Test the failure case too (missing resource, invalid input, not found)
4. Check whether a reconfigure/apply call is required after the operation
5. Document the curl command and real response as a comment above the test function

```bash
# GET
hack/opnsense-curl.sh /api/firewall/alias/getAliasUUID/myalias

# POST with inline JSON
hack/opnsense-curl.sh -X POST \
  -d '{"alias":{"name":"test","type":"host","content":"192.0.2.10"}}' \
  /api/firewall/alias/addItem
```

## Gotchas

- **HTTP 200 does not mean success.** OPNsense returns `{"result":"failed"}` (or similar) inside the body for errors. Always check the body, not just the status code.
- **Reconfigure is required after most create/update/delete operations.** Forgetting it means the change is staged but not applied to the running firewall.
- **Not-found responses vary by endpoint.** Some return `{"uuid":""}`, others return `{"result":"not found"}`. Verify the real shape before writing the not-found branch.
- **Use the official docs as a starting point only.** Always confirm behaviour with a real request — the docs are sometimes incomplete or wrong.

## Test comment format

Document the curl command and real response directly above the test:

```go
// $ hack/opnsense-curl.sh /api/firewall/alias/getAliasUUID/test
// {"uuid":"c6b50d57-b441-4217-a2d1-b81313887fdc"}
func TestGetAliasUUID(t *testing.T) {
    ...
}
```

## Implementation checklist

- [ ] Verified happy path response with real curl
- [ ] Verified failure/not-found response with real curl
- [ ] Confirmed whether reconfigure is required
- [ ] Mock HTTP server in unit test reflects real response shape
- [ ] Curl command and real response documented above the test

If you encounter non-standard status codes, unexpected response shapes, or need environment setup details, read [references/api-patterns.md](references/api-patterns.md).
