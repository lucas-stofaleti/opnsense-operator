# OPNsense Firewall Filter API — Implementation Spec

Compact reference for implementing `internal/opnsense/` client functions.
All findings are based on live requests against a real OPNsense instance.
Full raw transcripts with every response body are in `docs/opnsense-filter-api-evidence.md`.

---

## Endpoints used by the operator

| Method | Path | Purpose | Apply needed? |
|--------|------|---------|---------------|
| POST | `/api/firewall/filter/addRule` | Create a rule | Yes |
| GET | `/api/firewall/filter/getRule/{uuid}` | Fetch rule by UUID | No |
| POST | `/api/firewall/filter/setRule/{uuid}` | Update rule (partial payload OK) | Yes |
| POST | `/api/firewall/filter/delRule/{uuid}` | Delete a rule | Yes |
| GET | `/api/firewall/filter/searchRule` | Search rules by phrase (used for fallback lookup) | No |
| POST | `/api/firewall/filter/apply` | Push staged config to live firewall | — |

All other endpoints (`savepoint`, `cancelRollback`, `toggleRule`, `moveRuleBefore`, etc.)
are not needed for the initial implementation and are documented in the evidence file.

---

## Request format

Every write call (`addRule`, `setRule`) wraps fields in a top-level `rule` object:

```json
{
  "rule": {
    "description": "Allow HTTPS [opnsense-operator:default/allow-https]",
    "action": "pass",
    "interface": "lan",
    "direction": "in",
    "ipprotocol": "inet",
    "protocol": "TCP",
    "source_net": "any",
    "destination_net": "192.168.1.10/32",
    "destination_port": "443",
    "enabled": "1",
    "log": "0",
    "quick": "1"
  }
}
```

`delRule` and `getRule` take no body — only the UUID in the path.
`apply` takes an empty body `{}`.

---

## Rule fields (operator-relevant subset)

All fields are optional. OPNsense applies defaults when omitted.

| Field | JSON type | Allowed values | Default | Notes |
|-------|-----------|----------------|---------|-------|
| `enabled` | string | `"0"`, `"1"` | `"1"` | Bool encoded as string |
| `action` | string | `"pass"`, `"block"`, `"reject"` | `"pass"` | Invalid value → validation error |
| `quick` | string | `"0"`, `"1"` | `"1"` | First-match wins when `"1"` |
| `interface` | string | `"lan"`, `"wan"`, `"opt1"`, group names, `""` | `""` | Empty = floating rule (prio 200000); named = interface rule (prio 400000) |
| `interfacenot` | string | `"0"`, `"1"` | `"0"` | Invert interface match |
| `direction` | string | `"in"`, `"out"`, `"any"` | `"in"` | Invalid value → validation error |
| `ipprotocol` | string | `"inet"`, `"inet6"`, `"inet46"` | `"inet"` | |
| `protocol` | string | `"any"`, `"TCP"`, `"UDP"`, `"TCP/UDP"`, `"ICMP"`, and many others | `"any"` | Invalid value → validation error |
| `source_net` | string | CIDR, alias name, `"any"` | `"any"` | Alias names accepted directly |
| `source_not` | string | `"0"`, `"1"` | `"0"` | Invert source match |
| `source_port` | string | port number, range (e.g. `"8080:8090"`), or `""` | `""` | |
| `destination_net` | string | CIDR, alias name, `"any"` | `"any"` | |
| `destination_not` | string | `"0"`, `"1"` | `"0"` | |
| `destination_port` | string | port number, range, or `""` | `""` | |
| `sequence` | string | numeric string | auto-assigned | Not unique; duplicates accepted; stored and returned as string |
| `log` | string | `"0"`, `"1"` | `"0"` | |
| `description` | string | free-form | `""` | Max 255 chars. Special chars `/`, `"`, `<`, `>`, `[`, `]` accepted |

Fields not in this table (state options, TCP flags, shaping, etc.) are rarely needed
and documented fully in the evidence file's schema table.

---

## Response shapes

### addRule — success
```json
{"result": "saved", "uuid": "<uuid>"}
```

### addRule — validation error
```json
{"result": "failed", "validations": {"rule.action": "Option [] not in list."}}
```

### addRule — missing rule wrapper (empty payload `{}`)
```json
{"result": "failed"}
```
Note: no `validations` key present. Distinct from a field-level validation failure.

### setRule — success
```json
{"result": "saved"}
```
No UUID returned (it was already known).

### getRule/{uuid} — success
Returns the full rule model as a nested object with select options.
The operator only needs the flat fields; use a flat struct for decoding.
Key read-back fields: `uuid`, `enabled`, `action`, `interface`, `direction`,
`ipprotocol`, `protocol`, `source_net`, `source_not`, `source_port`,
`destination_net`, `destination_not`, `destination_port`, `sequence`,
`log`, `quick`, `description`, `prio_group`, `sort_order`.

### getRule/{uuid} — not found
```json
[]
```
A bare JSON array, not an object. Detect with `bytes.TrimSpace(body)[0] == '['`.

### delRule/{uuid} — success
```json
{"result": "deleted"}
```

### delRule/{uuid} — not found
```json
{"result": "not found"}
```

### apply — success (always identical, even with nothing pending)
```json
{"status": "OK\n\n"}
```
**Check with `strings.TrimSpace(response.Status) == "OK"`** — the raw value contains
trailing newlines. Note: alias `ReconfigureAliases` checks for lowercase `"ok"`;
filter `apply` returns uppercase `"OK"`. These are different endpoints.

### searchRule — success
```json
{
  "total": 1,
  "rowCount": 1,
  "current": 1,
  "rows": [
    {
      "uuid": "<uuid>",
      "enabled": "1",
      "sequence": "2500",
      "sort_order": "200000.0002500",
      "prio_group": "200000",
      "action": "pass",
      "interface": "",
      "direction": "in",
      "ipprotocol": "inet",
      "protocol": "any",
      "source_net": "any",
      "source_not": "0",
      "source_port": "",
      "destination_net": "any",
      "destination_not": "0",
      "destination_port": "",
      "quick": "1",
      "log": "0",
      "description": "Allow HTTPS [opnsense-operator:default/allow-https]"
    }
  ]
}
```

### searchRule — no match
```json
{"total": 0, "rowCount": 0, "current": 1, "rows": []}
```

### Wrong credentials (any endpoint)
HTTP 401, body:
```json
{"status": 401, "message": "Authentication Failed"}
```
curl exits with code 22 through the helper script.

---

## Rule scope — how `interface` controls priority

| `interface` value | Scope | `prio_group` in response |
|-------------------|-------|--------------------------|
| `""` (empty) | Floating rule | `"200000"` |
| group name (e.g. `"testgroup"`) | Group rule | `"300000"` |
| interface name (e.g. `"lan"`) | Interface rule | `"400000"` |

Lower `prio_group` = processed first = wins when `quick: "1"`.
`sort_order` format: `"<prio_group>.<sequence_padded>"`, e.g. `"200000.0002500"`.

---

## Managed suffix — fallback lookup

The operator appends `[opnsense-operator:<namespace>/<name>]` to the user's description
before sending to OPNsense. On fallback (stale/missing UUID in status), the operator
calls `searchRule?searchPhrase=<namespace>/<name>` to find the rule.

**Observed search behaviour:**
- Case-insensitive substring match
- `searchPhrase=default/allow-https` finds `"Allow HTTPS [opnsense-operator:default/allow-https]"`
- Can return multiple rows if different rules share the same substring
- The operator must handle 0, 1, or N results:
  - 0 → rule does not exist, create it
  - 1 → rule found, adopt UUID
  - N → ambiguous; treat as an error (log warning, set Ready=False)

**Description length constraint:** max 255 chars total (including the suffix).
The suffix `[opnsense-operator:namespace/name]` is ~35–50 chars depending on names.
Validate in the webhook: `len(spec.description) + len(suffix) <= 255`.

---

## Apply behaviour

- Call `POST /api/firewall/filter/apply` with body `{}` after every `addRule`, `setRule`, `delRule`.
- Response is always `{"status":"OK\n\n"}` regardless of whether anything was pending.
- `delRule` removes the rule from the config model immediately (getRule returns `[]`
  before apply). Apply is still required to remove it from the live running firewall.
- The savepoint/auto-rollback mechanism was unreliable in testing — do not rely on it.
  Defer savepoint support to a future version.

---

## Partial update behaviour

`setRule` accepts partial payloads. Omitted fields are preserved as-is.
Confirmed: sending only `{"rule":{"sequence":"100"}}` updated the sequence
and left all other fields unchanged.

---

## Duplicate rules

OPNsense accepts identical payloads submitted twice — it creates two separate rules
with different UUIDs. There is no uniqueness constraint on any field.
The managed suffix is the only mechanism preventing duplicates.

---

## Go implementation notes

- All bool fields are encoded as `"0"`/`"1"` strings in both requests and responses.
- `sequence` is always a JSON string, not a number.
- HTTP status is always 200 for all outcomes (success, not found, validation failure).
  Detect errors entirely from the response body.
- The `validations` key is absent when the payload is structurally invalid (missing
  `rule` wrapper). Always check `result == "failed"` first, then optionally inspect
  `validations`.
- Use `errors.Is` with sentinel errors (`ErrFirewallRuleNotFound`, `ErrValidationFailed`,
  `ErrUnexpectedResponse`) — same pattern as the existing alias client.
- `getRule` not-found is a bare `[]` array — detect with a leading `[` byte check,
  same pattern as `GetAlias` in the existing client.
- The `%action`, `%direction`, `%statetype` fields in `searchRule` rows are
  human-readable labels (e.g. `"%action":"Pass"`). Ignore them; use the raw field.
