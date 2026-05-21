# OPNsense API Patterns

## Environment setup

```bash
export OPNSENSE_BASE_URL=https://192.168.1.1
export OPNSENSE_API_KEY=your-key
export OPNSENSE_API_SECRET=your-secret
export OPNSENSE_INSECURE=true    # for self-signed TLS
# or: export OPNSENSE_CA_CERT=/path/to/ca.pem
```

## hack/opnsense-curl.sh usage

```bash
# GET
hack/opnsense-curl.sh /api/firewall/alias/getAliasUUID/myalias

# POST with inline body
hack/opnsense-curl.sh -X POST \
  -d '{"alias":{"name":"test","type":"host","content":"192.0.2.10"}}' \
  /api/firewall/alias/addItem

# POST with body file
hack/opnsense-curl.sh -X POST --body-file payload.json /api/firewall/alias/addItem

# POST from stdin
echo '{"alias":{...}}' | hack/opnsense-curl.sh -X POST /api/firewall/alias/addItem

# DELETE
hack/opnsense-curl.sh -X DELETE /api/firewall/alias/delItem/<uuid>

# Custom headers, query strings, pass-through curl flags
hack/opnsense-curl.sh -H "X-Custom: value" /api/... -- --max-time 5
```

## Common response shapes

### Success (create/update)
```json
{"result": "saved", "uuid": "c6b50d57-b441-4217-a2d1-b81313887fdc"}
```

### Success (delete)
```json
{"result": "deleted"}
```

### Success (reconfigure/apply)
```json
{"status": 0, "message": "OK"}
```

### Failure (HTTP 200, body-level error)
```json
{"result": "failed"}
{"validations": {"name": ["name is required"]}}
```

### Not found (varies by endpoint — verify which applies)
```json
{"uuid": ""}
{"result": "not found"}
```

## Alias API examples

```bash
# Get UUID by name
hack/opnsense-curl.sh /api/firewall/alias/getAliasUUID/myalias
# {"uuid":"c6b50d57-b441-4217-a2d1-b81313887fdc"}

# Get alias details
hack/opnsense-curl.sh /api/firewall/alias/getItem/c6b50d57-b441-4217-a2d1-b81313887fdc

# Create alias
hack/opnsense-curl.sh -X POST \
  -d '{"alias":{"name":"test","type":"host","description":"","content":"192.0.2.10\n10.0.0.1"}}' \
  /api/firewall/alias/addItem

# Update alias
hack/opnsense-curl.sh -X POST \
  -d '{"alias":{"name":"test","type":"host","content":"192.0.2.10"}}' \
  /api/firewall/alias/setItem/<uuid>

# Delete alias
hack/opnsense-curl.sh -X POST /api/firewall/alias/delItem/<uuid>

# Apply changes (required after create/update/delete)
hack/opnsense-curl.sh -X POST /api/firewall/alias/reconfigure
```
