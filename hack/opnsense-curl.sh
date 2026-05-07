#!/usr/bin/env bash
set -euo pipefail

: "${OPNSENSE_BASE_URL:?must be set}"
: "${OPNSENSE_API_KEY:?must be set}"
: "${OPNSENSE_API_SECRET:?must be set}"

usage() {
  cat >&2 <<'EOF'
usage: opnsense-curl.sh [options] <api-path> [-- <extra curl args>]

Options:
  -X, --method METHOD       HTTP method to use (default: GET)
  -d, --data BODY           Inline request body
      --data-file FILE      Read request body from FILE
      --stdin-body          Read request body from stdin
  -H, --header HEADER       Extra header (repeatable)
  -q, --query KEY=VALUE     Query string entry (repeatable)
      --json                Send/expect JSON (default)
      --raw                 Do not add JSON headers automatically
  -i, --include             Include response headers
      --write-status        Append HTTP status to output
  -v, --verbose             Enable curl verbose output
  -h, --help                Show this help

Environment:
  OPNSENSE_BASE_URL         Base URL, e.g. https://opnsense.local
  OPNSENSE_API_KEY          API key
  OPNSENSE_API_SECRET       API secret
  OPNSENSE_INSECURE=true    Disable TLS verification for self-signed certs
  OPNSENSE_CA_CERT          CA bundle path for TLS verification

Examples:
  opnsense-curl.sh /api/firewall/alias/getAliasUUID/test
  opnsense-curl.sh -X POST -d '{"alias":{"name":"test"}}' /api/firewall/alias/addItem
  opnsense-curl.sh -X POST --data-file payload.json /api/firewall/alias/setItem
  printf '%s' '{"foo":"bar"}' | opnsense-curl.sh -X POST --stdin-body /api/core/firmware/check
  opnsense-curl.sh -q page=1 -q limit=10 /api/some/endpoint -- --max-time 10
EOF
}

method="GET"
path=""
body=""
json_mode=true
write_status=false

declare -a curl_args=()
declare -a extra_headers=()
declare -a queries=()
declare -a trailing_args=()

while (($# > 0)); do
  case "$1" in
    -X|--method)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; usage; exit 1; }
      method="$2"
      shift 2
      ;;
    -d|--data)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; usage; exit 1; }
      body="$2"
      shift 2
      ;;
    --data-file)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; usage; exit 1; }
      body="@$2"
      shift 2
      ;;
    --stdin-body)
      body="@-"
      shift
      ;;
    -H|--header)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; usage; exit 1; }
      extra_headers+=("$2")
      shift 2
      ;;
    -q|--query)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; usage; exit 1; }
      queries+=("$2")
      shift 2
      ;;
    --json)
      json_mode=true
      shift
      ;;
    --raw)
      json_mode=false
      shift
      ;;
    -i|--include)
      curl_args+=(--include)
      shift
      ;;
    --write-status)
      write_status=true
      shift
      ;;
    -v|--verbose)
      curl_args+=(--verbose)
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      trailing_args+=("$@")
      break
      ;;
    -*)
      echo "unknown option: $1" >&2
      usage
      exit 1
      ;;
    *)
      if [[ -n "${path}" ]]; then
        echo "unexpected extra argument: $1" >&2
        usage
        exit 1
      fi
      path="$1"
      shift
      ;;
  esac
done

if [[ -z "${path}" ]]; then
  usage
  exit 1
fi

if [[ "${path}" != /* ]]; then
  path="/${path}"
fi

url="${OPNSENSE_BASE_URL%/}${path}"
if ((${#queries[@]} > 0)); then
  separator="?"
  for query in "${queries[@]}"; do
    url+="${separator}${query}"
    separator="&"
  done
fi

curl_args+=(
  --silent
  --show-error
  --fail-with-body
  --request "${method}"
  --user "${OPNSENSE_API_KEY}:${OPNSENSE_API_SECRET}"
)

if [[ "${OPNSENSE_INSECURE:-}" == "true" ]]; then
  curl_args+=(-k)
fi

if [[ -n "${OPNSENSE_CA_CERT:-}" ]]; then
  curl_args+=(--cacert "${OPNSENSE_CA_CERT}")
fi

if [[ "${json_mode}" == "true" ]]; then
  curl_args+=(
    --header "Accept: application/json"
  )
  if [[ -n "${body}" ]]; then
    curl_args+=(--header "Content-Type: application/json")
  fi
fi

for header in "${extra_headers[@]}"; do
  curl_args+=(--header "${header}")
done

if [[ -n "${body}" ]]; then
  curl_args+=(--data "${body}")
fi

if [[ "${write_status}" == "true" ]]; then
  curl_args+=(--write-out $'\nHTTP_STATUS:%{http_code}\n')
fi

curl "${curl_args[@]}" "${trailing_args[@]}" "${url}"
