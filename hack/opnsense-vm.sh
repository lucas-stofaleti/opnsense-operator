#!/usr/bin/env bash
#
# Boot an OPNsense VM headlessly and print the environment the integration
# tests expect. Phase 0b of the version-compatibility plan.
#
# Runs QEMU inside a container so no host packages (and no sudo) are needed.
# KVM is used when /dev/kvm is available and falls back to software emulation.
#
# usage: hack/opnsense-vm.sh up <series>      # e.g. 26.7, 26.1, 25.7
#        hack/opnsense-vm.sh down <series>
#        hack/opnsense-vm.sh env <series>
#
set -euo pipefail

MIRROR="${OPNSENSE_MIRROR:-https://mirror.ams1.nl.leaseweb.net/opnsense/releases}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${OPNSENSE_VM_DIR:-$REPO_ROOT/.opnsense-vm}"
TOOLBOX_IMAGE="opnsense-vm-toolbox:latest"

# OPNsense's default LAN address. Aligning slirp's subnet with it means the
# guest needs no network reconfiguration to be reachable from the host.
GUEST_LAN_IP="192.168.1.1"
SLIRP_NET="192.168.1.0/24"
SLIRP_HOST="192.168.1.2"

log()  { printf '[opnsense-vm] %s\n' "$*" >&2; }
fail() { printf '[opnsense-vm] ERROR: %s\n' "$*" >&2; exit 1; }

container_name() { printf 'opnsense-vm-%s' "${1//./-}"; }

# Host port for a series, so several VMs can run side by side in the matrix.
host_port() {
  case "$1" in
    26.7) echo 18443 ;;
    26.1) echo 18444 ;;
    25.7) echo 18445 ;;
    *)    fail "unknown series '$1' (expected 26.7, 26.1 or 25.7)" ;;
  esac
}

build_toolbox() {
  if ! docker image inspect "$TOOLBOX_IMAGE" >/dev/null 2>&1; then
    log "building QEMU toolbox image"
    docker build -q -t "$TOOLBOX_IMAGE" "$REPO_ROOT/hack/opnsense-vm/" >/dev/null
  fi
}

# Download the nano image and verify it against the published checksum.
# Nano is the only image type that is pre-installed; the others boot an
# installer that would have to be driven interactively.
fetch_image() {
  local series="$1"
  local img="OPNsense-${series}-nano-amd64.img"
  local archive="${img}.bz2"

  mkdir -p "$WORK_DIR"
  cd "$WORK_DIR"

  if [[ ! -f "$archive" ]]; then
    log "downloading $archive"
    curl -fsSL --retry 3 -o "${archive}.part" "$MIRROR/$series/$archive"
    mv "${archive}.part" "$archive"
  fi

  log "verifying checksum"
  curl -fsSL -o "checksums-${series}.sha256" "$MIRROR/$series/OPNsense-${series}-checksums-amd64.sha256"
  local want have
  want="$(awk -v f="($archive)" '$2 == f {print $4}' "checksums-${series}.sha256")"
  [[ -n "$want" ]] || fail "no published checksum for $archive"
  have="$(sha256sum "$archive" | cut -d' ' -f1)"
  [[ "$want" == "$have" ]] || fail "checksum mismatch for $archive (want $want, got $have)"

  # Decompress fully before anything reads the file. A partially written image
  # produces a mangled UFS that looks like disk corruption at boot.
  if [[ ! -f "$img" ]] || [[ "$archive" -nt "$img" ]]; then
    log "decompressing (this takes a moment)"
    bunzip2 -kf "$archive"
    [[ -f "$img" ]] || fail "decompression produced no image"
  fi

  printf '%s' "$img"
}

accel_flag() {
  if [[ -e /dev/kvm ]]; then echo "kvm"; else
    log "WARNING: /dev/kvm absent, falling back to software emulation (slow)"
    echo "tcg"
  fi
}

cmd_up() {
  local series="$1"
  local name port img accel
  name="$(container_name "$series")"
  port="$(host_port "$series")"

  build_toolbox
  img="$(fetch_image "$series")"
  cd "$WORK_DIR"

  if docker ps --filter "name=^${name}$" --format '{{.Names}}' | grep -q .; then
    log "$name already running"
    cmd_env "$series"
    return 0
  fi

  # A qcow2 overlay keeps the downloaded image pristine across runs, and
  # growing it to 8G lets the nano root filesystem resize itself on first boot.
  local overlay="disk-${series}.qcow2"
  local serial="serial-${series}.log"
  rm -f "$overlay"
  docker run --rm -v "$WORK_DIR:/vm" "$TOOLBOX_IMAGE" \
    qemu-img create -f qcow2 -F raw -b "$img" "$overlay" 8G >/dev/null

  : > "$serial"; chmod 666 "$serial"

  accel="$(accel_flag)"
  local kvm_args=()
  [[ "$accel" == "kvm" ]] && kvm_args=(--device /dev/kvm)

  log "booting $series (accel=$accel, host port $port)"
  docker run -d --rm --name "$name" "${kvm_args[@]}" \
    -v "$WORK_DIR:/vm" --network host \
    "$TOOLBOX_IMAGE" \
    qemu-system-x86_64 \
      -accel "$accel" -m 2048 -smp 2 \
      -drive "file=/vm/${overlay},format=qcow2,if=ide" \
      -display none -serial "file:/vm/${serial}" \
      -netdev "user,id=lan,net=${SLIRP_NET},host=${SLIRP_HOST},hostfwd=tcp:127.0.0.1:${port}-${GUEST_LAN_IP}:443" \
      -device e1000,netdev=lan \
      >/dev/null

  log "waiting for the web GUI (first boot runs the installer scripts)"
  local waited=0 timeout=600
  until curl -sk --max-time 4 -o /dev/null "https://127.0.0.1:${port}/" 2>/dev/null; do
    if ! docker ps --filter "name=^${name}$" --format '{{.Names}}' | grep -q .; then
      log "--- last serial output ---"; tail -40 "$serial" >&2 || true
      fail "VM exited during boot"
    fi
    (( waited += 5 ))
    (( waited > timeout )) && { log "--- last serial output ---"; tail -40 "$serial" >&2; fail "timed out after ${timeout}s"; }
    sleep 5
  done
  log "GUI reachable after ${waited}s"

  cmd_env "$series"
}

cmd_down() {
  local name; name="$(container_name "$1")"
  docker rm -f "$name" >/dev/null 2>&1 || true
  log "stopped $name"
}

# Mint an API key through the web GUI's own session, which avoids driving the
# serial console entirely. addApiKey returns the plaintext secret exactly once.
mint_api_key() {
  local port="$1"
  local base="https://127.0.0.1:${port}"
  local jar; jar="$(mktemp)"
  trap 'rm -f "$jar"' RETURN

  local page token
  page="$(curl -sk -c "$jar" --max-time 20 "$base/")"
  token="$(printf '%s' "$page" | grep -oE '<input[^>]*type="hidden"[^>]*>' | head -1 \
           | grep -oE 'value="[^"]+"' | head -1 | sed 's/value="//;s/"$//')"
  local tname
  tname="$(printf '%s' "$page" | grep -oE '<input[^>]*type="hidden"[^>]*name="[^"]+"' | head -1 \
           | grep -oE 'name="[^"]+"' | sed 's/name="//;s/"$//')"
  [[ -n "$token" && -n "$tname" ]] || fail "could not read the login CSRF token"

  curl -sk -b "$jar" -c "$jar" --max-time 25 -o /dev/null \
    -d "$tname=$token" -d "usernamefld=root" -d "passwordfld=opnsense" -d "login=1" \
    "$base/index.php"

  # A fresh token is needed for the API call; the login rotated it.
  local token2
  token2="$(curl -sk -b "$jar" -c "$jar" --max-time 20 "$base/index.php" \
            | grep -oE '<input[^>]*type="hidden"[^>]*>' | head -1 \
            | grep -oE 'value="[^"]+"' | head -1 | sed 's/value="//;s/"$//')"
  [[ -n "$token2" ]] || fail "login failed (default credentials root/opnsense rejected?)"

  curl -sk -b "$jar" --max-time 30 -X POST \
    -H "X-CSRFToken: $token2" -H "Content-Type: application/json" -d '{}' \
    "$base/api/auth/user/addApiKey/root"
}

# Bring the VM to the latest point release of its series.
#
# This matters: base images are not what anyone runs. OPNsense 26.1.0 returns
# only floating rules when searchRule is called without an interface parameter,
# a behaviour changed by 26.1.2 -- testing the base image would mean chasing
# bugs no supported version has.
update_to_series_latest() {
  local port="$1" key="$2" secret="$3"
  local base="https://127.0.0.1:${port}"
  local auth=(-sk -u "${key}:${secret}" --max-time 120)

  log "checking for updates"
  curl "${auth[@]}" -X POST "$base/api/core/firmware/check" >/dev/null || true

  # check runs in the backend; give it a moment to populate status.
  local waited=0
  while (( waited < 120 )); do
    local st
    st="$(curl "${auth[@]}" "$base/api/core/firmware/status" \
          | python3 -c 'import sys,json;print(json.load(sys.stdin).get("status",""))' 2>/dev/null || echo "")"
    [[ "$st" == "update" || "$st" == "upgrade" ]] && break
    [[ "$st" == "none" ]] && { log "already at series-latest"; return 0; }
    sleep 5; (( waited += 5 ))
  done

  log "applying updates"
  curl "${auth[@]}" -X POST "$base/api/core/firmware/update" >/dev/null || true

  # The update may reboot the VM; poll until the GUI answers again.
  waited=0
  local timeout=1200
  while (( waited < timeout )); do
    local st
    st="$(curl "${auth[@]}" "$base/api/core/firmware/upgradestatus" \
          | python3 -c 'import sys,json;print(json.load(sys.stdin).get("status",""))' 2>/dev/null || echo "unreachable")"
    case "$st" in
      done) log "update finished"; break ;;
      reboot) log "guest is rebooting" ;;
    esac
    sleep 10; (( waited += 10 ))
  done

  log "waiting for the GUI after update"
  waited=0
  until curl -sk --max-time 5 -o /dev/null "$base/" 2>/dev/null; do
    sleep 5; (( waited += 5 ))
    (( waited > 600 )) && fail "GUI did not return after update"
  done
}

cmd_env() {
  local series="$1"
  local port; port="$(host_port "$series")"
  local creds key secret

  creds="$(mint_api_key "$port")"
  key="$(printf '%s' "$creds" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("key",""))')"
  secret="$(printf '%s' "$creds" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("secret",""))')"
  [[ -n "$key" && -n "$secret" ]] || fail "API key creation failed: $creds"

  # Opt-in until the guest has a default route. The VM currently has only a
  # static LAN address, so the update mirrors are unreachable. See the plan's
  # "series-latest" gap.
  if [[ "${OPNSENSE_UPDATE:-}" == "true" ]]; then
    update_to_series_latest "$port" "$key" "$secret"
  fi

  cat <<EOF
export OPNSENSE_BASE_URL=https://127.0.0.1:${port}
export OPNSENSE_API_KEY='${key}'
export OPNSENSE_API_SECRET='${secret}'
export OPNSENSE_INSECURE=true
EOF
}

main() {
  [[ $# -ge 2 ]] || fail "usage: $0 {up|down|env} <series>"
  command -v docker >/dev/null || fail "docker is required"
  case "$1" in
    up)   cmd_up   "$2" ;;
    down) cmd_down "$2" ;;
    env)  cmd_env  "$2" ;;
    *)    fail "unknown command '$1'" ;;
  esac
}

main "$@"
