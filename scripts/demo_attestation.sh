#!/usr/bin/env bash
# ============================================================================
# demo_attestation.sh — Cryptographic Governance Attestation Demo (§3.1)
#
# End-to-end demo: real puzzled, real sandbox, real attestation, real verification.
#
# What this script does:
#   1. Ensures puzzled is set up and running (via dev-setup.sh)
#   2. Creates a branch, runs an agent, commits — real governance runs
#   3. Exports the Ed25519 public key
#   4. Runs puzzlectl attestation verify (third-party verification)
#
# If puzzled/D-Bus is not available, falls back to puzzle-phase2-demo which exercises
# the same attestation code path without the sandbox/D-Bus layer.
#
# Prerequisites:
#   - Linux (Lima VM on macOS)
#   - Root privileges
#   - Run 'sudo scripts/dev-setup.sh setup' at least once
#
# Usage:
#   sudo ./scripts/demo_attestation.sh           # Full end-to-end
#   ./scripts/demo_attestation.sh --standalone    # No puzzled needed
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

STARTED_PUZZLED=false

cleanup() {
    if $STARTED_PUZZLED; then
        echo -e "\n${CYAN}--- Stopping puzzled ---${RESET}"
        "$SCRIPT_DIR/dev-setup.sh" stop 2>/dev/null || true
    fi
    if [[ -n "${DEMO_DIR:-}" && -d "${DEMO_DIR:-}" ]]; then
        rm -rf "$DEMO_DIR"
    fi
}
trap cleanup EXIT

step() {
    echo -e "\n${BOLD}${CYAN}=== $1 ===${RESET}\n"
}

ok()   { echo -e "  ${GREEN}\u2713${RESET} $1"; }
info() { echo -e "  ${DIM}\u25b8${RESET} $1"; }
warn() { echo -e "  ${YELLOW}!${RESET} $1"; }
fail() { echo -e "  ${RED}\u2717${RESET} $1"; }

# ── Find binaries ──────────────────────────────────────────────────────────

PUZZLED=""
PUZZLECTL=""
PHASE2_DEMO=""
for dir in "/var/tmp/puzzlepod-target/debug" "/var/tmp/puzzlepod-target/release" "${CARGO_TARGET_DIR:-$REPO_DIR/target}/debug" "${CARGO_TARGET_DIR:-$REPO_DIR/target}/release" "$REPO_DIR/target/debug" "$REPO_DIR/target/release"; do
    if [[ -z "$PUZZLED" && -x "$dir/puzzled" ]]; then PUZZLED="$dir/puzzled"; fi
    if [[ -z "$PUZZLECTL" && -x "$dir/puzzlectl" ]]; then PUZZLECTL="$dir/puzzlectl"; fi
    if [[ -z "$PHASE2_DEMO" && -x "$dir/puzzle-phase2-demo" ]]; then PHASE2_DEMO="$dir/puzzle-phase2-demo"; fi
done

# ── Mode selection ─────────────────────────────────────────────────────────

STANDALONE=false
if [[ "${1:-}" == "--standalone" ]]; then
    STANDALONE=true
fi

if [[ "$STANDALONE" == false && $EUID -ne 0 ]]; then
    echo "Full demo requires root. Use --standalone for no-root mode."
    echo "Usage:"
    echo "  sudo $0              # Full end-to-end with real puzzled"
    echo "  $0 --standalone      # Attestation crypto only (no puzzled/D-Bus)"
    exit 1
fi

# ── Standalone mode (no puzzled) ───────────────────────────────────────────

if $STANDALONE; then
    if [[ -z "$PHASE2_DEMO" ]]; then
        echo "Cannot find puzzle-phase2-demo binary. Run 'cargo build -p puzzle-phase2-demo' first."
        exit 1
    fi
    if [[ -z "$PUZZLECTL" ]]; then
        echo "Cannot find puzzlectl binary. Run 'cargo build -p puzzlectl' first."
        exit 1
    fi

    info "puzzle-phase2-demo: $PHASE2_DEMO"
    info "puzzlectl:    $PUZZLECTL"

    step "Part 1: Generate signed governance events (same crypto as puzzled)"

    DEMO_DIR=$(mktemp -d /tmp/puzzlepod-attestation-demo.XXXXXX)
    AUDIT_DIR="$DEMO_DIR/audit"
    ATTESTATION_DIR="$DEMO_DIR/attestation"

    OUTPUT=$($PHASE2_DEMO attestation --output-dir "$DEMO_DIR" 2>&1)
    echo "$OUTPUT"

    # Get pubkey file path (puzzle-phase2-demo writes it)
    PUBKEY_FILE="$ATTESTATION_DIR/public_key.hex"

    if [[ ! -f "$AUDIT_DIR/events.ndjson" ]]; then
        fail "No events.ndjson found in $AUDIT_DIR"
        exit 1
    fi

    step "Part 2: THIRD-PARTY VERIFICATION"

    echo -e "  ${BOLD}Running: puzzlectl attestation verify${RESET}"
    echo ""

    VERIFY_ARGS=("attestation" "verify" "--audit-dir" "$AUDIT_DIR")
    if [[ -f "$PUBKEY_FILE" ]]; then
        VERIFY_ARGS+=("--pubkey" "$PUBKEY_FILE")
    fi
    if [[ -d "$ATTESTATION_DIR" ]]; then
        VERIFY_ARGS+=("--merkle" "--attestation-dir" "$ATTESTATION_DIR")
    fi

    $PUZZLECTL "${VERIFY_ARGS[@]}" 2>&1 || true

    step "Summary"
    echo -e "  This demo exercised the ${BOLD}real attestation code${RESET} from puzzled:"
    echo -e "  - AuditStore::new_with_attestation() — same as production"
    echo -e "  - Ed25519 signing with domain-separated canonical JSON"
    echo -e "  - Merkle tree (RFC 6962 / Certificate Transparency)"
    echo -e "  - HMAC chain integrity"
    echo -e "  - puzzlectl verification (what a third party runs)"
    echo ""
    echo -e "  For the full end-to-end demo with real sandbox + D-Bus:"
    echo -e "  ${YELLOW}sudo $0${RESET}"
    echo ""
    echo -e "${GREEN}${BOLD}Demo complete.${RESET}"
    exit 0
fi

# ── Full end-to-end mode ──────────────────────────────────────────────────

if [[ -z "$PUZZLED" ]]; then
    echo "Cannot find puzzled binary. Run 'cargo build -p puzzled' first."
    exit 1
fi
if [[ -z "$PUZZLECTL" ]]; then
    echo "Cannot find puzzlectl binary. Run 'cargo build -p puzzlectl' first."
    exit 1
fi

ok "puzzled:   $PUZZLED"
ok "puzzlectl: $PUZZLECTL"

# ── Step 1: Ensure system is set up ───────────────────────────────────────

step "Step 1: Ensure puzzled environment is configured"

CONF_FILE="/etc/puzzled/puzzled.conf"
DBUS_POLICY="/etc/dbus-1/system.d/org.lobstertrap.PuzzlePod1.conf"
BRANCH_ROOT="/var/lib/puzzled/branches"
AUDIT_DIR="$BRANCH_ROOT/audit"

if [[ ! -f "$CONF_FILE" || ! -f "$DBUS_POLICY" ]]; then
    warn "System not set up. Running dev-setup.sh setup..."
    "$SCRIPT_DIR/dev-setup.sh" setup
else
    ok "Config: $CONF_FILE"
    ok "D-Bus policy: $DBUS_POLICY"
fi

# Enable attestation in config if not already
if ! grep -q "^attestation:" "$CONF_FILE" 2>/dev/null; then
    info "Adding attestation config to $CONF_FILE..."
    cat >> "$CONF_FILE" <<'ATT'

# Attestation (added by demo_attestation.sh)
attestation:
  enabled: true
  merkle_tree: true
  attestation_dir: /var/lib/puzzled/attestation
  checkpoint_dir: /var/lib/puzzled/checkpoints
  checkpoint_interval: 100
  checkpoint_time_interval_secs: 3600
ATT
    mkdir -p /var/lib/puzzled/attestation /var/lib/puzzled/checkpoints
    ok "Attestation enabled in config"
else
    ok "Attestation already configured"
fi

ATTESTATION_DIR=$(grep 'attestation_dir:' "$CONF_FILE" | tail -1 | awk '{print $2}' | tr -d '"')
mkdir -p "$ATTESTATION_DIR" 2>/dev/null || true

# ── Step 2: Start puzzled ──────────────────────────────────────────────────

step "Step 2: Start puzzled"

PID_FILE="/run/puzzled/puzzled.pid"
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    ok "puzzled already running (PID $(cat "$PID_FILE"))"
else
    info "Starting puzzled in background..."
    "$SCRIPT_DIR/dev-setup.sh" startbg
    STARTED_PUZZLED=true
    sleep 2

    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        ok "puzzled started (PID $(cat "$PID_FILE"))"
    else
        fail "puzzled failed to start. Check /var/log/puzzled.log"
        tail -10 /var/log/puzzled.log 2>/dev/null || true
        exit 1
    fi
fi

# Verify D-Bus is responding
if $PUZZLECTL --bus system status 2>/dev/null; then
    ok "D-Bus API responding"
else
    warn "D-Bus not responding. Checking..."
    $PUZZLECTL --bus system status 2>&1 || true
fi

# ── Step 3: Agent lifecycle ───────────────────────────────────────────────

step "Step 3: Run a governed agent lifecycle (Fork → Explore → Commit)"

echo -e "  ${BOLD}Creating a branch with 'restricted' profile...${RESET}"
BRANCH_JSON=$($PUZZLECTL --bus system --output json branch create \
    --profile restricted \
    --base-path /tmp \
    --command '["echo","hello from governed agent"]' 2>&1) || true

echo "  $BRANCH_JSON"

# Extract branch ID
BRANCH_ID=$(echo "$BRANCH_JSON" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4) || true

if [[ -z "$BRANCH_ID" ]]; then
    fail "Could not create branch. puzzled response:"
    echo "  $BRANCH_JSON"
    warn "Falling back to standalone mode..."
    STANDALONE=true
    exec "$0" --standalone
fi

ok "Branch created: $BRANCH_ID"
sleep 1

echo ""
echo -e "  ${BOLD}Inspecting branch...${RESET}"
$PUZZLECTL --bus system branch inspect "$BRANCH_ID" 2>&1 || true

echo ""
echo -e "  ${BOLD}Rolling back branch (generates signed governance event)...${RESET}"
$PUZZLECTL --bus system branch rollback "$BRANCH_ID" "attestation demo complete" 2>&1 || true
sleep 1

ok "Branch rolled back"

# ── Step 4: Show attestation trail ────────────────────────────────────────

step "Step 4: Examine the cryptographic audit trail"

EVENTS_FILE="$AUDIT_DIR/events.ndjson"

if [[ ! -f "$EVENTS_FILE" ]]; then
    fail "No events.ndjson at $EVENTS_FILE"
    info "The AuditStore may not be writing events. Check puzzled logs."
    tail -20 /var/log/puzzled.log 2>/dev/null || true
    exit 1
fi

EVENT_COUNT=$(wc -l < "$EVENTS_FILE")
ok "Audit log: $EVENTS_FILE ($EVENT_COUNT events)"

echo ""
echo -e "  ${BOLD}  Governance events with attestation signatures:${RESET}"
echo -e "  ${DIM}  $(printf '\u2500%.0s' {1..72})${RESET}"

# Show signed events (filter by branch)
while IFS= read -r line; do
    # Use python3 or jq to parse — try jq first
    if command -v jq &>/dev/null; then
        EVENT_TYPE=$(echo "$line" | jq -r '.event.event_type // "?"')
        RECORD_ID=$(echo "$line" | jq -r '.record_id // "none"')
        HAS_SIG=$(echo "$line" | jq -r 'if .signature then "YES" else "no" end')
        MERKLE_IDX=$(echo "$line" | jq -r '.merkle_leaf_index // "-"')
        BRANCH=$(echo "$line" | jq -r '.event.branch_id // "-"')
    else
        EVENT_TYPE=$(echo "$line" | python3 -c "import sys,json; e=json.load(sys.stdin); print(e.get('event',{}).get('event_type','?'))" 2>/dev/null || echo "?")
        RECORD_ID=$(echo "$line" | python3 -c "import sys,json; e=json.load(sys.stdin); r=e.get('record_id'); print(r if r else 'none')" 2>/dev/null || echo "?")
        HAS_SIG=$(echo "$line" | python3 -c "import sys,json; e=json.load(sys.stdin); print('YES' if e.get('signature') else 'no')" 2>/dev/null || echo "?")
        MERKLE_IDX=$(echo "$line" | python3 -c "import sys,json; e=json.load(sys.stdin); print(e.get('merkle_leaf_index','-'))" 2>/dev/null || echo "?")
        BRANCH=$(echo "$line" | python3 -c "import sys,json; e=json.load(sys.stdin); print(e.get('event',{}).get('branch_id','-'))" 2>/dev/null || echo "?")
    fi

    # Truncate for display
    [[ ${#RECORD_ID} -gt 12 ]] && RECORD_ID="${RECORD_ID:0:12}"
    [[ ${#BRANCH} -gt 14 ]] && BRANCH="${BRANCH:0:14}"

    printf "  ${CYAN}  %-20s  record=%-14s  sig=%-3s  leaf=%-4s  branch=%-14s${RESET}\n" \
        "$EVENT_TYPE" "$RECORD_ID" "$HAS_SIG" "$MERKLE_IDX" "$BRANCH"
done < "$EVENTS_FILE"

# ── Step 5: Extract public key ────────────────────────────────────────────

step "Step 5: Export the governance public key"

echo -e "  The public key is the ${BOLD}ONLY${RESET} thing a third party needs to trust."
echo -e "  It can be published, pinned, or distributed out-of-band.\n"

PUBKEY_FILE="$ATTESTATION_DIR/public_key.hex"

if [[ -f "$PUBKEY_FILE" ]]; then
    PUBKEY=$(cat "$PUBKEY_FILE")
    ok "Public key (Ed25519): ${PUBKEY:0:16}...${PUBKEY: -16}"
    ok "Key file: $PUBKEY_FILE"
else
    warn "Public key not found at $PUBKEY_FILE"
    warn "Verification will check format but skip crypto."
fi

# ── Step 6: Third-party verification ──────────────────────────────────────

step "Step 6: THIRD-PARTY VERIFICATION"

echo -e "  ${BOLD}This is what an auditor, regulator, or compliance tool does.${RESET}"
echo -e "  They receive:"
echo -e "    1. The audit log  (events.ndjson)"
echo -e "    2. The public key (32 bytes, hex)"
echo -e "  They do NOT need access to puzzled, the signing key, or the system.\n"

echo -e "  ${CYAN}Running: puzzlectl attestation verify${RESET}"
echo -e "  $(printf '\u2500%.0s' {1..50})\n"

VERIFY_ARGS=("attestation" "verify" "--audit-dir" "$AUDIT_DIR")
if [[ -f "$PUBKEY_FILE" ]]; then
    VERIFY_ARGS+=("--pubkey" "$PUBKEY_FILE")
fi
if [[ -n "$ATTESTATION_DIR" && -d "$ATTESTATION_DIR" ]]; then
    VERIFY_ARGS+=("--merkle" "--attestation-dir" "$ATTESTATION_DIR")
fi

$PUZZLECTL "${VERIFY_ARGS[@]}" 2>&1 || true

# ── Summary ────────────────────────────────────────────────────────────────

step "What was demonstrated"

cat <<SUMMARY
  ${BOLD}End-to-end cryptographic governance attestation:${RESET}

  1. ${GREEN}REAL AGENT LIFECYCLE${RESET}
     puzzled created a sandboxed branch, governance ran, branch was rolled back.
     Every step was recorded in the NDJSON audit log.

  2. ${GREEN}TAMPER-EVIDENT SIGNATURES${RESET}
     Each governance event got an Ed25519 signature over canonical JSON.
     Modifying any field (timestamp, decision, branch_id) invalidates it.

  3. ${GREEN}MERKLE TREE (RFC 6962)${RESET}
     Events are leaves in an append-only Merkle tree.
     Inclusion proofs: prove an event exists without revealing others.
     Consistency proofs: prove the log was never rewritten.

  4. ${GREEN}CHAIN INTEGRITY${RESET}
     parent_record_id links events per branch: created -> committed|rolled_back.
     An auditor reconstructs the full governance timeline.

  5. ${GREEN}EXTERNAL VERIFIABILITY${RESET}
     The ONLY thing a third party needs is the public key (32 bytes).
     All verification is offline. The audit log is a self-contained proof.

  6. ${GREEN}COMPLIANCE MAPPING${RESET}
     Map attestation records to regulatory controls:
       puzzlectl compliance report --framework eu-ai-act --audit-dir $AUDIT_DIR
SUMMARY

echo -e "\n${GREEN}${BOLD}Demo complete.${RESET}\n"
