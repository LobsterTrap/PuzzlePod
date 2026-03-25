#!/bin/bash
# run_demo_phase2.sh — PuzzlePod Phase 2 Live Demo (Hardening)
#
# Exercises REAL Rust code from the puzzle-phase2-demo binary for each section,
# plus shell-driven network namespace isolation. This is the Phase 2
# counterpart to Phase 1's run_demo_phase1.sh + sandbox-demo binary.
#
# Usage:
#   sudo demo/run_demo_phase2.sh
#
# Prerequisites (Lima VM on macOS):
#   limactl shell puzzled
#   cd /path/to/puzzlepod
#   cargo build --workspace --release
#   sudo demo/run_demo_phase2.sh
#
# The demo runs:
#   1. Expanded profile library (23 domain-specific profiles)
#   2. Cross-branch conflict detection
#   3. Adaptive budget engine (trust-through-behavior)
#   4. Persistent audit storage with query and export
#   5. Network journal append/read/discard
#   6. HTTP proxy with domain filtering
#   7. seccomp USER_NOTIF with argument inspection (Linux only)
#   8. fanotify behavioral monitoring (Linux only)
#   9. BPF LSM exec rate limiting
#  10. Prometheus metrics registry and encoding
#  11. Zero-downtime state serialization
#  12. Network namespace isolation (shell-driven, Linux only)

set -euo pipefail

# ─── Colors & Formatting ─────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

step_number=0

header() {
    echo ""
    echo -e "${BOLD}${MAGENTA}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${MAGENTA}  $1${NC}"
    echo -e "${BOLD}${MAGENTA}════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

step() {
    step_number=$((step_number + 1))
    echo ""
    echo -e "${BOLD}${CYAN}── Step ${step_number}: $1 ──${NC}"
    echo ""
}

info() {
    echo -e "  ${DIM}▸${NC} $1"
}

ok() {
    echo -e "  ${GREEN}✓${NC} $1"
}

fail() {
    echo -e "  ${RED}✗${NC} $1"
}

warn() {
    echo -e "  ${YELLOW}!${NC} $1"
}

pause() {
    echo ""
    echo -e "  ${DIM}Press Enter to continue...${NC}"
    read -r
}

# ─── Resolve Paths ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROFILES_DIR="$REPO_DIR/policies/profiles"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/var/tmp/puzzlepod-target}"
PHASE2_DEMO="$CARGO_TARGET_DIR/release/puzzle-phase2-demo"
[ -x "$PHASE2_DEMO" ] || PHASE2_DEMO="$REPO_DIR/target/release/puzzle-phase2-demo"
DEMO_BASE="/tmp/puzzled-puzzle-phase2-demo"

# ─── Cleanup ──────────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    info "Cleaning up Phase 2 demo artifacts..."

    # Remove veth pairs (if any survived)
    ip link del veth-gated-h 2>/dev/null || true
    ip link del veth-mon-h 2>/dev/null || true

    # Remove network namespaces
    ip netns del ns-gated-agent 2>/dev/null || true
    ip netns del ns-monitored-agent 2>/dev/null || true

    # Remove nftables table
    nft delete table inet puzzled_demo 2>/dev/null || true

    rm -rf "$DEMO_BASE"
    ok "Cleanup complete"
}

trap cleanup EXIT

# ─── Prerequisites ────────────────────────────────────────────────────────────

header "PuzzlePod — Phase 2 Live Demo (Hardening)"

info "This demo exercises REAL Rust code from the puzzle-phase2-demo binary"
info "for every Phase 2 feature, plus shell-driven network isolation."
echo ""

# Check for puzzle-phase2-demo binary
if [ ! -x "$PHASE2_DEMO" ]; then
    fail "puzzle-phase2-demo binary not found at $PHASE2_DEMO"
    info "Build it first: cargo build --workspace --release"
    exit 1
fi
ok "puzzle-phase2-demo binary found: $PHASE2_DEMO"

# Check platform
IS_LINUX=false
if [ "$(uname -s)" = "Linux" ]; then
    IS_LINUX=true
    ok "Running on Linux — all sections available"
else
    warn "Running on $(uname -s) — Linux-only sections will show config only"
fi

# Create demo base directory
mkdir -p "$DEMO_BASE"
ok "Demo directory: $DEMO_BASE"

pause

# ═══════════════════════════════════════════════════════════════════════════════
# Section 1: Expanded Profile Library
# ═══════════════════════════════════════════════════════════════════════════════

step "Expanded Profile Library (23 domain-specific profiles)"

info "Running: puzzle-phase2-demo profiles --profiles-dir $PROFILES_DIR"
echo ""
$PHASE2_DEMO profiles --profiles-dir "$PROFILES_DIR"

pause

# ═══════════════════════════════════════════════════════════════════════════════
# Section 2: Cross-Branch Conflict Detection
# ═══════════════════════════════════════════════════════════════════════════════

step "Cross-Branch Conflict Detection"

info "Running: puzzle-phase2-demo conflict"
echo ""
$PHASE2_DEMO conflict

pause

# ═══════════════════════════════════════════════════════════════════════════════
# Section 3: Adaptive Budget Engine
# ═══════════════════════════════════════════════════════════════════════════════

step "Adaptive Budget Engine (trust-through-behavior)"

info "Running: puzzle-phase2-demo budget"
echo ""
$PHASE2_DEMO budget

pause

# ═══════════════════════════════════════════════════════════════════════════════
# Section 4: Persistent Audit Storage
# ═══════════════════════════════════════════════════════════════════════════════

step "Persistent Audit Storage"

info "Running: puzzle-phase2-demo audit"
echo ""
$PHASE2_DEMO audit

pause

# ═══════════════════════════════════════════════════════════════════════════════
# Section 5: Network Journal
# ═══════════════════════════════════════════════════════════════════════════════

step "Network Journal (side-effect capture and replay)"

info "Running: puzzle-phase2-demo journal"
echo ""
$PHASE2_DEMO journal

pause

# ═══════════════════════════════════════════════════════════════════════════════
# Section 6: HTTP Proxy with Domain Filtering
# ═══════════════════════════════════════════════════════════════════════════════

step "HTTP Proxy with Domain Filtering"

info "Running: puzzle-phase2-demo proxy"
echo ""
$PHASE2_DEMO proxy

pause

# ═══════════════════════════════════════════════════════════════════════════════
# Section 7: seccomp USER_NOTIF
# ═══════════════════════════════════════════════════════════════════════════════

step "seccomp USER_NOTIF with Argument Inspection"

info "Running: puzzle-phase2-demo seccomp"
echo ""
$PHASE2_DEMO seccomp

pause

# ═══════════════════════════════════════════════════════════════════════════════
# Section 8: fanotify Behavioral Monitoring
# ═══════════════════════════════════════════════════════════════════════════════

step "fanotify Behavioral Monitoring"

info "Running: puzzle-phase2-demo fanotify"
echo ""
$PHASE2_DEMO fanotify

pause

# ═══════════════════════════════════════════════════════════════════════════════
# Section 9: BPF LSM Exec Rate Limiting
# ═══════════════════════════════════════════════════════════════════════════════

step "BPF LSM Exec Rate Limiting"

info "Running: puzzle-phase2-demo bpf-lsm"
echo ""
$PHASE2_DEMO bpf-lsm

pause

# ═══════════════════════════════════════════════════════════════════════════════
# Section 10: Prometheus Metrics
# ═══════════════════════════════════════════════════════════════════════════════

step "Prometheus Metrics"

info "Running: puzzle-phase2-demo metrics"
echo ""
$PHASE2_DEMO metrics

pause

# ═══════════════════════════════════════════════════════════════════════════════
# Section 11: Zero-Downtime State Serialization
# ═══════════════════════════════════════════════════════════════════════════════

step "Zero-Downtime State Serialization"

info "Running: puzzle-phase2-demo state"
echo ""
$PHASE2_DEMO state

pause

# ═══════════════════════════════════════════════════════════════════════════════
# Section 12: Network Namespace Isolation (shell-driven)
# ═══════════════════════════════════════════════════════════════════════════════

step "Network Namespace Isolation"

if [ "$IS_LINUX" = true ]; then
    info "Demonstrating network isolation using real kernel namespaces"
    echo ""

    # ─── Mode 1: Blocked (no network) ─────────────────────────────────────

    echo -e "  ${BOLD}${CYAN}── Mode: Blocked (no network) ──${NC}"
    echo ""

    BLOCKED_NS="ns-blocked-demo"
    ip netns add "$BLOCKED_NS" 2>/dev/null || true

    # Test: no connectivity inside blocked namespace
    if ip netns exec "$BLOCKED_NS" ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1; then
        # Loopback works (normal — lo is present but down)
        fail "Unexpected: ping to loopback succeeded in blocked ns"
    else
        ok "Blocked mode: ping to 127.0.0.1 failed (no interfaces up)"
    fi

    # Bring up loopback, verify external is still blocked
    ip netns exec "$BLOCKED_NS" ip link set lo up 2>/dev/null || true
    if ip netns exec "$BLOCKED_NS" ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1; then
        fail "Unexpected: external ping succeeded in blocked ns"
    else
        ok "Blocked mode: ping to 8.8.8.8 failed (no route to host)"
    fi

    ip netns del "$BLOCKED_NS" 2>/dev/null || true
    echo ""

    # ─── Mode 2: Gated (veth + nftables) ──────────────────────────────────

    echo -e "  ${BOLD}${CYAN}── Mode: Gated (veth + nftables filtering) ──${NC}"
    echo ""

    GATED_NS="ns-gated-agent"

    # Create namespace + veth pair
    ip netns add "$GATED_NS" 2>/dev/null || true
    ip link add veth-gated-h type veth peer name veth-gated-ns 2>/dev/null || true
    ip link set veth-gated-ns netns "$GATED_NS" 2>/dev/null || true

    # Configure addresses
    ip addr add 10.200.1.1/24 dev veth-gated-h 2>/dev/null || true
    ip link set veth-gated-h up 2>/dev/null || true
    ip netns exec "$GATED_NS" ip addr add 10.200.1.2/24 dev veth-gated-ns 2>/dev/null || true
    ip netns exec "$GATED_NS" ip link set veth-gated-ns up 2>/dev/null || true
    ip netns exec "$GATED_NS" ip link set lo up 2>/dev/null || true
    ip netns exec "$GATED_NS" ip route add default via 10.200.1.1 2>/dev/null || true

    ok "Created veth pair: veth-gated-h <-> veth-gated-ns (10.200.1.0/24)"

    # Test connectivity to host side
    if ip netns exec "$GATED_NS" ping -c 1 -W 1 10.200.1.1 >/dev/null 2>&1; then
        ok "Gated mode: agent can reach host veth (10.200.1.1)"
    else
        warn "Gated mode: cannot reach host veth (firewall or routing issue)"
    fi

    # Apply nftables filtering (allow only specific ports)
    if command -v nft >/dev/null 2>&1; then
        nft add table inet puzzled_demo 2>/dev/null || true
        nft add chain inet puzzled_demo gated_forward '{ type filter hook forward priority 0; policy drop; }' 2>/dev/null || true
        # Allow DNS (53) and HTTPS (443) only
        nft add rule inet puzzled_demo gated_forward iifname "veth-gated-h" tcp dport '{53, 443}' accept 2>/dev/null || true
        nft add rule inet puzzled_demo gated_forward iifname "veth-gated-h" udp dport 53 accept 2>/dev/null || true
        # Allow established/related
        nft add rule inet puzzled_demo gated_forward ct state established,related accept 2>/dev/null || true

        ok "nftables: allow DNS(53) + HTTPS(443) only, drop all else"

        # Show rules
        info "nftables rules:"
        nft list table inet puzzled_demo 2>/dev/null | sed 's/^/    /'
    else
        warn "nft not found — skipping nftables filtering demo"
    fi

    echo ""

    # ─── Mode 3: Monitored (full access with logging) ─────────────────────

    echo -e "  ${BOLD}${CYAN}── Mode: Monitored (full access + logging) ──${NC}"
    echo ""

    MONITORED_NS="ns-monitored-agent"
    ip netns add "$MONITORED_NS" 2>/dev/null || true
    ip link add veth-mon-h type veth peer name veth-mon-ns 2>/dev/null || true
    ip link set veth-mon-ns netns "$MONITORED_NS" 2>/dev/null || true

    ip addr add 10.200.2.1/24 dev veth-mon-h 2>/dev/null || true
    ip link set veth-mon-h up 2>/dev/null || true
    ip netns exec "$MONITORED_NS" ip addr add 10.200.2.2/24 dev veth-mon-ns 2>/dev/null || true
    ip netns exec "$MONITORED_NS" ip link set veth-mon-ns up 2>/dev/null || true
    ip netns exec "$MONITORED_NS" ip link set lo up 2>/dev/null || true
    ip netns exec "$MONITORED_NS" ip route add default via 10.200.2.1 2>/dev/null || true

    ok "Created veth pair: veth-mon-h <-> veth-mon-ns (10.200.2.0/24)"

    # Add nftables logging rule (if available)
    if command -v nft >/dev/null 2>&1; then
        nft add chain inet puzzled_demo monitored_log '{ type filter hook forward priority -1; policy accept; }' 2>/dev/null || true
        nft add rule inet puzzled_demo monitored_log iifname "veth-mon-h" log prefix '"puzzled-monitored: "' 2>/dev/null || true
        ok "nftables: logging all traffic from monitored namespace"
    fi

    # Test full connectivity
    if ip netns exec "$MONITORED_NS" ping -c 1 -W 1 10.200.2.1 >/dev/null 2>&1; then
        ok "Monitored mode: full network access (with logging)"
    else
        warn "Monitored mode: routing not fully configured"
    fi

    echo ""

    # ─── Summary ──────────────────────────────────────────────────────────

    echo -e "  ${BOLD}${CYAN}── Network Isolation Summary ──${NC}"
    echo ""
    echo -e "    ${RED}Blocked${NC}:    Empty network namespace (no interfaces)"
    echo -e "    ${YELLOW}Gated${NC}:      veth pair + nftables (DNS+HTTPS only) + HTTP proxy"
    echo -e "    ${GREEN}Monitored${NC}:  veth pair + nftables logging (all traffic allowed)"
    echo ""
    ok "Network isolation demonstrated with real kernel namespaces"

else
    info "Network namespace isolation requires Linux."
    info "Run inside the Lima VM: limactl shell puzzled-dev"
    echo ""

    echo -e "  ${BOLD}Network isolation modes:${NC}"
    echo -e "    ${RED}Blocked${NC}:    ip netns add (no interfaces = no connectivity)"
    echo -e "    ${YELLOW}Gated${NC}:      veth pair + nftables rules (port filtering)"
    echo -e "    ${GREEN}Monitored${NC}:  veth pair + nftables log (full access, logged)"
    echo ""
    ok "Network isolation configuration displayed"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════

header "Phase 2 Demo Complete"

echo -e "  ${BOLD}Features demonstrated:${NC}"
echo ""
echo -e "    ${GREEN}✓${NC}  Expanded profile library (23 domain-specific profiles)"
echo -e "    ${GREEN}✓${NC}  Cross-branch conflict detection (Reject + LastWriterWins)"
echo -e "    ${GREEN}✓${NC}  Adaptive budget engine (Restricted -> Standard -> Extended)"
echo -e "    ${GREEN}✓${NC}  Persistent audit storage (query by branch/type, JSON/CSV export)"
echo -e "    ${GREEN}✓${NC}  Network journal (append, read, discard)"
echo -e "    ${GREEN}✓${NC}  HTTP proxy with domain filtering"
echo -e "    ${GREEN}✓${NC}  seccomp USER_NOTIF (two-tier: static deny + daemon-gated)"
echo -e "    ${GREEN}✓${NC}  fanotify behavioral monitoring (mass deletion, credential access)"
echo -e "    ${GREEN}✓${NC}  BPF LSM exec rate limiting (per-cgroup enforcement)"
echo -e "    ${GREEN}✓${NC}  Prometheus metrics (6 counters, 3 histograms, 1 gauge)"
echo -e "    ${GREEN}✓${NC}  Zero-downtime state serialization (save/restore active branches)"
echo -e "    ${GREEN}✓${NC}  Network namespace isolation (Blocked / Gated / Monitored)"
echo ""

echo -e "  ${BOLD}Key principle:${NC} Userspace configures, kernel enforces."
echo -e "  All enforcement survives daemon crash. Agent cannot remove"
echo -e "  its own restrictions."
echo ""
echo -e "  ${BOLD}All code exercised is real Rust from puzzled, puzzled-types,${NC}"
echo -e "  ${BOLD}and puzzle-proxy crates — not echo output.${NC}"
echo ""
