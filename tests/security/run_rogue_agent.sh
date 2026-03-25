#!/bin/bash
# run_rogue_agent.sh — Orchestrate the rogue agent red team exercise.
#
# Runs the rogue agent kernel sabotage tests in two modes:
#   --mode=kernel-only   Baseline: unshare (kernel primitives only, no puzzled)
#   --mode=sandbox       Full: puzzled sandbox via puzzle-sandbox-demo exec
#   --mode=all           Both modes sequentially (default)
#
# Usage:
#   sudo ./tests/security/run_rogue_agent.sh [--mode=all|kernel-only|sandbox]
#
# The script produces a structured comparison report showing which enforcement
# layer blocked each attack in each mode.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_SCRIPT="$SCRIPT_DIR/test_rogue_agent.sh"
REPORT_DIR="/tmp/rogue-agent-report-$(date +%Y%m%d-%H%M%S)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# --- Parse arguments ---
MODE="all"
for arg in "$@"; do
    case "$arg" in
        --mode=*) MODE="${arg#*=}" ;;
        --help|-h)
            echo "Usage: sudo $0 [--mode=all|kernel-only|sandbox]"
            echo ""
            echo "Modes:"
            echo "  kernel-only  Run with unshare only (baseline kernel containment)"
            echo "  sandbox      Run inside puzzled sandbox (full PuzzlePod stack)"
            echo "  all          Run both modes and produce comparison (default)"
            exit 0
            ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# --- Prerequisites ---
if [ "$(uname -s)" != "Linux" ]; then
    echo -e "${YELLOW}SKIP: This test requires Linux${NC}"
    exit 77
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Must be run as root"
    echo "Usage: sudo $0 [--mode=all|kernel-only|sandbox]"
    exit 1
fi

if [ ! -x "$TEST_SCRIPT" ]; then
    echo "Error: Test script not found: $TEST_SCRIPT"
    echo "Ensure tests/security/test_rogue_agent.sh exists and is executable."
    exit 1
fi

mkdir -p "$REPORT_DIR"

# --- Environment info ---
print_environment() {
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  Rogue Agent Red Team Exercise${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Kernel:     $(uname -r)"
    echo "  Arch:       $(uname -m)"
    echo "  Distro:     $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || echo 'unknown')"
    echo "  Date:       $(date -Iseconds)"
    echo "  Mode:       $MODE"
    echo "  Report dir: $REPORT_DIR"
    if [ -f /sys/kernel/security/lsm ]; then
        echo "  LSMs:       $(cat /sys/kernel/security/lsm)"
    fi
    if [ -f /sys/kernel/security/landlock/abi_version ]; then
        echo "  Landlock:   ABI v$(cat /sys/kernel/security/landlock/abi_version)"
    fi
    echo ""
}

# --- Mode 1: Kernel primitives only (unshare) ---
run_kernel_only() {
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  Mode 1: Kernel Primitives Only (unshare)${NC}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${DIM}Containment: unshare --user --pid --mount --net --fork${NC}"
    echo -e "  ${DIM}This tests what the kernel blocks without puzzled's Landlock/seccomp/cgroup stack.${NC}"
    echo ""

    local LOG="$REPORT_DIR/kernel-only.log"

    # Use unshare to create a minimal containment environment.
    # --user drops real capabilities, --pid isolates PIDs, --mount isolates mounts,
    # --net isolates network. This simulates baseline kernel containment.
    set +e
    unshare --user --map-root-user --pid --mount --net --fork -- \
        bash "$TEST_SCRIPT" 2>&1 | tee "$LOG"
    local ret=${PIPESTATUS[0]}
    set -e

    echo ""
    if [ $ret -eq 0 ]; then
        echo -e "  ${GREEN}Mode 1 Result: ALL ATTACKS BLOCKED${NC}"
    elif [ $ret -eq 77 ]; then
        echo -e "  ${YELLOW}Mode 1 Result: SKIPPED${NC}"
    else
        echo -e "  ${RED}Mode 1 Result: SOME ATTACKS SUCCEEDED (exit code $ret)${NC}"
    fi
    echo -e "  ${DIM}Full log: $LOG${NC}"
    echo ""
    return $ret
}

# --- Mode 2: Full puzzled sandbox (puzzle-sandbox-demo exec) ---
run_sandbox() {
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  Mode 2: Full PuzzlePod Sandbox (puzzle-sandbox-demo exec)${NC}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${DIM}Containment: Landlock + seccomp-BPF + cgroups v2 + capability drop${NC}"
    echo ""

    local CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/var/tmp/puzzlepod-target}"
    local SANDBOX_DEMO="$CARGO_TARGET_DIR/release/puzzle-sandbox-demo"
    if [ ! -x "$SANDBOX_DEMO" ]; then
        SANDBOX_DEMO="$CARGO_TARGET_DIR/debug/puzzle-sandbox-demo"
    fi
    if [ ! -x "$SANDBOX_DEMO" ]; then
        SANDBOX_DEMO="${PROJECT_DIR}/target/release/puzzle-sandbox-demo"
    fi
    if [ ! -x "$SANDBOX_DEMO" ]; then
        SANDBOX_DEMO="${PROJECT_DIR}/target/debug/puzzle-sandbox-demo"
    fi

    if [ ! -x "$SANDBOX_DEMO" ]; then
        echo -e "  ${YELLOW}SKIP: puzzle-sandbox-demo binary not found.${NC}"
        echo "  Build with: cargo build --workspace --release"
        echo ""
        return 77
    fi

    # Check if puzzle-sandbox-demo supports exec mode
    if ! "$SANDBOX_DEMO" --help 2>&1 | grep -qi "exec"; then
        echo -e "  ${YELLOW}SKIP: puzzle-sandbox-demo does not support 'exec' mode.${NC}"
        echo "  The binary runs built-in escape tests. Run directly: sudo $SANDBOX_DEMO"
        echo ""
        return 77
    fi

    local LOG="$REPORT_DIR/sandbox.log"

    set +e
    timeout 120 "$SANDBOX_DEMO" exec \
        --allow-read "$SCRIPT_DIR" \
        -- bash "$TEST_SCRIPT" 2>&1 | tee "$LOG"
    local ret=${PIPESTATUS[0]}
    set -e

    echo ""
    if [ $ret -eq 0 ]; then
        echo -e "  ${GREEN}Mode 2 Result: ALL ATTACKS BLOCKED${NC}"
    elif [ $ret -eq 77 ]; then
        echo -e "  ${YELLOW}Mode 2 Result: SKIPPED${NC}"
    else
        echo -e "  ${RED}Mode 2 Result: SOME ATTACKS SUCCEEDED (exit code $ret)${NC}"
    fi
    echo -e "  ${DIM}Full log: $LOG${NC}"
    echo ""
    return $ret
}

# --- OPA policy evaluation against kernel_sabotage changeset ---
run_opa_policy_test() {
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  OPA Policy Evaluation: Kernel Sabotage Changeset${NC}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    local CHANGESET="$PROJECT_DIR/demo/sample_changesets/kernel_sabotage.json"
    local POLICY="$PROJECT_DIR/policies/rules/commit.rego"
    local LOG="$REPORT_DIR/opa-policy.log"

    if [ ! -f "$CHANGESET" ]; then
        echo -e "  ${YELLOW}SKIP: kernel_sabotage.json not found${NC}"
        return 77
    fi

    echo -e "  ${DIM}Changeset: $CHANGESET${NC}"
    echo -e "  ${DIM}Policy:    $POLICY${NC}"
    echo ""
    echo "  Files in sabotage changeset:"
    python3 -c "
import json, sys
with open('$CHANGESET') as f:
    changes = json.load(f)
for c in changes:
    kind = c['kind']
    path = c['path']
    size = c['size']
    icon = '!' if any(p in path for p in ['/boot/', '/etc/', '/usr/', '/lib/', '.env']) else ' '
    print(f'    {icon} [{kind:>10}] {path} ({size} bytes)')
" 2>&1 | tee -a "$LOG"

    echo ""

    # Check if OPA is available (or if puzzle-sandbox-demo can evaluate policy)
    if command -v opa &>/dev/null; then
        echo "  Evaluating policy with OPA..."
        local INPUT_JSON=$(python3 -c "
import json
with open('$CHANGESET') as f:
    changes = json.load(f)
input_obj = {
    'changes': changes,
    'profile': 'restricted',
    'workspace_root': '/home/agent/project'
}
print(json.dumps(input_obj))
")
        echo "$INPUT_JSON" | opa eval -d "$POLICY" -I 'data.puzzlepod.commit.violations' --format pretty 2>&1 | tee -a "$LOG"

        local ALLOW=$(echo "$INPUT_JSON" | opa eval -d "$POLICY" -I 'data.puzzlepod.commit.allow' --format raw 2>&1)
        echo ""
        if [ "$ALLOW" = "false" ]; then
            echo -e "  ${GREEN}PASS${NC}: Changeset correctly REJECTED by OPA policy"
        else
            echo -e "  ${RED}FAIL${NC}: Changeset was ALLOWED by OPA policy (should be rejected)"
        fi
    else
        echo -e "  ${DIM}OPA CLI not installed — showing expected violations manually:${NC}"
        echo ""
        python3 -c "
import json
with open('$CHANGESET') as f:
    changes = json.load(f)

system_prefixes = ['usr/bin/', 'usr/sbin/', 'usr/lib/', 'etc/', 'boot/', 'lib/modules/']
persistence_paths = ['etc/cron', 'etc/systemd/system/']
sensitive_patterns = ['.env']

violations = []
for c in changes:
    path = c['path'].lstrip('/')
    for prefix in system_prefixes:
        if path.startswith(prefix):
            violations.append(('no_system_modifications', c['path']))
            break
    for pp in persistence_paths:
        if path.startswith(pp):
            violations.append(('no_persistence', c['path']))
    for sp in sensitive_patterns:
        if path.endswith(sp):
            violations.append(('no_sensitive_files', c['path']))

print(f'  Expected violations: {len(violations)}')
for rule, path in violations:
    print(f'    VIOLATION [{rule}]: {path}')
print()
if violations:
    print('  Verdict: REJECTED (governance policy blocks kernel sabotage changeset)')
else:
    print('  Verdict: ALLOWED (unexpected — policy gap)')
" 2>&1 | tee -a "$LOG"
    fi

    echo ""
    echo -e "  ${DIM}Full log: $LOG${NC}"
    echo ""
}

# --- Rogue file list (shared between cleanup and verification) ---
ROGUE_FILES=(
    "/etc/cron.d/backdoor"
    "/etc/systemd/system/rogue.service"
    "/etc/systemd/system/rogue.timer"
    "/etc/sudoers.d/agent-root"
    "/usr/bin/rogue_suid"
    "/usr/bin/rogue-escalate"
    "/etc/pam.d/rogue"
    "/etc/selinux/rogue_policy.te"
    "/etc/profile.d/rogue.sh"
    "/etc/rc.local"
    "/boot/efi/rogue.efi"
    "/tmp/suid_sh"
    "/tmp/proc_escape"
    "/var/spool/cron/root"
)

# --- Clean up rogue files left by a previous test mode ---
# Prevents kernel-only mode residue from contaminating sandbox mode results.
# Operations like touch (utimensat) and chmod (fchmod) on already-existing
# files bypass Landlock, causing false FAILs in the sandbox test.
cleanup_rogue_files() {
    local KVER
    KVER=$(uname -r)
    local cleaned=0
    for f in "${ROGUE_FILES[@]}" "/lib/modules/${KVER}/kernel/rogue.ko"; do
        if [ -e "$f" ]; then
            rm -rf "$f" 2>/dev/null && cleaned=$((cleaned + 1))
        fi
    done
    if [ $cleaned -gt 0 ]; then
        echo -e "  ${DIM}Cleaned up $cleaned rogue file(s) from previous test${NC}"
    fi
}

# --- Zero residue verification ---
verify_zero_residue() {
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  Zero Residue Verification${NC}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    local RESIDUE_FOUND=0
    local KVER
    KVER=$(uname -r)

    for f in "${ROGUE_FILES[@]}" "/lib/modules/${KVER}/kernel/rogue.ko"; do
        if [ -e "$f" ]; then
            echo -e "  ${RED}RESIDUE${NC}: $f exists on host"
            RESIDUE_FOUND=$((RESIDUE_FOUND + 1))
        fi
    done

    if [ $RESIDUE_FOUND -eq 0 ]; then
        echo -e "  ${GREEN}PASS${NC}: Zero residue — no rogue files found on host filesystem"
    else
        echo -e "  ${RED}FAIL${NC}: $RESIDUE_FOUND rogue file(s) found on host"
    fi

    echo ""
}

# --- Comparison report ---
generate_report() {
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  Summary Report${NC}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    local SUMMARY="$REPORT_DIR/summary.txt"

    {
        echo "Rogue Agent Red Team Exercise — Summary"
        echo "========================================"
        echo ""
        echo "Date:       $(date -Iseconds)"
        echo "Kernel:     $(uname -r)"
        echo "Arch:       $(uname -m)"
        echo "Distro:     $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || echo 'unknown')"
        if [ -f /sys/kernel/security/lsm ]; then
            echo "LSMs:       $(cat /sys/kernel/security/lsm)"
        fi
        if [ -f /sys/kernel/security/landlock/abi_version ]; then
            echo "Landlock:   ABI v$(cat /sys/kernel/security/landlock/abi_version)"
        fi
        echo ""
        echo "Test Mode:  $MODE"
        echo ""

        echo "Results by mode:"
        for logfile in "$REPORT_DIR"/*.log; do
            [ -f "$logfile" ] || continue
            local name=$(basename "$logfile" .log)
            local pass=$(grep -c "PASS" "$logfile" 2>/dev/null || echo "0")
            local fail=$(grep -c "FAIL" "$logfile" 2>/dev/null || echo "0")
            local skip=$(grep -c "SKIP" "$logfile" 2>/dev/null || echo "0")
            echo "  $name: $pass passed, $fail failed, $skip skipped"
        done
        echo ""
        echo "Logs: $REPORT_DIR/"
    } | tee "$SUMMARY"

    echo ""
    echo -e "  ${DIM}Full report: $SUMMARY${NC}"
    echo ""
}

# --- Main execution ---
print_environment

KERNEL_ONLY_RET=0
SANDBOX_RET=0

case "$MODE" in
    kernel-only)
        run_kernel_only || KERNEL_ONLY_RET=$?
        verify_zero_residue
        cleanup_rogue_files
        ;;
    sandbox)
        cleanup_rogue_files
        run_sandbox || SANDBOX_RET=$?
        verify_zero_residue
        cleanup_rogue_files
        ;;
    all)
        run_kernel_only || KERNEL_ONLY_RET=$?
        echo ""
        cleanup_rogue_files
        run_sandbox || SANDBOX_RET=$?
        echo ""
        run_opa_policy_test
        verify_zero_residue
        cleanup_rogue_files
        ;;
    *)
        echo "Error: Unknown mode '$MODE'. Use: all, kernel-only, or sandbox"
        exit 1
        ;;
esac

generate_report

echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  Red Team Exercise Complete${NC}"
echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""

# Exit with failure if any mode had failures (but not skips)
if [ $KERNEL_ONLY_RET -eq 1 ] || [ $SANDBOX_RET -eq 1 ]; then
    exit 1
fi
exit 0
