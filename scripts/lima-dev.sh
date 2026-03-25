#!/usr/bin/env bash
#
# lima-dev.sh — Lima VM convenience script for PuzzlePod development
#
# Usage:
#   ./scripts/lima-dev.sh setup      # Create + start VM, wait for Rust (idempotent)
#   ./scripts/lima-dev.sh shell      # Enter VM shell at project directory
#   ./scripts/lima-dev.sh build      # cargo build --workspace inside VM
#   ./scripts/lima-dev.sh test       # cargo test --workspace inside VM
#   ./scripts/lima-dev.sh security   # sudo tests/security/run_all.sh inside VM
#   ./scripts/lima-dev.sh stop       # Stop VM
#   ./scripts/lima-dev.sh destroy    # Delete VM entirely
#   ./scripts/lima-dev.sh status     # Show VM status

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
YAML_FILE="$PROJECT_DIR/puzzled-dev.yaml"
VM_NAME="puzzled-dev"

# Timeout (seconds) to wait for rustc after limactl start
RUST_POLL_TIMEOUT=600
RUST_POLL_INTERVAL=10

# --- Helpers ---
die() { echo "Error: $*" >&2; exit 1; }

check_limactl() {
    command -v limactl &>/dev/null || die "limactl not found. Install Lima: https://lima-vm.io"
}

vm_status() {
    limactl list --json 2>/dev/null | \
        python3 -c "import sys,json
for line in sys.stdin:
    obj=json.loads(line)
    if obj.get('name')=='$VM_NAME':
        print(obj.get('status','Unknown'))
        sys.exit(0)
print('NotFound')" 2>/dev/null || echo "NotFound"
}

run_in_vm() {
    limactl shell "$VM_NAME" -- bash -lc "cd '$PROJECT_DIR' && $(printf '%q ' "$@")"
}

wait_for_rust() {
    echo "Waiting for Rust toolchain to become available (up to ${RUST_POLL_TIMEOUT}s)..."
    local elapsed=0
    while [ $elapsed -lt $RUST_POLL_TIMEOUT ]; do
        if limactl shell "$VM_NAME" -- bash -lc 'command -v rustc &>/dev/null && rustc --version' 2>/dev/null; then
            echo "Rust toolchain ready."
            return 0
        fi
        sleep "$RUST_POLL_INTERVAL"
        elapsed=$((elapsed + RUST_POLL_INTERVAL))
        echo "  ... still waiting (${elapsed}s / ${RUST_POLL_TIMEOUT}s)"
    done
    die "Timed out waiting for Rust toolchain after ${RUST_POLL_TIMEOUT}s"
}

# --- Commands ---
cmd_setup() {
    local status
    status="$(vm_status)"

    case "$status" in
        Running)
            echo "VM '$VM_NAME' is already running."
            ;;
        Stopped)
            echo "VM '$VM_NAME' exists but is stopped. Starting..."
            limactl start "$VM_NAME" || true
            wait_for_rust
            ;;
        NotFound)
            echo "Creating VM '$VM_NAME' from $YAML_FILE..."
            [ -f "$YAML_FILE" ] || die "Lima config not found: $YAML_FILE"
            # limactl start may timeout waiting for probes (Rust install takes ~10 min).
            # We handle the timeout ourselves with wait_for_rust.
            limactl create --name="$VM_NAME" "$YAML_FILE"
            limactl start "$VM_NAME" || true
            wait_for_rust
            ;;
        *)
            die "VM '$VM_NAME' is in unexpected state: $status"
            ;;
    esac

    # Ensure the lima user has a usable default toolchain
    limactl shell "$VM_NAME" -- bash -lc 'rustup default stable 2>/dev/null || true'

    echo ""
    echo "VM '$VM_NAME' is ready."
    echo "  Enter VM:  ./scripts/lima-dev.sh shell"
    echo "  Build:     ./scripts/lima-dev.sh build"
    echo "  Test:      ./scripts/lima-dev.sh test"
}

cmd_shell() {
    local status
    status="$(vm_status)"
    [ "$status" = "Running" ] || die "VM '$VM_NAME' is not running (status: $status). Run: ./scripts/lima-dev.sh setup"
    limactl shell "$VM_NAME" -- bash -lc "cd '$PROJECT_DIR' && exec bash"
}

cmd_build() {
    local status
    status="$(vm_status)"
    [ "$status" = "Running" ] || die "VM '$VM_NAME' is not running. Run: ./scripts/lima-dev.sh setup"
    echo "Building workspace in VM..."
    run_in_vm cargo build --workspace
}

cmd_test() {
    local status
    status="$(vm_status)"
    [ "$status" = "Running" ] || die "VM '$VM_NAME' is not running. Run: ./scripts/lima-dev.sh setup"
    echo "Running tests in VM..."
    run_in_vm cargo test --workspace
}

cmd_security() {
    local status
    status="$(vm_status)"
    [ "$status" = "Running" ] || die "VM '$VM_NAME' is not running. Run: ./scripts/lima-dev.sh setup"
    echo "Running security tests in VM (requires root)..."
    run_in_vm sudo bash tests/security/run_all.sh
}

cmd_stop() {
    echo "Stopping VM '$VM_NAME'..."
    limactl stop "$VM_NAME"
}

cmd_destroy() {
    echo "Deleting VM '$VM_NAME'..."
    limactl delete --force "$VM_NAME" 2>/dev/null || limactl delete "$VM_NAME"
}

cmd_status() {
    local status
    status="$(vm_status)"
    echo "VM '$VM_NAME': $status"
    if [ "$status" = "Running" ]; then
        limactl list | head -1
        limactl list | grep "$VM_NAME" || true
    fi
}

# --- Main ---
check_limactl

case "${1:-}" in
    setup)    cmd_setup ;;
    shell)    cmd_shell ;;
    build)    cmd_build ;;
    test)     cmd_test ;;
    security) cmd_security ;;
    stop)     cmd_stop ;;
    destroy)  cmd_destroy ;;
    status)   cmd_status ;;
    *)
        echo "Usage: $(basename "$0") <command>"
        echo ""
        echo "Commands:"
        echo "  setup      Create + start VM, wait for Rust (idempotent)"
        echo "  shell      Enter VM shell at project directory"
        echo "  build      cargo build --workspace inside VM"
        echo "  test       cargo test --workspace inside VM"
        echo "  security   Run security tests (sudo) inside VM"
        echo "  stop       Stop VM"
        echo "  destroy    Delete VM entirely"
        echo "  status     Show VM status"
        exit 1
        ;;
esac
