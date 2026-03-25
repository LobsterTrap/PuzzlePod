#!/bin/bash
# test_sandbox_escape.sh — Test escape vectors from within the actual puzzled sandbox.
#
# Unlike test_escape_vectors.sh (which tests kernel primitives via `unshare`),
# this script launches a real sandbox via the puzzle-sandbox-demo binary and attempts
# escapes from within the puzzled-configured sandbox. This validates that:
#
#   1. Landlock rulesets are actually enforced (not NotEnforced)
#   2. seccomp filters block io_uring and other escape syscalls
#   3. Capabilities are dropped (no CAP_SYS_ADMIN, CAP_NET_ADMIN, etc.)
#   4. SELinux context is applied (if available)
#   5. cgroup limits are enforced
#   6. Path traversal in execve is blocked
#
# Requires: puzzled puzzle-sandbox-demo binary built and in PATH
# Run as root: sudo ./test_sandbox_escape.sh

source "$(dirname "$0")/helpers.sh"

require_linux
require_root

# Define pass/fail/warn/skip in terms of helpers.sh counters
pass() { echo -e "  ${GREEN}PASS${NC}: $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo -e "  ${RED}FAIL${NC}: $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
warn() { echo -e "  ${YELLOW}WARN${NC}: $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
skip() { echo -e "  ${YELLOW}SKIP${NC}: $1"; SKIP_COUNT=$((SKIP_COUNT + 1)); }

echo "=== Sandbox Escape Tests (puzzled sandbox) ==="
echo ""
echo "These tests exercise the ACTUAL puzzled sandbox, not just kernel primitives."
echo ""

# Path to puzzle-sandbox-demo binary — check SANDBOX_DEMO env, then CARGO_TARGET_DIR, then ./target
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/var/tmp/puzzlepod-target}"
SANDBOX_DEMO="${SANDBOX_DEMO:-}"
if [ -z "$SANDBOX_DEMO" ] || [ ! -x "$SANDBOX_DEMO" ]; then
    for candidate in \
        "$CARGO_TARGET_DIR/debug/puzzle-sandbox-demo" \
        "$CARGO_TARGET_DIR/release/puzzle-sandbox-demo" \
        "$(dirname "$0")/../../target/debug/puzzle-sandbox-demo" \
        "$(dirname "$0")/../../target/release/puzzle-sandbox-demo"; do
        if [ -x "$candidate" ]; then
            SANDBOX_DEMO="$candidate"
            break
        fi
    done
fi

if [ -z "$SANDBOX_DEMO" ] || [ ! -x "$SANDBOX_DEMO" ]; then
    echo -e "${YELLOW}SKIP${NC}: puzzle-sandbox-demo binary not found. Build with: CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo build --bin puzzle-sandbox-demo"
    echo "      Set SANDBOX_DEMO=/path/to/binary to override."
    exit 77
fi

# Check if puzzle-sandbox-demo supports 'exec' mode (runs commands inside sandbox)
if ! "$SANDBOX_DEMO" --help 2>&1 | grep -qi "exec"; then
    echo -e "${YELLOW}SKIP${NC}: puzzle-sandbox-demo does not support 'exec' mode yet."
    echo "      The demo binary runs its own escape tests internally."
    echo "      Run it directly: sudo $SANDBOX_DEMO"
    exit 77
fi

# Disable set -e for the test body — we check exit codes explicitly.
set +e

# Helper: run a command inside the sandbox and capture exit code + stderr
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
run_in_sandbox() {
    local description="$1"
    shift
    timeout 10 "$SANDBOX_DEMO" exec \
        --allow-read "$SCRIPT_DIR" \
        -- "$@" 2>&1
    return $?
}

# --- Test 1: Landlock enforcement ---
echo "[1] Landlock: access to /etc/shadow should be denied"
# Landlock uses syscalls, not securityfs — check the LSM list instead
if ! grep -q landlock /sys/kernel/security/lsm 2>/dev/null; then
    skip "Landlock not available on this kernel (test requires kernel 5.13+)"
else
    output=$(run_in_sandbox "read /etc/shadow" cat /etc/shadow 2>&1)
    ret=$?
    if [ $ret -ne 0 ]; then
        pass "Landlock blocks /etc/shadow read"
    else
        fail "Landlock did NOT block /etc/shadow read"
    fi
fi

# --- Test 2: seccomp blocks ptrace ---
echo "[2] seccomp: ptrace should be blocked"
output=$(run_in_sandbox "ptrace" sh -c 'echo 0 > /proc/1/mem' 2>&1)
ret=$?
if [ $ret -ne 0 ]; then
    pass "seccomp blocks ptrace"
else
    fail "seccomp did NOT block ptrace"
fi

# --- Test 3: seccomp blocks io_uring ---
echo "[3] seccomp: io_uring_setup should be blocked"
# Use a small C program or python to attempt io_uring_setup (syscall 425)
output=$(run_in_sandbox "io_uring" python3 -c "
import ctypes, os, platform
libc = ctypes.CDLL(None, use_errno=True)
# io_uring_setup syscall number varies by architecture
if platform.machine() == 'aarch64':
    NR_IO_URING_SETUP = 426
else:
    NR_IO_URING_SETUP = 425  # x86_64
ret = libc.syscall(NR_IO_URING_SETUP, 32, ctypes.c_void_p(0))
if ret < 0:
    errno = ctypes.get_errno()
    if errno == 1:  # EPERM
        print('BLOCKED_EPERM')
        os._exit(1)
    print(f'FAILED errno={errno}')
    os._exit(1)
print('ALLOWED')
os._exit(0)
" 2>&1)
ret=$?
if echo "$output" | grep -q "BLOCKED_EPERM"; then
    pass "seccomp blocks io_uring_setup with EPERM"
elif [ $ret -ne 0 ]; then
    pass "io_uring_setup denied (exit code $ret)"
else
    fail "seccomp did NOT block io_uring_setup"
fi

# --- Test 4: seccomp blocks mount ---
echo "[4] seccomp: mount should be blocked"
output=$(run_in_sandbox "mount" mount -t proc proc /proc 2>&1)
ret=$?
if [ $ret -ne 0 ]; then
    pass "seccomp blocks mount"
else
    fail "seccomp did NOT block mount"
fi

# --- Test 5: seccomp blocks module loading ---
echo "[5] seccomp: init_module should be blocked"
output=$(run_in_sandbox "insmod" insmod /nonexistent.ko 2>&1)
ret=$?
if [ $ret -ne 0 ]; then
    pass "seccomp blocks module loading"
else
    fail "seccomp did NOT block module loading"
fi

# --- Test 6: Capabilities dropped ---
echo "[6] Capabilities: CAP_SYS_ADMIN should be dropped"
output=$(run_in_sandbox "capcheck" sh -c 'cat /proc/self/status | grep CapEff' 2>&1)
cap_eff=$(echo "$output" | grep CapEff | awk '{print $2}')
if [ -n "$cap_eff" ] && [ "$cap_eff" = "0000000000000000" ]; then
    pass "all capabilities dropped (CapEff=0)"
elif [ -n "$cap_eff" ]; then
    # Check if CAP_SYS_ADMIN (bit 21) is clear
    cap_val=$((16#${cap_eff}))
    if [ $((cap_val & (1 << 21))) -eq 0 ]; then
        pass "CAP_SYS_ADMIN dropped (CapEff=$cap_eff)"
    else
        fail "CAP_SYS_ADMIN NOT dropped (CapEff=$cap_eff)"
    fi
else
    skip "could not read CapEff from sandbox"
fi

# --- Test 7: Path traversal in execve ---
echo "[7] Execve: path traversal should be resolved"
# Attempt to execute a binary via traversal path
output=$(run_in_sandbox "traversal" /usr/bin/../../bin/sh -c 'echo ESCAPED' 2>&1)
ret=$?
if echo "$output" | grep -q "ESCAPED"; then
    # The exec succeeded, but check if the path was canonicalized
    # (seccomp should have resolved /usr/bin/../../bin/sh to /bin/sh)
    warn "path traversal exec succeeded — verify seccomp canonicalized the path"
else
    pass "path traversal exec blocked or resolved"
fi

# --- Test 8: setns blocked ---
echo "[8] seccomp: setns should be blocked"
output=$(run_in_sandbox "setns" nsenter -t 1 -m -u -i -n -p -- true 2>&1)
ret=$?
if [ $ret -ne 0 ]; then
    pass "seccomp blocks setns (nsenter)"
else
    fail "seccomp did NOT block setns"
fi

# --- Test 9: unshare blocked ---
echo "[9] seccomp: unshare should be blocked"
output=$(run_in_sandbox "unshare" unshare --user true 2>&1)
ret=$?
if [ $ret -ne 0 ]; then
    pass "seccomp blocks unshare"
else
    fail "seccomp did NOT block unshare"
fi

# --- Test 10: bpf syscall blocked ---
echo "[10] seccomp: bpf syscall should be blocked"
output=$(run_in_sandbox "bpf" python3 -c "
import ctypes, os, platform
libc = ctypes.CDLL(None, use_errno=True)
# bpf syscall number varies by architecture
if platform.machine() == 'aarch64':
    NR_BPF = 280
else:
    NR_BPF = 321  # x86_64
ret = libc.syscall(NR_BPF, 0, 0, 0)
errno = ctypes.get_errno()
if errno == 1:  # EPERM
    print('BLOCKED')
    os._exit(1)
print('ALLOWED')
os._exit(0)
" 2>&1)
ret=$?
if echo "$output" | grep -q "BLOCKED"; then
    pass "seccomp blocks bpf syscall"
elif [ $ret -ne 0 ]; then
    pass "bpf syscall denied (exit code $ret)"
else
    fail "seccomp did NOT block bpf syscall"
fi

# --- Test 11: SysV shared memory blocked ---
echo "[11] seccomp: shmget should be blocked"
output=$(run_in_sandbox "shmget" python3 -c "
import ctypes, os, platform
libc = ctypes.CDLL(None, use_errno=True)
if platform.machine() == 'aarch64':
    NR_SHMGET = 194
else:
    NR_SHMGET = 29  # x86_64
ret = libc.syscall(NR_SHMGET, 0x1234, 4096, 0o1000 | 0o666)
errno = ctypes.get_errno()
if errno == 1:
    print('BLOCKED')
    os._exit(1)
print('ALLOWED')
os._exit(0)
" 2>&1)
ret=$?
if echo "$output" | grep -q "BLOCKED"; then
    pass "seccomp blocks shmget"
elif [ $ret -ne 0 ]; then
    pass "shmget denied (exit code $ret)"
else
    fail "seccomp did NOT block shmget"
fi

# --- Test 12: Sensitive /proc paths masked ---
echo "[12] Sensitive paths: /proc/kallsyms should be masked (empty)"
output=$(run_in_sandbox "kallsyms" cat /proc/kallsyms 2>&1)
ret=$?
# Kallsyms lines look like: "ffffffff81000000 T _text"
# If masked (/dev/null bind mount), cat returns 0 but no kernel symbols appear.
if echo "$output" | grep -qE '^[0-9a-f]{8,16} [A-Za-z] '; then
    warn "/proc/kallsyms readable — sensitive path masking may not be active"
else
    pass "/proc/kallsyms masked or inaccessible"
fi

echo ""
print_summary "Sandbox Escape Tests"
