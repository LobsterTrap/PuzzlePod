#!/bin/bash
# test_escape_vectors.sh — Validate kernel primitives block escape vectors.
#
# NOTE: This test validates that Linux kernel primitives (namespaces, seccomp,
# capabilities) correctly block syscall-level escapes. It uses `unshare --user`
# to create a user namespace (dropping real capabilities), simulating the
# privilege level of a sandboxed agent. For tests that exercise the actual
# puzzled sandbox configuration, see test_sandbox_escape.sh.
#
# Some operations (mount, chroot, pivot_root, nested unshare) are ALLOWED by
# design in user namespaces — these are blocked by seccomp in the real puzzled
# sandbox and are tested in test_sandbox_escape.sh instead.
#
# Run as root: sudo ./test_escape_vectors.sh

source "$(dirname "$0")/helpers.sh"

require_linux
require_root

echo "=== Escape Vector Tests ==="
echo ""

# Create a test cgroup scope for the sandbox
SANDBOX_CGROUP="/sys/fs/cgroup/puzzle.slice/agent-test-escape.scope"
mkdir -p "$SANDBOX_CGROUP" 2>/dev/null || true

# Use --user (without --map-root-user) to drop real capabilities.
# The process runs as unmapped UID (nobody) and lacks real root access.
UNSHARE="unshare --user --pid --fork"

# 1. ptrace — should be blocked by capability restrictions
echo "[1] ptrace escape vectors"
assert_eperm "ptrace ATTACH on init" \
    "$UNSHARE -- sh -c 'echo 0 > /proc/1/mem'" 2>/dev/null

# 2. mount — ALLOWED in user+mount NS by design (blocked by seccomp in puzzled)
echo "[2] mount escape vectors"
skip_test "mount proc allowed in user+mount NS by design (seccomp blocks in puzzled sandbox)"

# 3. setns — should be blocked by capability restrictions
echo "[3] setns escape vectors"
assert_eperm "setns to init namespace via nsenter" \
    "$UNSHARE -- nsenter -t 1 -m -u -i -n -p -- true"

# 4. unshare — nested user NS creation allowed by design (blocked by seccomp in puzzled)
echo "[4] unshare escape vectors"
skip_test "nested unshare --user allowed in user NS by design (seccomp blocks in puzzled sandbox)"

# 5. BPF — should be blocked without CAP_BPF/CAP_SYS_ADMIN in init NS
echo "[5] BPF escape vectors"
assert_eperm "bpf prog load" \
    "$UNSHARE -- sh -c 'echo | bpf 2>/dev/null'" 2>/dev/null

# 6. kexec_load — should be blocked without CAP_SYS_BOOT in init NS
echo "[6] kexec_load escape vectors"
if command -v kexec &>/dev/null; then
    assert_eperm "kexec_load" \
        "$UNSHARE -- kexec -l /boot/vmlinuz 2>/dev/null"
else
    skip_test "kexec not installed"
fi

# 7. init_module / finit_module — should be blocked without CAP_SYS_MODULE
echo "[7] Module loading escape vectors"
assert_eperm "insmod" \
    "$UNSHARE -- insmod /nonexistent.ko 2>/dev/null"

# 8. reboot — should be blocked without CAP_SYS_BOOT in init NS
echo "[8] reboot escape vectors"
# IMPORTANT: Do NOT use the `reboot` command — on systemd systems it sends
# a D-Bus message (not the reboot syscall) and will actually reboot the host!
# Use runuser -u nobody to ensure no polkit authorization for reboot.
assert_eperm "reboot" \
    "runuser -u nobody -- reboot 2>/dev/null"

# 9. pivot_root — ALLOWED in user+mount NS by design (blocked by seccomp in puzzled)
echo "[9] pivot_root escape vectors"
skip_test "pivot_root allowed in user+mount NS by design (seccomp blocks in puzzled sandbox)"

# 10. mknod — should be blocked (device creation restricted in user NS)
echo "[10] Device creation escape vectors"
assert_eperm "mknod device" \
    "$UNSHARE -- mknod /tmp/test_dev b 8 0 2>/dev/null"

# 11. chroot — ALLOWED in user NS by design (blocked by seccomp in puzzled)
echo "[11] chroot escape vectors"
skip_test "chroot allowed in user NS by design (seccomp blocks in puzzled sandbox)"

# 12. /proc/sys write — should be blocked for non-root
echo "[12] /proc/sys write escape vectors"
assert_eperm "sysctl write" \
    "runuser -u nobody -- sh -c 'echo 1 > /proc/sys/kernel/sysrq 2>/dev/null'"

# 13. ioperm/iopl — should be blocked without CAP_SYS_RAWIO in init NS
echo "[13] I/O privilege escape vectors"
assert_eperm "iopl" \
    "$UNSHARE -- sh -c 'python3 -c \"import ctypes; ctypes.CDLL(None).iopl(3)\" 2>/dev/null'"

# 14. acct — should be blocked without CAP_SYS_PACCT in init NS
echo "[14] Process accounting escape vectors"
assert_eperm "acct" \
    "$UNSHARE -- sh -c 'python3 -c \"import os; os.acct(\\\"/tmp/acct\\\")\" 2>/dev/null'"

# 15. userfaultfd — may be allowed on modern kernels (vm.unprivileged_userfaultfd=1)
echo "[15] userfaultfd escape vectors"
# On kernels 5.11+, userfaultfd is allowed for unprivileged users by default.
# In the puzzled sandbox, seccomp blocks it. Skip if allowed by kernel config.
UNPRIVILEGED_USERFAULTFD=$(cat /proc/sys/vm/unprivileged_userfaultfd 2>/dev/null || echo "1")
if [ "$UNPRIVILEGED_USERFAULTFD" = "1" ]; then
    skip_test "userfaultfd allowed by vm.unprivileged_userfaultfd=1 (seccomp blocks in puzzled sandbox)"
else
    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ]; then
        NR_USERFAULTFD=282
    else
        NR_USERFAULTFD=323  # x86_64
    fi
    assert_eperm "userfaultfd" \
        "$UNSHARE -- sh -c 'python3 -c \"
import ctypes, sys
libc = ctypes.CDLL(None)
ret = libc.syscall($NR_USERFAULTFD, 0)
sys.exit(0 if ret >= 0 else 1)
\" 2>/dev/null'"
fi

# 16. perf_event_open — may be allowed by kernel.perf_event_paranoid
echo "[16] Performance monitoring escape vectors"
PERF_PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "2")
if [ "$PERF_PARANOID" -lt 3 ]; then
    skip_test "perf_event_open allowed by perf_event_paranoid=$PERF_PARANOID (seccomp blocks in puzzled sandbox)"
elif command -v perf &>/dev/null; then
    assert_eperm "perf_event_open" \
        "runuser -u nobody -- perf stat true 2>/dev/null"
else
    skip_test "perf not installed"
fi

# Cleanup
rmdir "$SANDBOX_CGROUP" 2>/dev/null || true

echo ""
print_summary "Escape Vector Tests"
