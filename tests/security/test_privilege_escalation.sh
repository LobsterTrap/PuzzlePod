#!/bin/bash
# test_privilege_escalation.sh — Test that agents cannot escalate privileges.
#
# Tests capability escalation, SUID exploitation, and other privesc vectors.
# Uses `runuser -u nobody` to simulate a non-root sandboxed agent.
#
# Run as root: sudo ./test_privilege_escalation.sh

source "$(dirname "$0")/helpers.sh"

require_linux
require_root

echo "=== Privilege Escalation Tests ==="
echo ""

# Use runuser to run as non-root, matching puzzled's switch_credentials()
NONROOT="runuser -u nobody --"

# 1. CAP_SYS_ADMIN escalation
echo "[1] Capability escalation"
assert_eperm "setcap within namespace" \
    "$NONROOT setcap cap_sys_admin+eip /bin/cat 2>/dev/null"

# 2. SUID bit manipulation
echo "[2] SUID/SGID manipulation"
TMPBIN=$(mktemp)
cp /bin/true "$TMPBIN"
assert_eperm "chmod +s" \
    "$NONROOT chmod u+s $TMPBIN 2>/dev/null"
rm -f "$TMPBIN"

# 3. Writing to /etc/passwd
echo "[3] System file modification"
assert_eperm "write /etc/passwd" \
    "$NONROOT sh -c 'echo \"hacker:x:0:0::/root:/bin/bash\" >> /etc/passwd 2>/dev/null'"

# 4. Writing to /etc/sudoers
assert_eperm "write /etc/sudoers" \
    "$NONROOT sh -c 'echo \"ALL ALL=(ALL) NOPASSWD: ALL\" >> /etc/sudoers 2>/dev/null'"

# 5. cgroup escape via release_agent
echo "[4] cgroup escape via release_agent"
assert_eperm "cgroup release_agent" \
    "$NONROOT sh -c 'echo /tmp/exploit.sh > /sys/fs/cgroup/release_agent 2>/dev/null'"

# 6. UID/GID manipulation
echo "[5] UID/GID manipulation"
assert_eperm "setuid to root" \
    "$NONROOT sh -c 'python3 -c \"import os; os.setuid(0)\" 2>/dev/null'"

# 7. Capabilities via prctl
echo "[6] prctl capability manipulation"
# prctl(PR_SET_NO_NEW_PRIVS, 0) tries to CLEAR no_new_privs (irreversible).
# Kernel returns EINVAL. ctypes doesn't raise on C errors, so check return.
assert_eperm "PR_SET_NO_NEW_PRIVS bypass" \
    "$NONROOT sh -c 'python3 -c \"
import ctypes, sys
ret = ctypes.CDLL(None).prctl(38, 0)
sys.exit(0 if ret == 0 else 1)
\" 2>/dev/null'"

# 8. Access /proc/kcore
echo "[7] Kernel memory access"
assert_eperm "read /proc/kcore" \
    "$NONROOT cat /proc/kcore 2>/dev/null"

# 9. Access /dev/mem
echo "[8] Physical memory access"
assert_eperm "read /dev/mem" \
    "$NONROOT cat /dev/mem 2>/dev/null"

# 10. Loading kernel modules
echo "[9] Kernel module loading"
assert_eperm "modprobe" \
    "$NONROOT modprobe dummy 2>/dev/null"

echo ""
print_summary "Privilege Escalation Tests"
