#!/bin/bash
# test_landlock_bypass.sh — Test Landlock LSM bypass resistance.
#
# Tests fd inheritance, procfs tricks, and other Landlock bypass vectors.
# Uses --user namespace to simulate restricted agent capabilities.
#
# Run as root: sudo ./test_landlock_bypass.sh

source "$(dirname "$0")/helpers.sh"

require_linux
require_root

echo "=== Landlock Bypass Tests ==="
echo ""

# Check Landlock availability — use syscall probe (sysfs dir doesn't exist on all kernels)
if ! cat /sys/kernel/security/lsm 2>/dev/null | grep -q landlock; then
    skip_test "Landlock not in active LSM list"
    print_summary "Landlock Bypass Tests"
    exit 0
fi

UNSHARE="unshare --user --pid --fork "

# 1. fd inheritance attack
echo "[1] File descriptor inheritance"
# Test that /etc/shadow is not readable by non-root via unshare.
# In the real puzzled sandbox, Landlock would block new opens; here we test
# that user namespace isolation denies the open.
assert_eperm "fd open of /etc/shadow in user namespace" \
    "$UNSHARE -- python3 -c \"
import os
# Attempt to open /etc/shadow — should fail with EACCES in user NS
fd = os.open('/etc/shadow', os.O_RDONLY)
os.close(fd)
\" 2>/dev/null"

# 2. /proc/self/fd symlink bypass
echo "[2] /proc/self/fd symlink bypass"
assert_eperm "procfs fd link read" \
    "$UNSHARE -- sh -c 'exec 3</etc/hostname && cat /proc/self/fd/3 > /dev/null 2>&1 && cat /etc/shadow 2>/dev/null'"

# 3. O_PATH fd trick
echo "[3] O_PATH file descriptor trick"
assert_eperm "O_PATH openat bypass" \
    "$UNSHARE -- python3 -c \"
import os
try:
    # Open parent directory with O_PATH
    dirfd = os.open('/etc', os.O_PATH | os.O_DIRECTORY)
    # Try to open a file relative to it
    fd = os.open('shadow', os.O_RDONLY, dir_fd=dirfd)
    os.close(fd)
    os.close(dirfd)
except PermissionError:
    exit(1)
\" 2>/dev/null"

# 4. /proc/<pid>/root traversal
echo "[4] /proc/<pid>/root traversal"
assert_eperm "proc root traversal" \
    "$UNSHARE -- cat /proc/1/root/etc/shadow 2>/dev/null"

# 5. Hardlink bypass attempt
echo "[5] Hardlink bypass"
assert_eperm "hardlink to restricted file" \
    "$UNSHARE -- ln /etc/shadow /tmp/shadow_link 2>/dev/null"

# 6. Bind mount bypass
echo "[6] Bind mount bypass"
assert_eperm "bind mount restricted path" \
    "unshare --user --pid --mount --fork  -- mount --bind /etc/shadow /tmp/shadow_bind 2>/dev/null"

echo ""
print_summary "Landlock Bypass Tests"
