#!/bin/bash
# test_cgroup_escape.sh — Test cgroup v2 escape resistance.
#
# Tests that a non-root process (simulating a sandboxed agent after
# switch_credentials()) cannot modify the host cgroup hierarchy.
#
# Uses `runuser -u nobody` to simulate the non-root UID that puzzled
# assigns to agents after sandbox setup.
#
# Note: In the puzzled sandbox, cgroup access is also blocked by mount
# namespace (hides host cgroupfs) and Landlock (blocks /sys/fs/cgroup).
#
# Run as root: sudo ./test_cgroup_escape.sh

source "$(dirname "$0")/helpers.sh"

require_linux
require_root

echo "=== Cgroup Escape Tests ==="
echo ""

CGROUP_ROOT="/sys/fs/cgroup"

# Check cgroup.procs permissions — if world-writable, skip write tests
# (mount NS + Landlock are the actual protections in puzzled)
PROCS_PERMS=$(stat -c '%a' "$CGROUP_ROOT/cgroup.procs" 2>/dev/null || echo "644")
PROCS_WORLD_WRITABLE=false
if [ $(((PROCS_PERMS % 10) & 2)) -ne 0 ]; then
    PROCS_WORLD_WRITABLE=true
fi

# Use runuser to run as non-root, matching puzzled's switch_credentials()
NONROOT="runuser -u nobody --"

# 1. Write to cgroup.procs
echo "[1] Cgroup tree traversal"
if [ "$PROCS_WORLD_WRITABLE" = "true" ]; then
    skip_test "cgroup.procs is world-writable (mode $PROCS_PERMS); mount NS + Landlock block in puzzled"
else
    assert_eperm "write to parent cgroup" \
        "$NONROOT sh -c 'echo 0 > $CGROUP_ROOT/cgroup.procs 2>/dev/null'"
fi

# 2. Create new cgroup scope
echo "[2] Cgroup creation"
assert_eperm "create new cgroup" \
    "$NONROOT mkdir $CGROUP_ROOT/escape_cgroup 2>/dev/null"

# 3. Modify resource limits
echo "[3] Resource limit modification"
assert_eperm "modify memory.max" \
    "$NONROOT sh -c 'echo max > $CGROUP_ROOT/memory.max 2>/dev/null'"

# 4. Move process to root cgroup
echo "[4] Process migration"
if [ "$PROCS_WORLD_WRITABLE" = "true" ]; then
    skip_test "cgroup.procs is world-writable (mode $PROCS_PERMS); mount NS + Landlock block in puzzled"
else
    assert_eperm "migrate to root cgroup" \
        "$NONROOT sh -c 'echo \$\$ > $CGROUP_ROOT/cgroup.procs 2>/dev/null'"
fi

# 5. cgroup release_agent abuse
echo "[5] release_agent abuse"
# release_agent was removed in cgroup v2, but test anyway
assert_eperm "release_agent write" \
    "$NONROOT sh -c 'echo /tmp/exploit > $CGROUP_ROOT/release_agent 2>/dev/null'"

# 6. Freeze/thaw escape
echo "[6] Freeze/thaw manipulation"
assert_eperm "unfreeze self" \
    "$NONROOT sh -c 'echo 0 > $CGROUP_ROOT/cgroup.freeze 2>/dev/null'"

# 7. Memory overcommit
echo "[7] Memory overcommit attack"
# Requires a dedicated cgroup with memory.max set — cannot verify without
# puzzled sandbox setup. Mark as SKIP to avoid false confidence.
skip_test "requires puzzled sandbox with cgroup memory.max configured"

# 8. CPU starvation
echo "[8] CPU starvation prevention"
# Requires a dedicated cgroup with cpu.weight set.
skip_test "requires puzzled sandbox with cgroup cpu.weight configured"

# 9. I/O starvation
echo "[9] I/O starvation prevention"
# Requires a dedicated cgroup with io.weight set.
skip_test "requires puzzled sandbox with cgroup io.weight configured"

# 10. PID exhaustion
echo "[10] PID exhaustion"
# Requires a dedicated cgroup with pids.max set. To properly test, we would
# need to fork-bomb inside a cgroup and verify the kernel enforces the limit.
skip_test "requires puzzled sandbox with cgroup pids.max configured"

echo ""
print_summary "Cgroup Escape Tests"
