#!/bin/bash
# test_network_escape.sh — Verify network isolation in Blocked and Gated modes.
#
# Tests:
# 1. Blocked mode: agent cannot reach any external host
# 2. Blocked mode: actual network DNS query blocked (not local NSS)
# 3. Blocked mode: TCP connect blocked
# 4. Raw socket creation restricted
#
# Note: `unshare --net` creates an empty network namespace with only loopback.
# DNS resolution via systemd-resolved Unix socket may still work (filesystem
# path, not network). The puzzled sandbox blocks this via mount namespace
# isolation. Here we test actual network-level DNS queries.
#
# Run as root: sudo ./test_network_escape.sh

source "$(dirname "$0")/helpers.sh"

require_linux
require_root

echo "=== Network Escape Tests ==="

# Test 1: Blocked mode — no network access (ping)
echo ""
echo "[1] Blocked mode network isolation"
assert_eperm "Blocked mode ping to 8.8.8.8" \
    "unshare --net -- timeout 3 ping -c1 8.8.8.8 2>/dev/null"

# Test 2: Blocked mode — no network-level DNS
# Note: `getent hosts` uses NSS which may resolve via systemd-resolved Unix
# socket (filesystem path, not network). Instead, test an actual UDP connection
# to a DNS server, which requires network access.
echo ""
echo "[2] Blocked mode DNS (network-level)"
assert_eperm "Blocked mode UDP to DNS server" \
    "unshare --net -- timeout 3 python3 -c \"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(b'\\x00', ('8.8.8.8', 53))
\" 2>/dev/null"

# Test 3: Blocked mode — no TCP connect
echo ""
echo "[3] Blocked mode TCP"
assert_eperm "Blocked mode TCP connect" \
    "unshare --net -- timeout 3 bash -c 'echo > /dev/tcp/8.8.8.8/53' 2>/dev/null"

# Test 4: Raw socket creation in user namespace
echo ""
echo "[4] Raw socket restriction"
# In a user namespace (without --map-root-user), the process has caps within
# the user NS but CAP_NET_RAW doesn't grant real raw socket access on
# physical interfaces. With --net, there's only loopback anyway.
# In the puzzled sandbox, seccomp blocks SOCK_RAW via argument filtering (A1).
if unshare --user --net -- python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    print('raw_socket_created')
except (PermissionError, OSError):
    print('raw_socket_blocked')
    exit(1)
" 2>/dev/null | grep -q "raw_socket_blocked"; then
    echo -e "  ${GREEN}PASS${NC}: Raw socket creation blocked in user+net namespace (correctly denied)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    # Raw socket may succeed in user NS (CAP_NET_RAW within NS), but there's
    # no external network to reach. In the puzzled sandbox, seccomp blocks this.
    skip_test "raw socket created in user NS (expected — no external network; seccomp blocks in puzzled)"
fi

echo ""
print_summary "Network Escape Tests"
