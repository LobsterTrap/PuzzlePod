#!/bin/bash
# helpers.sh — Shared utilities for security tests.
#
# Source this file from test scripts:
#   source "$(dirname "$0")/helpers.sh"

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# Check if running as root
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${YELLOW}SKIP: Security tests must be run as root${NC}"
        exit 77
    fi
}

# Check if running on Linux
require_linux() {
    if [ "$(uname -s)" != "Linux" ]; then
        echo -e "${YELLOW}SKIP: Security tests require Linux${NC}"
        exit 77
    fi
}

# Check for required tools
require_tool() {
    local tool="$1"
    if ! command -v "$tool" &>/dev/null; then
        echo -e "${YELLOW}SKIP: Required tool '$tool' not found${NC}"
        return 1
    fi
    return 0
}

# Test assertion: command should fail with EPERM (exit code != 0)
# Always returns 0 so set -e doesn't abort; failures tracked in FAIL_COUNT.
assert_eperm() {
    local description="$1"
    shift
    local cmd="$*"

    if eval "$cmd" 2>/dev/null; then
        echo -e "  ${RED}FAIL${NC}: $description (should have been denied)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        echo -e "  ${GREEN}PASS${NC}: $description (correctly denied)"
        PASS_COUNT=$((PASS_COUNT + 1))
    fi
    return 0
}

# Test assertion: command should succeed
# Always returns 0 so set -e doesn't abort; failures tracked in FAIL_COUNT.
assert_success() {
    local description="$1"
    shift
    local cmd="$*"

    if eval "$cmd" 2>/dev/null; then
        echo -e "  ${GREEN}PASS${NC}: $description (succeeded as expected)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "  ${RED}FAIL${NC}: $description (unexpectedly failed)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    return 0
}

# Skip a test with a message
skip_test() {
    local description="$1"
    echo -e "  ${YELLOW}SKIP${NC}: $description"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

# Print test suite summary
print_summary() {
    local suite="$1"
    echo ""
    echo "=== $suite Summary ==="
    echo -e "  ${GREEN}Passed${NC}: $PASS_COUNT"
    echo -e "  ${RED}Failed${NC}: $FAIL_COUNT"
    echo -e "  ${YELLOW}Skipped${NC}: $SKIP_COUNT"
    echo ""

    if [ $FAIL_COUNT -gt 0 ]; then
        echo -e "${RED}RESULT: FAILED${NC}"
        return 1
    else
        echo -e "${GREEN}RESULT: PASSED${NC}"
        return 0
    fi
}

# Create a minimal sandbox environment for testing
# Usage: setup_sandbox <base_dir>
setup_sandbox() {
    local base="$1"
    mkdir -p "$base"/{upper,work,merged,lower}
    echo "test content" > "$base/lower/test.txt"
}

# Clean up sandbox
cleanup_sandbox() {
    local base="$1"
    umount "$base/merged" 2>/dev/null || true
    rm -rf "$base"
}
