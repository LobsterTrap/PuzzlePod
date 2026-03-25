#!/bin/bash
# run_all.sh — Run all PuzzlePod security tests.
#
# Usage: sudo ./run_all.sh
#
# Runs all test_*.sh scripts in this directory and reports overall results.
# Exit codes: 0 = all passed/skipped, 1 = at least one failure.
# Individual test exit codes: 0 = pass, 1 = fail, 77 = skip.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/var/tmp/puzzlepod-target}"

# Export paths so individual test scripts can find binaries
export PUZZLECTL="${PUZZLECTL:-$CARGO_TARGET_DIR/debug/puzzlectl}"
export SANDBOX_DEMO="${SANDBOX_DEMO:-$CARGO_TARGET_DIR/debug/puzzle-sandbox-demo}"

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
SUITE_RESULTS=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}======================================${NC}"
echo -e "${BOLD}  PuzzlePod Security Test Suite${NC}"
echo -e "${BOLD}======================================${NC}"
echo ""

# Check prerequisites
if [ "$(uname -s)" != "Linux" ]; then
    echo -e "${YELLOW}SKIP: Security tests require Linux${NC}"
    exit 77
fi

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${YELLOW}SKIP: Security tests must be run as root${NC}"
    echo "Usage: sudo $0"
    exit 77
fi

echo "System: $(uname -r) ($(uname -m))"
echo "Date: $(date -Iseconds)"
echo ""

# Run each test suite
for test_script in "$SCRIPT_DIR"/test_*.sh; do
    if [ ! -x "$test_script" ]; then
        chmod +x "$test_script"
    fi

    suite_name=$(basename "$test_script" .sh)

    # test_rogue_agent requires running inside an puzzled sandbox
    # (e.g. puzzle-sandbox-demo exec -- bash test_rogue_agent.sh), not standalone.
    if [ "$suite_name" = "test_rogue_agent" ]; then
        echo -e "${YELLOW}SKIP${NC}  $suite_name (requires sandbox — run via: puzzle-sandbox-demo exec -- bash $test_script)"
        SUITE_RESULTS+=("${YELLOW}SKIP${NC}  $suite_name")
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
        echo ""
        continue
    fi
    echo -e "${BOLD}--- Running: $suite_name ---${NC}"

    set +e
    bash "$test_script" 2>&1
    ret=$?
    set -e

    if [ $ret -eq 0 ]; then
        SUITE_RESULTS+=("${GREEN}PASS${NC}  $suite_name")
        TOTAL_PASS=$((TOTAL_PASS + 1))
    elif [ $ret -eq 77 ]; then
        SUITE_RESULTS+=("${YELLOW}SKIP${NC}  $suite_name")
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
    else
        SUITE_RESULTS+=("${RED}FAIL${NC}  $suite_name")
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi

    echo ""
done

# Print overall summary
echo -e "${BOLD}======================================${NC}"
echo -e "${BOLD}  Overall Results${NC}"
echo -e "${BOLD}======================================${NC}"
echo ""

for result in "${SUITE_RESULTS[@]}"; do
    echo -e "  $result"
done

echo ""
echo -e "  ${GREEN}Passed${NC}: $TOTAL_PASS"
echo -e "  ${RED}Failed${NC}: $TOTAL_FAIL"
echo -e "  ${YELLOW}Skipped${NC}: $TOTAL_SKIP"
echo ""

if [ $TOTAL_FAIL -gt 0 ]; then
    echo -e "${RED}${BOLD}OVERALL: FAILED ($TOTAL_FAIL suite(s) failed)${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}OVERALL: PASSED ($TOTAL_PASS passed, $TOTAL_SKIP skipped)${NC}"
    exit 0
fi
