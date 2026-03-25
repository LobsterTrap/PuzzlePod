#!/bin/bash
# Performance benchmark runner for PuzzlePod.
#
# Runs Criterion benchmarks and reports results against PRD targets.
# Usage: cd tests/performance && ./bench.sh [--quick]
#
# PRD Performance Targets (from CLAUDE.md):
#   Branch creation (sandbox setup):  < 50ms (x86_64), < 100ms (aarch64)
#   File I/O overhead (OverlayFS):    < 10%
#   Branch commit (1K files, WAL):    < 2s (x86_64), < 3s (aarch64)
#   Branch rollback:                  < 10ms
#   Concurrent branches:              64 (x86_64), 8 (edge)
#   puzzled memory:                    < 50MB + 5MB/branch

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CARGO="${CARGO:-cargo}"
QUICK=0
BENCH_OUTPUT="/tmp/puzzled_bench_output.txt"

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --quick)
            QUICK=1
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--quick]"
            echo ""
            echo "Options:"
            echo "  --quick    Run fewer iterations (suitable for CI)"
            echo "  -h,--help  Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Detect platform
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        TARGET_BRANCH_CREATE="50ms"
        TARGET_COMMIT_1K="2s"
        TARGET_CONCURRENT="64"
        ;;
    aarch64)
        TARGET_BRANCH_CREATE="100ms"
        TARGET_COMMIT_1K="3s"
        TARGET_CONCURRENT="8 (edge) / 64 (server)"
        ;;
    *)
        TARGET_BRANCH_CREATE="N/A (unsupported arch)"
        TARGET_COMMIT_1K="N/A"
        TARGET_CONCURRENT="N/A"
        ;;
esac

echo "=== PuzzlePod Performance Benchmarks ==="
echo "Architecture:  $ARCH"
echo "Kernel:        $(uname -r)"
echo "Date:          $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Mode:          $([ $QUICK -eq 1 ] && echo 'quick (reduced iterations)' || echo 'full')"
echo ""

# Build benchmark arguments
BENCH_ARGS=(-p puzzled)
if [ $QUICK -eq 1 ]; then
    BENCH_ARGS+=(-- --quick --warm-up-time 1 --measurement-time 3)
fi

# Run Criterion benchmarks (all suites)
echo "--- Running Criterion benchmarks ---"
cd "$REPO_ROOT"
$CARGO bench "${BENCH_ARGS[@]}" 2>&1 | tee "$BENCH_OUTPUT"

echo ""
echo "--- Benchmark Results Summary ---"
echo ""

# Extract timing results from Criterion output
if grep -qE "time:.*\[" "$BENCH_OUTPUT" 2>/dev/null; then
    printf "%-45s %s\n" "BENCHMARK" "TIME"
    printf "%-45s %s\n" "---------" "----"
    grep -E "^[a-z_]+/" "$BENCH_OUTPUT" | while IFS= read -r line; do
        bench_name=$(echo "$line" | sed 's/\s*time:.*//')
        bench_time=$(echo "$line" | grep -oE 'time:\s*\[[^]]+\]' || echo "")
        if [ -n "$bench_time" ]; then
            printf "%-45s %s\n" "$bench_name" "$bench_time"
        fi
    done
    echo ""
else
    echo "(no timing results found — run on Linux with real kernel primitives for full results)"
    echo ""
fi

echo "--- PRD Target Comparison ($ARCH) ---"
echo ""
printf "%-35s %-20s %-15s\n" "METRIC" "TARGET" "STATUS"
printf "%-35s %-20s %-15s\n" "------" "------" "------"
printf "%-35s %-20s %-15s\n" "Branch creation (sandbox setup)" "< $TARGET_BRANCH_CREATE" "(see benchmarks)"
printf "%-35s %-20s %-15s\n" "File I/O overhead (OverlayFS)" "< 10%" "(requires fio)"
printf "%-35s %-20s %-15s\n" "Commit (1K files, WAL)" "< $TARGET_COMMIT_1K" "(see benchmarks)"
printf "%-35s %-20s %-15s\n" "Branch rollback" "< 10ms" "(see benchmarks)"
printf "%-35s %-20s %-15s\n" "Concurrent branches" "$TARGET_CONCURRENT" "(see benchmarks)"
printf "%-35s %-20s %-15s\n" "puzzled memory" "< 50MB + 5MB/branch" "(requires valgrind)"
printf "%-35s %-20s %-15s\n" "Landlock check latency" "< 1 μs" "(kernel, not benchmarked)"
printf "%-35s %-20s %-15s\n" "BPF LSM check latency" "< 1 μs" "(kernel, not benchmarked)"
printf "%-35s %-20s %-15s\n" "seccomp USER_NOTIF per call" "~50-100 μs" "(requires Linux)"
echo ""
echo "NOTE: Full PRD target validation requires running on Linux with root"
echo "privileges and real kernel primitives (clone3, OverlayFS, namespaces)."
echo "The Criterion benchmarks measure component-level performance (diff engine,"
echo "WAL, policy evaluation, commit executor). End-to-end sandbox creation"
echo "timing requires the integration test suite on a Linux host."
echo ""
echo "=== Done ==="
