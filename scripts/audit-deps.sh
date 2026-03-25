#!/bin/bash
# audit-deps.sh — Run cargo-deny to audit dependencies for security and licensing.
#
# Checks:
#   1. Known vulnerabilities (from RustSec advisory database)
#   2. License compatibility (allowlist-based)
#   3. Duplicate dependency versions (bloat detection)
#   4. Banned crates (supply chain risk)
#   5. Source verification (only crates.io allowed)
#
# Usage:
#   ./scripts/audit-deps.sh          # Run all checks
#   ./scripts/audit-deps.sh advisories  # Run only vulnerability checks
#
# Install cargo-deny: cargo install cargo-deny
# Configuration: deny.toml (project root)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Check if cargo-deny is installed
if ! command -v cargo-deny &> /dev/null; then
    echo "ERROR: cargo-deny is not installed."
    echo "Install with: cargo install cargo-deny"
    echo ""
    echo "Alternatively, run a basic audit with:"
    echo "  cargo audit  (requires cargo-audit)"
    exit 1
fi

# Run the specified check or all checks
CHECK="${1:-all}"

echo "=== PuzzlePod Dependency Audit ==="
echo "Config: deny.toml"
echo ""

# Show direct dependency count for context
echo "Direct dependencies:"
cargo tree --depth 1 --prefix none 2>/dev/null | wc -l | xargs echo "  count:"
echo ""
echo "Total dependency tree (including transitive):"
cargo tree --prefix none 2>/dev/null | wc -l | xargs echo "  count:"
echo ""

if [ "$CHECK" = "all" ]; then
    echo "--- Checking advisories (known vulnerabilities) ---"
    cargo deny check advisories 2>&1 || true
    echo ""

    echo "--- Checking licenses ---"
    cargo deny check licenses 2>&1 || true
    echo ""

    echo "--- Checking bans (duplicate versions, banned crates) ---"
    cargo deny check bans 2>&1 || true
    echo ""

    echo "--- Checking sources (registry verification) ---"
    cargo deny check sources 2>&1 || true
else
    echo "--- Checking: $CHECK ---"
    cargo deny check "$CHECK"
fi

echo ""
echo "=== Audit complete ==="
