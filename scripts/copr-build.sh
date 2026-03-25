#!/bin/bash
# Build puzzled RPMs on Fedora COPR (copr.fedorainfracloud.org)
#
# Usage: ./scripts/copr-build.sh [OPTIONS]
#
# This script wraps copr-cli buildscm to build puzzled RPMs for
# Fedora 42, RHEL 10, and EPEL 10 (x86_64 + aarch64).

set -euo pipefail

# Defaults
COMMIT="v0.1-strengthening"
SPEC="packaging/puzzled.spec"
PROJECT="PuzzlePod"
CLONE_URL="https://github.com/LobsterTrap/PuzzlePod.git"
CONFIG="$HOME/.config/copr"
DRY_RUN=false

usage() {
    cat <<'EOF'
Build puzzled RPMs on Fedora COPR.

Usage: ./scripts/copr-build.sh [OPTIONS]

Options:
  -c, --commit BRANCH    Branch or tag to build (default: v0.1-strengthening)
  -s, --spec PATH        Spec file relative to repo root (default: packaging/puzzled.spec)
  -p, --project NAME     COPR project name (default: PuzzlePod)
  -u, --clone-url URL    Git clone URL (default: github.com/LobsterTrap/PuzzlePod.git)
      --config PATH      copr-cli config file (default: ~/.config/copr)
  -n, --dry-run          Print the command without executing
  -h, --help             Show this help

Examples:
  # Build from current branch
  ./scripts/copr-build.sh

  # Build from main branch
  ./scripts/copr-build.sh --commit main

  # Build a tagged release
  ./scripts/copr-build.sh --commit v0.2.0

  # Dry run to see the command
  ./scripts/copr-build.sh --commit main --dry-run

Notes:
  - RPM version comes from the spec file's Version: field
  - Each build replaces the previous in the COPR repo
  - aarch64 builds are QEMU-emulated and take 1-2 hours
  - Config file must exist at ~/.config/copr (get token from
    https://copr.fedorainfracloud.org/api/)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--commit)   COMMIT="$2"; shift 2 ;;
        -s|--spec)     SPEC="$2"; shift 2 ;;
        -p|--project)  PROJECT="$2"; shift 2 ;;
        -u|--clone-url) CLONE_URL="$2"; shift 2 ;;
        --config)      CONFIG="$2"; shift 2 ;;
        -n|--dry-run)  DRY_RUN=true; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ ! -f "$CONFIG" ]]; then
    echo "Error: Config file not found: $CONFIG" >&2
    echo "Get your API token from https://copr.fedorainfracloud.org/api/" >&2
    exit 1
fi

if ! command -v copr-cli &>/dev/null; then
    echo "Error: copr-cli not found. Install with: pipx install copr-cli" >&2
    exit 1
fi

CMD=(
    copr-cli --config "$CONFIG" buildscm
    --clone-url "$CLONE_URL"
    --commit "$COMMIT"
    --method make_srpm
    --spec "$SPEC"
    "$PROJECT"
)

echo "Building RPMs:"
echo "  Project:  $PROJECT"
echo "  Branch:   $COMMIT"
echo "  Spec:     $SPEC"
echo "  Repo:     $CLONE_URL"
echo ""

if $DRY_RUN; then
    echo "[dry-run] ${CMD[*]}"
else
    "${CMD[@]}"
fi
