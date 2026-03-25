#!/bin/bash
# Summit Demo — Laptop 1 (Fedora/RHEL 10 + PuzzlePod)
#
# Runs the bad-agent container GOVERNED by PuzzlePod in Podman-native mode.
# Kernel-enforced guardrails block malicious actions.
#
# Prerequisites:
#   - puzzled running (systemctl start puzzled)
#   - puzzle-podman, puzzlectl, puzzle-hook, puzzle-init installed
#   - summit-demo profile installed (/etc/puzzled/profiles/summit-demo.yaml)
#   - bad-agent image built (podman build -t bad-agent ...)
#   - OCI hook config installed (/usr/share/containers/oci/hooks.d/puzzlepod.json)
#
# Usage:
#   ./demo-governed.sh
#   ./demo-governed.sh --auto-commit    # auto-commit (will be rejected by policy)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${DEMO_IMAGE:-bad-agent}"
PROFILE="${DEMO_PROFILE:-summit-demo}"

echo ""
echo "=================================================================="
echo "  Laptop 1: GOVERNED — PuzzlePod + Podman-native mode"
echo "=================================================================="
echo ""
echo "  Image   : $IMAGE"
echo "  Profile : $PROFILE"
echo "  Mode    : Podman-native (puzzle-podman --native)"
echo ""
echo "  Governance stack:"
echo "    Landlock    — kernel-enforced filesystem ACL (irrevocable)"
echo "    seccomp     — static deny for escape-vector syscalls"
echo "    OPA/Rego    — policy evaluation at commit time"
echo "    OverlayFS   — copy-on-write isolation"
echo "    puzzle-hook — OCI hook for AttachGovernance/TriggerGovernance"
echo "    puzzle-init — Landlock shim (container entrypoint)"
echo ""
echo "  Press Enter to start..."
read -r

# Run governed: puzzle-podman creates branch, generates seccomp + Landlock,
# runs podman with puzzle-init as entrypoint, puzzle-hook fires at
# createRuntime and poststop.
# --no-seccomp-notif: use static seccomp filter only (no USER_NOTIF listener).
# TODO: Enable seccomp USER_NOTIF once puzzled's notification socket listener
# is wired up for Podman-native mode.
# Capture output so we can extract the branch ID
AGENT_OUTPUT=$(mktemp)
puzzle-podman run \
    --puzzle-branch \
    --profile="$PROFILE" \
    --native \
    --no-seccomp-notif \
    --agent-auto-commit \
    --rm \
    -it \
    "$IMAGE" 2>&1 | tee "$AGENT_OUTPUT" || true

# Extract branch ID from puzzle-podman output
BRANCH_ID=$(grep -o 'Branch created: [a-f0-9-]*' "$AGENT_OUTPUT" | head -1 | sed 's/Branch created: //')
rm -f "$AGENT_OUTPUT"

# Save branch ID for demo-attestation.sh to pick up
if [ -n "$BRANCH_ID" ]; then
    echo "$BRANCH_ID" > /tmp/summit-demo-branch-id
fi

echo ""
echo "=================================================================="
echo "  Post-run: Governance verification"
echo "=================================================================="
echo ""

if [ -n "$BRANCH_ID" ]; then
    echo "  Branch: $BRANCH_ID"
    echo "  (Branch was rolled back — governance rejected the changeset)"
    echo ""

    echo "--- Audit trail (persists after rollback) ---"
    puzzlectl audit list --branch-id "$BRANCH_ID" 2>/dev/null || echo "  (no audit events found)"
    echo ""

    echo "--- Attestation chain ---"
    puzzlectl attestation verify --branch-id "$BRANCH_ID" 2>/dev/null || echo "  (attestation verification not available)"
    echo ""
else
    echo "  (could not determine branch ID from puzzle-podman output)"
fi

echo ""
echo "=================================================================="
echo "  Result: Base filesystem is untouched"
echo "=================================================================="
echo ""
echo "  The cron job and systemd backdoor never reached the host."
echo "  Verifying:"
echo ""
echo -n "    /etc/cron.d/updater:                 "
if [ -f /etc/cron.d/updater ]; then echo "EXISTS (BAD!)"; else echo "does not exist (GOOD)"; fi
echo -n "    /etc/systemd/system/backdoor.service: "
if [ -f /etc/systemd/system/backdoor.service ]; then echo "EXISTS (BAD!)"; else echo "does not exist (GOOD)"; fi
echo ""
