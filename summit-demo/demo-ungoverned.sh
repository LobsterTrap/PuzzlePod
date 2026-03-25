#!/bin/bash
# Summit Demo — Laptop 2 (Ubuntu 22/24, no PuzzlePod)
#
# Runs the SAME bad-agent container image WITHOUT governance.
# All malicious actions succeed. No audit trail.
#
# Prerequisites:
#   - podman installed (sudo apt install podman)
#   - bad-agent image built or pulled
#
# Usage:
#   ./demo-ungoverned.sh

set -euo pipefail

IMAGE="${DEMO_IMAGE:-bad-agent}"

# Check that the image exists — it may be in root's storage if setup ran with sudo
if ! podman image exists "$IMAGE" 2>/dev/null; then
    echo "ERROR: Image '$IMAGE' not found."
    echo "  If setup ran with sudo, run this demo with: sudo ./demo-ungoverned.sh"
    echo "  Or rebuild as regular user: podman build -t bad-agent -f Containerfile.bad-agent ."
    exit 1
fi

echo ""
echo "=================================================================="
echo "  Laptop 2: UNGOVERNED — Plain Podman, no PuzzlePod"
echo "=================================================================="
echo ""
echo "  Image   : $IMAGE"
echo "  Mode    : Plain podman run (no governance)"
echo ""
echo "  No Landlock. No seccomp mediation. No OPA policy."
echo "  No OverlayFS branching. No audit trail."
echo "  The agent runs with full container permissions."
echo ""
echo "  Press Enter to start..."
read -r

# Run ungoverned: plain podman, no puzzle-podman wrapper, no governance
podman run \
    --rm \
    -it \
    "$IMAGE"

echo ""
echo "=================================================================="
echo "  Post-run: What governance looks like (hint: nothing)"
echo "=================================================================="
echo ""
echo "  No branch ID. No audit trail. No attestation chain."
echo "  No way to prove what the agent did or didn't do."
echo "  No policy was evaluated. No trust score exists."
echo ""
echo "  Compare to Laptop 1 (Fedora + PuzzlePod):"
echo ""
echo "    Laptop 1                         Laptop 2 (this machine)"
echo "    ─────────────────────────────    ─────────────────────────────"
echo "    /etc/shadow BLOCKED (Landlock)   /etc/shadow READABLE"
echo "    Cron job in OVERLAY (rejected)   Cron job WRITTEN (persists)"
echo "    Backdoor in OVERLAY (rejected)   Backdoor WRITTEN (persists)"
echo "    curl BLOCKED (network isolated)  curl SUCCEEDED (data sent)"
echo "    Escape BLOCKED (Landlock)        Sensitive files READABLE"
echo "    Signed audit trail + attestation NO audit trail"
echo "    Trust score + JWT-SVID identity  NO governance proof"
echo ""
echo "  This is the status quo for AI agent deployments."
echo ""
