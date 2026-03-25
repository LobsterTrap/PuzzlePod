#!/bin/bash
# Summit Demo — Laptop 2 Setup (Ubuntu 22.04 / 24.04)
#
# Installs Podman and builds the demo image. No PuzzlePod.
# Run once before the demo.
#
# Prerequisites:
#   - Ubuntu 22.04+ or 24.04+ (x86_64 or aarch64)
#   - Root access (sudo)
#
# Usage:
#   sudo ./setup-laptop2-ubuntu.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=================================================================="
echo "  Summit Demo — Laptop 2 Setup (Ubuntu)"
echo "=================================================================="
echo ""

# ---------------------------------------------------------------------------
# 1. Install Podman
# ---------------------------------------------------------------------------

echo "--- 1. Installing Podman ---"
apt-get update -qq
apt-get install -y -qq podman
echo "  Podman version: $(podman --version)"
echo ""

# ---------------------------------------------------------------------------
# 2. Build the bad-agent container image
# ---------------------------------------------------------------------------

echo "--- 2. Building bad-agent container image ---"
# Build as root (matches sudo setup). demo-ungoverned.sh must also run with sudo,
# or re-run this build step as regular user.
podman build -t bad-agent -f "$SCRIPT_DIR/Containerfile.bad-agent" "$SCRIPT_DIR/"
echo "  Built: bad-agent (in root storage — run demo with: sudo ./demo-ungoverned.sh)"
echo ""

# ---------------------------------------------------------------------------
# 3. Verify
# ---------------------------------------------------------------------------

echo "--- 3. Verification ---"
echo "  Podman:  $(command -v podman)"
echo "  Image:   $(podman images --format '{{.Repository}}:{{.Tag}}' | grep bad-agent || echo 'NOT FOUND')"
echo ""

echo "  NOT installed (intentionally):"
echo "    puzzled       — no governance daemon"
echo "    puzzlectl     — no governance CLI"
echo "    puzzle-podman — no governance wrapper"
echo "    puzzle-hook — no OCI hook"
echo "    puzzle-init — no Landlock shim"
echo ""

echo "=================================================================="
echo "  Setup complete! Run the demo:"
echo "    cd summit-demo"
echo "    sudo ./demo-ungoverned.sh"
echo "=================================================================="
