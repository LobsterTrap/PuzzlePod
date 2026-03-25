#!/bin/bash
# Summit Demo — Laptop 1 Setup (Fedora 42 / RHEL 10)
#
# Installs PuzzlePod components and builds the demo image.
# Run once before the demo.
#
# Prerequisites:
#   - Fedora 42+ or RHEL 10+ (x86_64 or aarch64)
#   - Root access (sudo)
#   - Podman installed
#   - Rust toolchain (for building from source)
#
# Usage:
#   sudo ./setup-laptop1-fedora.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=================================================================="
echo "  Summit Demo — Laptop 1 Setup (Fedora/RHEL)"
echo "=================================================================="
echo ""

# ---------------------------------------------------------------------------
# 1. Install system dependencies
# ---------------------------------------------------------------------------

echo "--- 1. Installing system dependencies ---"
dnf install -y --setopt=install_weak_deps=False \
    podman \
    crun \
    dbus-daemon \
    dbus-tools \
    libseccomp-devel \
    iproute \
    xfsprogs \
    util-linux \
    procps-ng \
    2>/dev/null || echo "  (some packages may already be installed)"

# Verify crun version (need >= 1.14 for listenerPath)
CRUN_VERSION=$(crun --version 2>/dev/null | head -1 | awk '{print $NF}' || echo "0")
echo "  crun version: $CRUN_VERSION"

echo ""

# ---------------------------------------------------------------------------
# 2. Build PuzzlePod from source
# ---------------------------------------------------------------------------

echo "--- 2. Building PuzzlePod from source ---"
cd "$REPO_ROOT"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/var/tmp/puzzlepod-target}"
cargo build --release -p puzzled -p puzzlectl -p puzzle-hook -p puzzle-init
echo "  Built: puzzled, puzzlectl, puzzle-hook, puzzle-init"
echo ""

# ---------------------------------------------------------------------------
# 3. Install binaries
# ---------------------------------------------------------------------------

echo "--- 3. Installing binaries ---"
install -m 0755 "$CARGO_TARGET_DIR/release/puzzled" /usr/bin/puzzled
install -m 0755 "$CARGO_TARGET_DIR/release/puzzlectl" /usr/bin/puzzlectl
install -m 0755 "$CARGO_TARGET_DIR/release/puzzle-hook" /usr/libexec/puzzle-hook
install -m 0755 "$CARGO_TARGET_DIR/release/puzzle-init" /usr/libexec/puzzle-init
install -m 0755 podman/puzzle-podman /usr/bin/puzzle-podman
echo "  Installed to /usr/bin/ and /usr/libexec/"
echo ""

# ---------------------------------------------------------------------------
# 4. Install configuration
# ---------------------------------------------------------------------------

echo "--- 4. Installing configuration ---"

# Create directories
mkdir -p /etc/puzzled/profiles /etc/puzzled/policies /var/lib/puzzled/branches/wal /run/puzzled /var/log/puzzled

# Install profiles (all standard profiles + summit-demo)
cp "$REPO_ROOT"/policies/profiles/*.yaml /etc/puzzled/profiles/
cp "$SCRIPT_DIR"/profiles/summit-demo.yaml /etc/puzzled/profiles/
echo "  Installed profiles to /etc/puzzled/profiles/"

# Install OPA/Rego policies
cp "$REPO_ROOT"/policies/rules/*.rego /etc/puzzled/policies/
echo "  Installed policies to /etc/puzzled/policies/"

# Install puzzled config
cat > /etc/puzzled/puzzled.conf << 'CONF'
branch_root: /var/lib/puzzled/branches
profiles_dir: /etc/puzzled/profiles
policies_dir: /etc/puzzled/policies
runtime_dir: /run/puzzled
bus_type: system
fs_type: ext4
max_branches: 64
log_level: info
watchdog_timeout_secs: 0
commit_timeout_seconds: 300
default_action: rollback
default_profile: standard
require_human_approval: false
require_policies: true
require_ima: false
require_self_hardening: false
governance:
  evaluation_timeout_ms: 5000
  require_signature: false
fanotify:
  enable: true
bpf_lsm:
  enable: false
trust:
  enable: true
  initial_score: 25
attestation:
  enable: true
identity:
  enable: true
CONF
echo "  Installed /etc/puzzled/puzzled.conf"

# Install D-Bus policy
cat > /etc/dbus-1/system.d/org.lobstertrap.PuzzlePod1.conf << 'DBUS'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="org.lobstertrap.PuzzlePod1"/>
    <allow send_destination="org.lobstertrap.PuzzlePod1"/>
    <allow receive_sender="org.lobstertrap.PuzzlePod1"/>
  </policy>
  <policy context="default">
    <allow send_destination="org.lobstertrap.PuzzlePod1"/>
    <allow receive_sender="org.lobstertrap.PuzzlePod1"/>
  </policy>
</busconfig>
DBUS
echo "  Installed D-Bus policy"

# NOTE: OCI hook config is installed AFTER the image build (step 5)
# because podman build applies hooks to build containers and fails
# if the hook binary path or format causes issues.

# Install systemd service
cat > /etc/systemd/system/puzzled.service << 'SVC'
[Unit]
Description=PuzzlePod Governance Daemon
After=dbus.service
Requires=dbus.service

[Service]
Type=simple
ExecStart=/usr/bin/puzzled
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=puzzled=info

[Install]
WantedBy=multi-user.target
SVC
systemctl daemon-reload
echo "  Installed puzzled.service"
echo ""

# ---------------------------------------------------------------------------
# 5. Build the demo container image
# ---------------------------------------------------------------------------

echo "--- 5. Building bad-agent container image ---"
podman build -t bad-agent -f "$SCRIPT_DIR/Containerfile.bad-agent" "$SCRIPT_DIR/"
echo "  Built: bad-agent"

# ---------------------------------------------------------------------------
# 5b. Install OCI hook configuration (AFTER image build)
# ---------------------------------------------------------------------------

echo "--- 5b. Installing OCI hook config ---"
mkdir -p /usr/share/containers/oci/hooks.d
cat > /usr/share/containers/oci/hooks.d/puzzlepod.json << 'HOOK'
{
    "version": "1.0.0",
    "hook": {
        "path": "/usr/libexec/puzzle-hook"
    },
    "when": {
        "annotations": {
            "run.oci.handler": "puzzlepod"
        }
    },
    "stages": ["createRuntime", "poststop"]
}
HOOK
echo "  Installed OCI hook config"
echo ""

# ---------------------------------------------------------------------------
# 6. Start puzzled
# ---------------------------------------------------------------------------

echo "--- 6. Starting puzzled ---"
systemctl enable --now puzzled
sleep 2

if systemctl is-active --quiet puzzled; then
    echo "  puzzled is running"
else
    echo "  WARNING: puzzled failed to start. Check: journalctl -u puzzled"
fi
echo ""

# ---------------------------------------------------------------------------
# 7. Verify
# ---------------------------------------------------------------------------

echo "--- 7. Verification ---"
echo "  puzzled:       $(command -v puzzled)"
echo "  puzzlectl:     $(command -v puzzlectl)"
echo "  puzzle-podman: $(command -v puzzle-podman)"
echo "  puzzle-hook: $(ls /usr/libexec/puzzle-hook 2>/dev/null || echo 'NOT FOUND')"
echo "  puzzle-init: $(ls /usr/libexec/puzzle-init 2>/dev/null || echo 'NOT FOUND')"
echo "  OCI hook:     $(ls /usr/share/containers/oci/hooks.d/puzzlepod.json 2>/dev/null || echo 'NOT FOUND')"
echo "  Profile:      $(ls /etc/puzzled/profiles/summit-demo.yaml 2>/dev/null || echo 'NOT FOUND')"
echo "  Policies:     $(ls /etc/puzzled/policies/*.rego 2>/dev/null | wc -l) rego files"
echo "  Image:        $(podman images --format '{{.Repository}}:{{.Tag}}' | grep bad-agent || echo 'NOT FOUND')"
echo ""
echo "  Test: puzzlectl branch list"
puzzlectl branch list 2>/dev/null || echo "  (puzzled may not be ready yet)"
echo ""

echo "=================================================================="
echo "  Setup complete! Run the demo:"
echo "    cd summit-demo"
echo "    sudo ./demo-governed.sh"
echo "    sudo ./demo-attestation.sh"
echo "=================================================================="
