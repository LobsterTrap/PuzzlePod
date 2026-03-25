#!/bin/bash
# DEPRECATED: Use crates/puzzle-hook/ (Rust binary) instead.
#
# puzzle-branch-hook.sh — OCI runtime hook for PuzzlePod branch integration.
#
# This hook runs at the createRuntime stage. It checks container annotations
# for AgentBranch=true and sets up the branch overlay mount if present.
#
# Invoked by the container runtime via puzzle-branch.json hook config.

set -euo pipefail

PUZZLECTL="${PUZZLECTL:-puzzlectl}"

# T39: Validate PUZZLECTL resolves to expected binary name
PUZZLECTL_REAL=$(command -v "$PUZZLECTL" 2>/dev/null || true)
if [ -z "$PUZZLECTL_REAL" ]; then
    echo "ERROR: PUZZLECTL binary '$PUZZLECTL' not found" >&2
    exit 1
fi

# V42: Validate PUZZLECTL resolves to expected binary name
PUZZLECTL_BASE=$(basename "$PUZZLECTL_REAL")
if [ "$PUZZLECTL_BASE" != "puzzlectl" ]; then
    echo "ERROR: PUZZLECTL resolves to '$PUZZLECTL_REAL' (expected 'puzzlectl')" >&2
    exit 1
fi

HOOK_LOG="/var/log/puzzled/hooks.log"

log() {
    echo "$(date -Iseconds) puzzle-branch-hook: $*" >> "$HOOK_LOG" 2>/dev/null || true
}

# U41: Bound OCI state input to 1MiB to prevent memory exhaustion
STATE=$(head -c 1048576)

CONTAINER_ID=$(echo "$STATE" | jq -r '.id // empty')
BUNDLE=$(echo "$STATE" | jq -r '.bundle // empty')
PID=$(echo "$STATE" | jq -r '.pid // empty')

if [ -z "$CONTAINER_ID" ] || [ -z "$BUNDLE" ]; then
    log "ERROR: missing container ID or bundle in OCI state"
    # N4: Fail-closed — containers must not run ungoverned due to missing OCI state
    exit 1
fi

# Read container config to check for agent annotations
CONFIG="$BUNDLE/config.json"
if [ ! -f "$CONFIG" ]; then
    log "no config.json at $CONFIG"
    exit 0
fi

# Check for AgentBranch annotation
AGENT_BRANCH=$(jq -r '.annotations["org.lobstertrap.puzzlepod.branch"] // empty' "$CONFIG" 2>/dev/null)
AGENT_PROFILE=$(jq -r '.annotations["org.lobstertrap.puzzlepod.profile"] // "standard"' "$CONFIG" 2>/dev/null)

# T41: Validate profile name contains only safe characters
if ! echo "$AGENT_PROFILE" | grep -qE '^[a-zA-Z0-9_-]+$'; then
    log "ERROR: invalid profile name in annotation: $AGENT_PROFILE"
    exit 1
fi

if [ -z "$AGENT_BRANCH" ] || [ "$AGENT_BRANCH" = "false" ]; then
    # No agent branching requested — passthrough
    exit 0
fi

log "agent branch requested for container $CONTAINER_ID (profile: $AGENT_PROFILE)"

# Determine the base path from annotations or use default
BASE_PATH=$(jq -r '.annotations["org.lobstertrap.puzzlepod.base_path"] // "/var/agent-workspace"' "$CONFIG" 2>/dev/null)

# T40: Validate base path is absolute and has no traversal
if [ "${BASE_PATH#/}" = "$BASE_PATH" ] || echo "$BASE_PATH" | grep -q '\.\.'; then
    log "ERROR: invalid base path in annotation: $BASE_PATH"
    exit 1
fi

# Create the branch via puzzlectl
BRANCH_OUTPUT=$($PUZZLECTL branch create \
    --profile="$AGENT_PROFILE" \
    --base="$BASE_PATH" \
    --output=json 2>&1) || {
    log "ERROR: failed to create branch: $BRANCH_OUTPUT"
    # N4: Fail-closed — containers must not run ungoverned if branch creation fails
    exit 1
}

BRANCH_ID=$(echo "$BRANCH_OUTPUT" | jq -r '.id // empty')
if [ -z "$BRANCH_ID" ]; then
    log "ERROR: no branch ID in output: $BRANCH_OUTPUT"
    # N4: Fail-closed — containers must not run ungoverned without a valid branch ID
    exit 1
fi

log "branch $BRANCH_ID created for container $CONTAINER_ID"

# Store the branch ID for cleanup hooks
BRANCH_STATE_DIR="/var/lib/puzzled/hooks/$CONTAINER_ID"
mkdir -p "$BRANCH_STATE_DIR"
# N5: Restrict permissions on hook state directory to prevent unprivileged reads
chmod 0700 "$BRANCH_STATE_DIR"
# N5: Set restrictive umask before writing sensitive state files
(umask 0077; echo "$BRANCH_ID" > "$BRANCH_STATE_DIR/branch_id")
(umask 0077; echo "$AGENT_PROFILE" > "$BRANCH_STATE_DIR/profile")

log "branch $BRANCH_ID associated with container $CONTAINER_ID"
