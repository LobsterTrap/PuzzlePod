# PuzzlePod Administration Guide

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Verifying Installation with Demos](#verifying-installation-with-demos)
5. [D-Bus Setup](#d-bus-setup)
6. [SELinux Policy Installation](#selinux-policy-installation)
7. [XFS Quota Setup](#xfs-quota-setup)
8. [BPF LSM Kernel Configuration](#bpf-lsm-kernel-configuration)
9. [Profile Management](#profile-management)
10. [Policy Management](#policy-management)
11. [Trust Management](#trust-management)
12. [Attestation & Audit](#attestation--audit)
13. [Workload Identity (JWT-SVID)](#workload-identity-jwt-svid)
14. [Migration Path](#migration-path)
15. [Monitoring](#monitoring)
16. [Troubleshooting](#troubleshooting)
17. [Edge Deployment](#edge-deployment)

---

## Prerequisites

### Supported Platforms

| Platform | Version | Architecture |
|---|---|---|
| RHEL | 10+ | x86_64, aarch64 |
| Fedora | 42+ | x86_64, aarch64 |
| CentOS Stream | 10 | x86_64, aarch64 |

### Kernel Requirements

PuzzlePod uses only existing upstream kernel primitives. The following kernel features must be available and enabled:

| Feature | Minimum Kernel | Required For |
|---|---|---|
| Landlock LSM | 5.13+ (ABI v4: 6.7+) | Filesystem and network ACL |
| BPF LSM | 5.7+ | Programmable per-cgroup security hooks |
| seccomp-BPF | 3.5+ (USER_NOTIF: 5.0+) | Syscall filtering and dynamic gating |
| PID namespaces | 3.8+ | Process isolation |
| Mount namespaces | 2.4.19+ | Per-agent filesystem view |
| Network namespaces | 2.6.29+ | Per-agent network isolation |
| cgroups v2 | 4.5+ | Resource limits |
| cgroup.freeze | 5.2+ | TOCTOU-free diff reading |
| OverlayFS | 3.18+ | Copy-on-write filesystem branching |
| XFS project quotas | 3.0+ | Per-branch storage and inode limits |
| pidfd | 5.3+ | Race-free process lifecycle management |
| clone3() | 5.3+ | Modern process creation with namespace flags |
| fanotify | 2.6.37+ (FID: 5.1+) | Real-time file access monitoring |
| Linux Audit | 2.6+ | Security event logging |
| IMA | 2.6.30+ | Integrity measurement for changeset signing |
| SELinux | 2.6+ | Mandatory label-based access control |

RHEL 10+ and Fedora 42+ kernels satisfy all of the above requirements.

### System Requirements

**Data center / server:**
- 4+ CPU cores
- 8+ GB RAM (minimum 4 GB)
- XFS-formatted partition for branch storage (recommended)
- cgroups v2 unified hierarchy enabled (default on RHEL 10+)

**Edge devices:**
- 4+ CPU cores (ARM64 or x86_64)
- 4+ GB RAM
- 16+ GB storage
- XFS or ext4 filesystem

---

## Installation

### RPM Packages

PuzzlePod ships as a set of RPM packages. Each package can be installed independently or via meta-packages.

#### Individual Packages

| Package | Description |
|---|---|
| `puzzled` | Core governance daemon (`puzzled`) |
| `puzzlectl` | CLI management tool (`puzzlectl`) |
| `puzzled-selinux` | SELinux policy module for `puzzlepod_t` domain |
| `puzzled-profiles` | Default agent profiles (restricted, standard, privileged, edge-minimal, etc.) |
| `puzzled-policies` | Default OPA/Rego governance policies |
| `puzzle-podman` | Podman integration wrapper (`puzzle-podman run`, branch management) |

```bash
# Install individual packages
sudo dnf install puzzled puzzlectl puzzled-selinux puzzled-profiles puzzled-policies

# Install Podman integration (optional)
sudo dnf install puzzle-podman
```

#### Meta-Packages

| Meta-Package | Includes | Use Case |
|---|---|---|
| `puzzlepod` | `puzzled`, `puzzlectl`, `puzzled-selinux`, `puzzled-profiles`, `puzzled-policies`, `puzzle-podman` | Full installation for data center servers |
| `puzzlepod-minimal` | `puzzled`, `puzzlectl`, `puzzled-profiles` | Minimal installation without SELinux or Podman integration |
| `puzzlepod-edge` | `puzzled`, `puzzlectl`, `puzzled-profiles` (edge-optimized, statically linked, < 5 MB total) | Resource-constrained edge devices |

```bash
# Full installation
sudo dnf install puzzlepod

# Minimal installation
sudo dnf install puzzlepod-minimal

# Edge deployment
sudo dnf install puzzlepod-edge
```

### Post-Installation

After installing, enable and start the `puzzled` service:

```bash
sudo systemctl enable --now puzzled.service
```

Verify the service is running:

```bash
sudo systemctl status puzzled.service
puzzlectl agent list
```

---

## Configuration

### Main Configuration File

**Location:** `/etc/puzzled/puzzled.conf`

The configuration file uses YAML syntax. Below is a complete reference of all supported fields:

```yaml
# Root directory for branch storage (OverlayFS upper layers, work dirs, WAL).
# Must be on an XFS filesystem for project quota support.
branch_root: /var/lib/puzzled/branches

# Directory containing agent profile YAML files.
profiles_dir: /etc/puzzled/profiles

# Directory containing OPA/Rego policy bundles.
policies_dir: /etc/puzzled/policies

# Maximum number of concurrent branches.
# Data center default: 64. Edge default: 8.
max_branches: 64

# D-Bus bus type: "system" (production) or "session" (development).
bus_type: system

# Filesystem type for branch storage.
# "xfs" is recommended for project quota support.
# Supported values: xfs, ext4, btrfs
fs_type: xfs

# Log level: trace, debug, info, warn, error.
log_level: info

# Watchdog timeout in seconds (0 = disabled).
# puzzled sends sd_notify(WATCHDOG=1) at half this interval.
# Also controls branch lifetime enforcement: active branches exceeding
# this timeout are automatically rolled back.
watchdog_timeout_secs: 30

# Path to the BPF LSM object file for exec counting/rate limiting.
# Set to empty string to disable BPF LSM integration.
bpf_obj_path: /usr/lib/puzzled/exec_guard.bpf.o
```

### Directory Structure

After installation, the following directories are created:

```
/etc/puzzled/
  puzzled.conf              # Main configuration
  profiles/                # Agent profile YAML files
  policies/                # OPA/Rego policy bundles

/var/lib/puzzled/
  branches/                # Branch storage (OverlayFS upper layers, work dirs)
    <branch-id>/
      upper/               # OverlayFS upper layer
      work/                # OverlayFS work directory
      wal/                 # Write-ahead log for crash-safe commit

/var/log/puzzled/
  puzzled.log               # Daemon log (also available via journald)

/run/puzzled/
  puzzled.pid               # PID file
  puzzled.sock              # Unix domain socket (if used)
```

---

## Verifying Installation with Demos

After installation, use the built-in demos to verify that all kernel primitives and userspace components are functioning correctly. For full demo documentation, see `docs/demo-guide.md`.

### Quick Verification (Phase 1 Demo)

The Phase 1 demo validates the complete Fork-Explore-Commit lifecycle:

```bash
# Build demo binaries (if installing from source)
cargo build --workspace --release

# Run the Phase 1 demo
sudo demo/run_demo_phase1.sh
```

The demo will:
1. **Check prerequisites** — verify Landlock, cgroups v2, OverlayFS, and PID namespaces
2. **Create an OverlayFS branch** with cgroup and namespace isolation
3. **Simulate agent writes** and verify copy-on-write behavior
4. **Evaluate OPA/Rego policy** and demonstrate approved commit with WAL + IMA signing
5. **Test malicious changesets** and demonstrate rejection with zero-residue rollback
6. **Run live kernel enforcement** via the `puzzle-sandbox-demo` binary (Landlock + seccomp + cgroups)

If all sections pass, your installation is correctly configured.

### Full Validation (Phase 2 Demo)

The Phase 2 demo validates hardening features:

```bash
sudo demo/run_demo_phase2.sh
```

This exercises: 23 security profiles, cross-branch conflict detection, adaptive budget engine, persistent audit storage, network journal, HTTP proxy, seccomp USER_NOTIF, fanotify behavioral monitoring, BPF LSM rate limiting, and network namespace isolation.

Individual Phase 2 features can be tested independently:

```bash
# Test a single feature
sudo target/release/puzzle-phase2-demo profiles --profiles-dir /etc/puzzled/profiles
sudo target/release/puzzle-phase2-demo seccomp
sudo target/release/puzzle-phase2-demo fanotify
```

### What Each Demo Validates

| Demo Section | Kernel Primitives Tested |
|---|---|
| Phase 1: Fork | clone3, PID/Mount/Net namespaces, OverlayFS, cgroups v2, XFS quotas |
| Phase 1: Explore | OverlayFS copy-on-write, Landlock file access |
| Phase 1: Commit | cgroup.freeze, OPA/Rego evaluation, WAL, IMA signing |
| Phase 1: Enforcement | Landlock LSM, seccomp-BPF, cgroup limits |
| Phase 2: seccomp | seccomp USER_NOTIF with argument inspection |
| Phase 2: fanotify | fanotify FID-based behavioral monitoring |
| Phase 2: BPF LSM | Per-cgroup exec counting and rate limiting |
| Phase 2: Network | Network namespaces, veth pairs, nftables rules |

---

## D-Bus Setup

`puzzled` exposes its API on the system D-Bus bus at the well-known name `org.lobstertrap.PuzzlePod1.Manager`.

### D-Bus Policy

The `puzzled` RPM installs a D-Bus policy file at `/etc/dbus-1/system.d/org.lobstertrap.PuzzlePod1.conf`. This file grants:

- `root` can own the `org.lobstertrap.PuzzlePod1.Manager` bus name
- Members of the `puzzled` group can call methods on the bus name
- All users can introspect the interface

If you need to grant non-root users access to `puzzlectl`, add them to the `puzzled` group:

```bash
sudo usermod -aG puzzled <username>
```

### Verifying D-Bus Registration

```bash
# Check that puzzled owns its bus name
busctl list | grep org.lobstertrap

# Introspect the interface
busctl introspect org.lobstertrap.PuzzlePod1 /org/lobstertrap/PuzzlePod1/Manager
```

---

## SELinux Policy Installation

The `puzzled-selinux` package installs a type enforcement module defining the following domains:

| Domain | Description |
|---|---|
| `puzzlepod_t` | Daemon domain for the `puzzled` process |
| `puzzlepod_t` | Domain for sandboxed agent processes |
| `puzzlepod_branch_t` | Filesystem type for branch data |

### Installation and Activation

```bash
sudo dnf install puzzled-selinux

# Verify the module is loaded
sudo semodule -l | grep puzzled

# Check that puzzled is running in the correct domain
ps -eZ | grep puzzled
# Expected: system_u:system_r:puzzlepod_t:s0 ... /usr/bin/puzzled
```

### Key neverallow Rules

The SELinux policy enforces the following restrictions on agent processes (`puzzlepod_t`):

- Cannot access system configuration files outside the branch
- Cannot use `ptrace` on any process
- Cannot load kernel modules
- Cannot modify SELinux policy
- Cannot transition to any privileged domain

---

## XFS Quota Setup

XFS project quotas are used to enforce per-branch storage and inode limits on OverlayFS upper layers. This prevents any single agent from exhausting disk space.

### Preparing the XFS Filesystem

1. Ensure the branch storage partition is formatted as XFS:

```bash
# Check current filesystem type
df -T /var/lib/puzzled/branches

# If not XFS, format the partition (WARNING: destroys data)
sudo mkfs.xfs -f /dev/sdX1
```

2. Mount with project quota support:

```bash
# Add to /etc/fstab with prjquota option
/dev/sdX1  /var/lib/puzzled/branches  xfs  defaults,prjquota  0 0

# Remount if already mounted
sudo mount -o remount,prjquota /var/lib/puzzled/branches
```

3. Verify quota support:

```bash
# Check that project quotas are enabled
xfs_quota -x -c 'state' /var/lib/puzzled/branches
```

`puzzled` automatically assigns XFS project IDs to each branch and enforces the `storage_quota_mb` and `inode_quota` values from the agent's profile.

---

## BPF LSM Kernel Configuration

BPF LSM is used for programmable per-cgroup security hooks (exec counting, rate limiting). It must be enabled in the kernel boot parameters.

### Enabling BPF LSM

1. Add `bpf` to the LSM list in the kernel command line:

```bash
# Check current LSM configuration
cat /sys/kernel/security/lsm

# Add bpf to the boot parameters
sudo grubby --update-kernel=ALL --args="lsm=lockdown,capability,landlock,yama,selinux,bpf"
```

2. Reboot the system:

```bash
sudo reboot
```

3. Verify BPF LSM is active:

```bash
cat /sys/kernel/security/lsm
# Should include "bpf" in the comma-separated list
```

### Verifying BPF Program Loading

After starting `puzzled`, verify that BPF LSM programs are loaded:

```bash
sudo bpftool prog list | grep lsm
```

---

## Profile Management

Agent profiles are YAML files that define per-agent access control, resource limits, network policy, and behavioral monitoring thresholds.

### Default Profiles

| Profile | Location | Description |
|---|---|---|
| `restricted` | `/etc/puzzled/profiles/restricted.yaml` | Minimal access, no network, small quotas |
| `standard` | `/etc/puzzled/profiles/standard.yaml` | Project-scoped access, gated network, standard quotas |
| `privileged` | `/etc/puzzled/profiles/privileged.yaml` | Broad access, monitored network, large quotas |
| `edge-minimal` | `/etc/puzzled/profiles/edge-minimal.yaml` | 128 MiB memory, no network, minimal utilities |

Additional specialized profiles are available: `code-assistant`, `ci-runner`, `data-analyst`, `devops-automation`, `safety-critical`, `web-scraper`, and others.

### Deploying a Custom Profile

1. Create a new YAML file in the profiles directory:

```bash
sudo cp /etc/puzzled/profiles/standard.yaml /etc/puzzled/profiles/my-agent.yaml
sudo vi /etc/puzzled/profiles/my-agent.yaml
```

2. Validate the profile against the JSON schema:

```bash
puzzlectl profile validate /etc/puzzled/profiles/my-agent.yaml
```

3. Reload profiles:

```bash
puzzlectl policy reload
```

### Profile Fields Reference

```yaml
name: my-agent
description: "Custom agent profile"

filesystem:
  read_allowlist:         # Paths the agent can read (in addition to branch)
    - /usr/share
    - /usr/lib
  write_allowlist: []     # Paths the agent can write outside the branch
  denylist:               # Paths always denied, even if in allowlist
    - /etc/shadow
    - /etc/ssh

exec_allowlist:           # Binaries the agent is permitted to execute
  - /usr/bin/python3
  - /usr/bin/git

resource_limits:
  memory_bytes: 536870912   # Hard memory limit (bytes)
  cpu_shares: 100           # CPU weight (relative to other cgroups)
  io_weight: 100            # I/O weight (relative to other cgroups)
  max_pids: 64              # Maximum number of processes
  storage_quota_mb: 1024    # XFS project quota for upper layer (MiB)
  inode_quota: 10000        # Maximum inodes in upper layer

network:
  mode: Blocked             # Blocked | Gated | Monitored
  allowed_domains:          # Only used when mode is Gated
    - api.github.com

behavioral:
  max_deletions: 50              # Trigger alert after N deletions
  max_reads_per_minute: 1000     # Rate limit on file reads
  credential_access_alert: true  # Alert on access to credential-like files

fail_mode: FailClosed      # FailClosed | FailSilent | FailOperational | FailSafeState
```

### Listing and Inspecting Profiles

```bash
# List all available profiles
puzzlectl profile list

# Show details of a specific profile
puzzlectl profile show standard

# Test a profile against a simulated workload
puzzlectl profile test standard --workload /path/to/workload.json
```

---

## Policy Management

Governance policies are written in Rego (the OPA policy language) and evaluated at commit time via `regorus` (a pure-Rust Rego evaluator).

### Writing Rego Policies

Policies are placed in `/etc/puzzled/policies/` and must use the `puzzlepod.commit` package. The input to each policy evaluation is a changeset manifest:

```json
{
  "changes": [
    {
      "path": "/home/user/project/file.py",
      "kind": "Created",
      "size": 1024,
      "checksum": "sha256:abcdef..."
    }
  ]
}
```

Example: Block changes to configuration files:

```rego
package puzzlepod.commit

import future.keywords.if
import future.keywords.in

violations[v] if {
    some change in input.changes
    endswith(change.path, ".conf")
    v := {
        "rule": "no_config_changes",
        "message": sprintf("configuration file modified: %s", [change.path]),
        "severity": "error",
    }
}
```

### Testing Policies

```bash
# Test a policy against a sample changeset
puzzlectl policy test --policy /etc/puzzled/policies/commit.rego \
    --input /path/to/test-changeset.json

# Dry-run a branch commit to see which policies would fire
puzzlectl branch inspect <branch-id> --dry-run
```

### Reloading Policies

After modifying policy files, reload them without restarting `puzzled`:

```bash
puzzlectl policy reload
```

`puzzled` reloads the Rego policies and replaces the running policy engine atomically.

---

## Trust Management

PuzzlePod tracks a graduated trust score per agent UID. Trust scores are adjusted based on commit outcomes and persisted across daemon restarts.

### Trust Tiers

| Tier | Score Range | Meaning |
|---|---|---|
| Untrusted | 0-19 | Emergency lockdown candidate. Agent may be frozen or terminated |
| Restricted | 20-39 | Minimal access, heavy monitoring |
| Standard | 40-59 | Normal operating range (new agents start at 50) |
| Elevated | 60-79 | Earned broader access through safe behavior |
| Trusted | 80-100 | Maximum trust |

### How Scores Change

- **Successful commit (approved):** Trust score increases (+10 by default)
- **Rejected commit (governance violation):** Trust score decreases (-20 by default)
- **Rollback:** Trust score decreases (-15 by default)

### Querying Trust

```bash
# Get trust score for a specific UID (non-root can only query own UID)
busctl call org.lobstertrap.PuzzlePod1 /org/lobstertrap/PuzzlePod1/Manager \
  org.lobstertrap.PuzzlePod1.Manager GetTrustScore u 1001

# Admin override (root only)
busctl call org.lobstertrap.PuzzlePod1 /org/lobstertrap/PuzzlePod1/Manager \
  org.lobstertrap.PuzzlePod1.Manager SetTrustOverride uus 1001 75 "manual review passed"

# Reset to baseline (root only)
busctl call org.lobstertrap.PuzzlePod1 /org/lobstertrap/PuzzlePod1/Manager \
  org.lobstertrap.PuzzlePod1.Manager ResetTrustScore u 1001
```

### What Changes at Each Tier (Current)

Tier transitions emit `TrustTransition` D-Bus signals and update JWT-SVID identity token claims. Operators can subscribe to these signals to trigger external actions (e.g., alert on demotion to Untrusted). Dynamic Landlock/seccomp tightening based on trust tier is planned for future work.

### UID Assignment

Agent UIDs are standard POSIX user identifiers assigned by the operator:

```bash
# Create a dedicated user for an agent
sudo useradd --system --no-create-home agent-ci

# Or use systemd DynamicUser in a service unit
[Service]
DynamicUser=yes
```

The UID is read from the kernel via `SCM_CREDENTIALS` on the D-Bus Unix socket — `puzzled` does not assign or manage UIDs.

---

## Attestation & Audit

Every governance decision is recorded in a tamper-evident attestation chain using Ed25519 signatures and Merkle trees.

### How It Works

1. Each audit event (branch created, committed, rejected, rolled back) is signed with an Ed25519 private key held by `puzzled`
2. Events are organized as leaves in a Merkle tree (SHA-256)
3. Merkle inclusion proofs allow verification that a specific event belongs to the tree
4. Consistency proofs verify that the tree has only been appended to (never modified)

### Querying Audit Events

```bash
# Query audit events for a branch
busctl call org.lobstertrap.PuzzlePod1 /org/lobstertrap/PuzzlePod1/Manager \
  org.lobstertrap.PuzzlePod1.Manager QueryAuditEvents s '{"branch_id": "abc123"}'

# Export audit events in JSON format
busctl call org.lobstertrap.PuzzlePod1 /org/lobstertrap/PuzzlePod1/Manager \
  org.lobstertrap.PuzzlePod1.Manager ExportAuditEvents ss '{"since": "2025-01-01"}' json

# Verify attestation chain integrity
busctl call org.lobstertrap.PuzzlePod1 /org/lobstertrap/PuzzlePod1/Manager \
  org.lobstertrap.PuzzlePod1.Manager VerifyAttestationChain s "abc123"
```

### Attestation Bundle Export

For compliance or forensic review, export a complete attestation bundle:

```bash
busctl call org.lobstertrap.PuzzlePod1 /org/lobstertrap/PuzzlePod1/Manager \
  org.lobstertrap.PuzzlePod1.Manager ExportAttestationBundle s "abc123"
```

The bundle contains all audit events, their Ed25519 signatures, Merkle inclusion proofs, and the tree root hash.

### Public Key for Verification

Third parties can verify attestation signatures using the public key:

```bash
busctl call org.lobstertrap.PuzzlePod1 /org/lobstertrap/PuzzlePod1/Manager \
  org.lobstertrap.PuzzlePod1.Manager GetAttestationPublicKey
```

---

## Workload Identity (JWT-SVID)

PuzzlePod issues SPIFFE-compatible JWT-SVID tokens for agent workloads. These tokens allow third-party services to verify an agent's identity and trust level without querying `puzzled` directly.

**Requires:** The `ima` Cargo feature must be enabled at build time.

### Token Contents

| Claim | Description |
|---|---|
| `sub` | SPIFFE ID: `spiffe://<trust_domain>/agent/<branch_id>` |
| `trust_level` | Current trust tier (e.g., "Standard") |
| `trust_score` | Numeric trust score (0-100) |
| `branch_id` | Branch identifier |
| `aud` | Audience (specified by the requesting agent) |
| `exp` | Expiration time |

### Requesting a Token

Tokens are requested via D-Bus. The caller must own the branch (UID-checked) or be root:

```bash
busctl call org.lobstertrap.PuzzlePod1 /org/lobstertrap/PuzzlePod1/Manager \
  org.lobstertrap.PuzzlePod1.Manager GetIdentityToken ss "branch-id" "api.github.com"
```

### Third-Party Verification Flow

1. Agent requests JWT-SVID from `puzzled` (local D-Bus call, UID-checked)
2. Agent presents the token as an HTTP bearer token to the third-party service
3. Third party verifies the token offline using a cached JWKS public key (Ed25519 asymmetric — no shared secret needed)

### Current Limitations

- No JWKS HTTP endpoint — key distribution is manual or in-process
- No published claims schema — third parties need documentation to interpret token claims
- No client SDK for third-party verification libraries

---

## Migration Path

PuzzlePod supports a phased adoption strategy allowing organizations to incrementally increase enforcement.

### Phase 1: Monitor Only

Agents run without containment. `puzzled` observes and logs all agent actions via fanotify and audit events but does not enforce any restrictions.

```yaml
# puzzled.conf
enforcement_mode: monitor
```

- All filesystem access is logged
- No Landlock restrictions applied
- No seccomp filtering
- No commit governance
- Use this phase to establish baseline agent behavior and identify necessary policy rules

### Phase 2: Audit Mode

Agents run with containment enabled, but policy violations generate warnings rather than blocking actions. Commits proceed even if governance checks fail, but violations are logged.

```yaml
# puzzled.conf
enforcement_mode: audit
```

- Landlock and seccomp are applied (kernel enforcement is active)
- Governance policy violations are logged but do not block commits
- Resource limits are enforced (cgroups)
- Use this phase to validate that policies do not break legitimate agent workflows

### Phase 3: Enforce Mode

Full containment and governance enforcement. Policy violations block commits and trigger rollback.

```yaml
# puzzled.conf
enforcement_mode: enforce
```

- All kernel enforcement active (Landlock, seccomp, namespaces, cgroups)
- Governance policy violations block commits
- Failed commits trigger automatic rollback
- Audit trail with IMA-signed manifests

### Phase 4: Full Governance

Complete deployment with SELinux type enforcement, BPF LSM hooks, behavioral monitoring, and network gating.

```yaml
# puzzled.conf
enforcement_mode: full
```

- All Phase 3 features plus:
- SELinux `puzzlepod_t` domain transition enforced
- BPF LSM exec counting and rate limiting active
- fanotify behavioral triggers (mass deletion detection, credential access alerts)
- Network gating via HTTP proxy (Gated mode)
- IMA-signed changeset manifests for every commit

---

## Monitoring

### Prometheus Metrics

`puzzled` exposes Prometheus metrics on a configurable endpoint (default: `http://localhost:9191/metrics`).

Key metrics:

| Metric | Type | Description |
|---|---|---|
| `puzzled_branches_active` | Gauge | Number of currently active branches |
| `puzzled_branches_created_total` | Counter | Total branches created |
| `puzzled_commits_total` | Counter | Total commits (by status: approved, rejected, rolled_back) |
| `puzzled_commit_duration_seconds` | Histogram | Commit operation latency |
| `puzzled_branch_creation_duration_seconds` | Histogram | Branch creation latency |
| `puzzled_policy_evaluation_duration_seconds` | Histogram | OPA policy evaluation latency |
| `puzzled_agent_memory_bytes` | Gauge | Per-agent memory usage (from cgroup) |
| `puzzled_agent_cpu_usage_seconds_total` | Counter | Per-agent CPU time |
| `puzzled_seccomp_notifications_total` | Counter | seccomp USER_NOTIF events processed |
| `puzzled_fanotify_events_total` | Counter | fanotify events by type |
| `puzzled_behavioral_triggers_total` | Counter | Behavioral trigger activations |

### Log Output

`puzzled` logs to the systemd journal. View logs with:

```bash
# Follow puzzled logs
sudo journalctl -u puzzled.service -f

# Show logs at a specific level
sudo journalctl -u puzzled.service -p info

# Show logs for a specific branch
sudo journalctl -u puzzled.service BRANCH_ID=<branch-id>
```

### Audit Events

Agent lifecycle events are logged to the Linux Audit subsystem. Query them with:

```bash
# List recent agent audit events
puzzlectl audit list

# Export audit events in JSON format
puzzlectl audit export --format json --since "1 hour ago"

# Verify audit event signatures
puzzlectl audit verify --branch <branch-id>
```

---

## Troubleshooting

### puzzled fails to start

**Symptom:** `systemctl status puzzled` shows the service as failed.

| Possible Cause | Solution |
|---|---|
| cgroups v2 not enabled | Ensure `systemd.unified_cgroup_hierarchy=1` is in kernel boot parameters (default on RHEL 10+) |
| BPF LSM not enabled | Add `bpf` to the `lsm=` kernel boot parameter and reboot |
| Branch root not on XFS | Set `fs_type: xfs` in `puzzled.conf` and mount branch storage on an XFS partition with `prjquota` |
| D-Bus policy missing | Reinstall `puzzled` package to restore `/etc/dbus-1/system.d/org.lobstertrap.PuzzlePod1.conf` |
| Insufficient capabilities | `puzzled` must run as root (or with `CAP_SYS_ADMIN`, `CAP_SYS_RESOURCE`, `CAP_BPF`) |

### Branch creation fails

**Symptom:** `puzzlectl branch list` shows no active branches; agent processes fail to start.

| Possible Cause | Solution |
|---|---|
| `max_branches` limit reached | Increase `max_branches` in `puzzled.conf` or clean up stale branches with `puzzlectl branch rollback` |
| XFS quota setup missing | Enable project quotas: mount with `prjquota` and verify with `xfs_quota -x -c 'state'` |
| OverlayFS mount failure | Check that the kernel supports OverlayFS: `modprobe overlay && lsmod | grep overlay` |
| Insufficient disk space | Ensure the branch root partition has adequate free space |

### Agent cannot access expected files

**Symptom:** Agent reports "Permission denied" on files it should be able to read.

| Possible Cause | Solution |
|---|---|
| File not in `read_allowlist` | Add the file's parent directory to the profile's `read_allowlist` |
| File in `denylist` | Remove the path from the profile's `denylist` |
| Landlock ABI version too old | Upgrade to kernel 6.7+ for Landlock ABI v4 (network restriction support) |
| SELinux denial | Check `ausearch -m avc -ts recent` for SELinux denials; update the SELinux policy if needed |

### Commit is rejected unexpectedly

**Symptom:** `puzzlectl branch inspect` shows governance violations.

```bash
# Inspect the changeset and policy evaluation result
puzzlectl branch inspect <branch-id>

# Dry-run the commit to see which rules fire
puzzlectl branch inspect <branch-id> --dry-run

# Test the policy against the changeset directly
puzzlectl policy test --policy /etc/puzzled/policies/commit.rego \
    --input <(puzzlectl branch inspect <branch-id> --output json)
```

### Orphaned branches after puzzled crash

If `puzzled` crashes or is killed, branches may be left in an inconsistent state. On restart, `puzzled` automatically scans `/var/lib/puzzled/branches/` and recovers orphaned branches:

- Branches with a complete WAL entry are committed
- Branches with an incomplete WAL entry are rolled back
- Branches with no WAL entry are cleaned up (upper layer removed)

To manually clean up orphaned branches:

```bash
puzzlectl branch list --all
puzzlectl branch rollback <branch-id>
```

### seccomp USER_NOTIF not working

**Symptom:** Agent processes are not being gated on `execve`/`connect`/`bind`.

| Possible Cause | Solution |
|---|---|
| Kernel too old | seccomp `USER_NOTIF` requires kernel 5.0+. Verify with `uname -r` |
| puzzled seccomp thread not running | Check `puzzled` logs for errors related to seccomp notification fd |
| Agent profile does not use USER_NOTIF | Ensure the profile is configured for dynamic gating (Phase 2 feature) |

---

## Edge Deployment

### Sizing for Edge Devices

PuzzlePod is designed to run on resource-constrained edge devices with as little as 4 GB RAM.

| Parameter | Edge Value | Data Center Value |
|---|---|---|
| `puzzled` binary size | < 5 MB (statically linked) | ~15 MB (dynamically linked) |
| `puzzled` memory footprint | < 30 MB + 3 MB/branch | < 50 MB + 5 MB/branch |
| `max_branches` | 8 | 64 |
| Default agent profile | `edge-minimal` | `standard` |
| Default agent memory | 128 MiB | 512 MiB |
| Default max PIDs | 8 | 64 |
| Network mode | Blocked | Gated |

### Edge Configuration

```yaml
# /etc/puzzled/puzzled.conf (edge)
branch_root: /var/lib/puzzled/branches
profiles_dir: /etc/puzzled/profiles
policies_dir: /etc/puzzled/policies
max_branches: 8
bus_type: system
fs_type: xfs
log_level: warn
watchdog_timeout_secs: 15
```

### Edge-Minimal Profile

The `edge-minimal` profile is designed for 128 MiB memory footprint with minimal syscall surface:

- **Memory:** 128 MiB hard limit
- **CPU shares:** 25 (low priority)
- **Max PIDs:** 8
- **Storage quota:** 64 MiB
- **Network:** Fully blocked
- **Exec allowlist:** Only `python3`, `cat`, `ls`, `grep`
- **Behavioral limits:** Max 5 deletions, 50 reads/minute
- **Fail mode:** FailClosed

### Optimizations for Edge

- Install `puzzlepod-edge` meta-package for statically linked binaries (< 5 MB total)
- Disable BPF LSM if the kernel does not support it (Landlock and seccomp provide sufficient containment)
- Use `ext4` if XFS is not available (project quotas will not be enforced; rely on cgroup I/O limits instead)
- Set `log_level: warn` to reduce I/O overhead
- Reduce `watchdog_timeout_secs` for faster failure detection
