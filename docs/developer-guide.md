# PuzzlePod Developer Guide

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Fork-Explore-Commit Lifecycle](#fork-explore-commit-lifecycle)
3. [Module Breakdown](#module-breakdown)
4. [Writing Custom Profiles](#writing-custom-profiles)
5. [Writing Rego Governance Policies](#writing-rego-governance-policies)
6. [Agent Framework Integration](#agent-framework-integration)
7. [D-Bus API Reference](#d-bus-api-reference)
8. [Building from Source](#building-from-source)
9. [Testing](#testing)
10. [Running Demos](#running-demos)
11. [Phase 2 Features](#phase-2-features)

---

## Architecture Overview

PuzzlePod is composed of eight Rust crates organized as a Cargo workspace, plus ancillary components for BPF programs, policies, SELinux modules, and Podman integration.

### Crate Map

| Crate | Location | Description |
|---|---|---|
| `puzzled` | `crates/puzzled/` | Core governance daemon. Manages agent sandbox lifecycle, OverlayFS branching, policy evaluation, trust scoring, provenance, attestation, identity (JWT-SVID), audit, and D-Bus API. |
| `puzzlectl` | `crates/puzzlectl/` | CLI management tool. Communicates with `puzzled` via D-Bus. Includes governance simulator (`sim`) and compliance evidence generation. |
| `puzzle-proxy` | `crates/puzzle-proxy/` | HTTP proxy for network side-effect gating (Phase 2). Runs per-agent inside the agent's network namespace. |
| `puzzled-types` | `crates/puzzled-types/` | Shared type definitions: `Branch`, `Change`, `CommitResult`, `TrustLevel`, profile structures, D-Bus interface types. |
| `puzzle-hook` | `crates/puzzle-hook/` | OCI runtime hook for Podman-native mode (proposed). |
| `puzzle-init` | `crates/puzzle-init/` | Landlock shim entrypoint for Podman-native mode (proposed). |
| `puzzle-sandbox-demo` | `crates/puzzle-sandbox-demo/` | Phase 1 demo binary: live Landlock + seccomp + cgroup enforcement |
| `puzzle-phase2-demo` | `crates/puzzle-phase2-demo/` | Phase 2 demo binary: 10 hardening feature demonstrations |

### Supporting Components

| Component | Location | Description |
|---|---|---|
| BPF LSM programs | `bpf/` | eBPF programs for exec counting and rate limiting (C, compiled with clang/LLVM) |
| Governance policies | `policies/rules/` | OPA/Rego rules evaluated at commit time |
| Agent profiles | `policies/profiles/` | 23 YAML-based per-agent access control and resource definitions |
| Profile schema | `policies/schemas/` | JSON Schema for profile validation |
| SELinux policy | `selinux/` | Type enforcement module (`puzzlepod_t`, `puzzlepod_agent_t`, `puzzlepod_branch_t`) |
| Podman integration | `podman/` | `puzzle-podman` wrapper script and OCI hooks for Podman-native mode |
| systemd units | `systemd/` | `puzzled.service`, `puzzle@.service` template, `puzzle.slice` |
| Configuration | `config/` | Example `puzzled.conf` |
| Ansible collection | `ansible/` | Ansible roles for deployment |
| Demo scripts | `demo/` | Phase 1, Phase 2, Sandbox Live, and E2E Governance demo scripts (see `docs/demo-guide.md`) |
| Fuzz targets | `fuzz/` | `cargo-fuzz` targets: `fuzz_diff_changeset`, `fuzz_policy_input`, `fuzz_profile_yaml` |

### System Architecture Diagram

```
  AI Agent A        AI Agent B        AI Agent C
  (PID ns +         (PID ns +         (PID ns +
   mount ns +        mount ns +        mount ns +
   net ns +          net ns +          net ns +
   cgroup +          cgroup +          cgroup +
   seccomp +         seccomp +         seccomp +
   landlock)         landlock)         landlock)
      |                 |                 |
      +--------+--------+--------+-------+
               |                  |
               v                  v
          puzzled (Governance Daemon)          puzzlectl (CLI)
          - Lifecycle Manager                 - D-Bus client
          - Governance Engine (OPA/Rego)      - Branch inspect
          - Diff Engine                       - Approve/reject
          - HTTP Proxy                        - Profile management
          - Audit / IMA                       - Policy management
               |
     +---------+---------+----------+--------+--------+
     |         |         |          |        |        |
     v         v         v          v        v        v
  Landlock  seccomp   PID NS    cgroups  OverlayFS  SELinux
  BPF LSM  (BPF)     Mount NS    v2     XFS quota  nftables
                      Net NS             fanotify   Audit/IMA
```

---

## Fork-Explore-Commit Lifecycle

The core execution model follows three phases:

### 1. Fork (Branch Creation)

When an agent is launched, `puzzled` constructs a complete sandbox:

```
puzzled CreateBranch(profile, base_path)
  |
  +-- clone3(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_PIDFD)
  |     Returns: child PID, pidfd
  |
  +-- Create OverlayFS upper layer directory
  |     /var/lib/puzzled/branches/<branch-id>/upper/
  |     /var/lib/puzzled/branches/<branch-id>/work/
  |
  +-- Set XFS project quota on upper layer
  |     (storage_quota_mb, inode_quota from profile)
  |
  +-- Create cgroup scope under puzzle.slice
  |     Write memory.max, cpu.weight, io.weight, pids.max
  |
  +-- Mount OverlayFS in mount namespace
  |     lowerdir=<base_path>, upperdir=<upper>, workdir=<work>
  |
  +-- Apply Landlock ruleset (read_allowlist, write_allowlist, denylist)
  |     Via landlock_create_ruleset() + landlock_add_rule() + landlock_restrict_self()
  |
  +-- Remount /proc inside PID namespace
  |     umount2(/proc, MNT_DETACH) + mount("proc", "/proc", "proc")
  |     Ensures /proc shows only sandbox PIDs, not host PIDs
  |
  +-- Load seccomp-BPF filter
  |     Static deny for 57 escape-vector syscalls using KillProcess action (ptrace, mount, setns, memfd_create, io_uring_*, shmget, semget, msgget, etc.; 58 on x86_64)
  |     USER_NOTIF for execve, connect, bind (Phase 2)
  |     Fail-closed: unknown USER_NOTIF syscalls are denied
  |
  +-- Load BPF LSM programs (exec counter, rate limiter)
  |
  +-- Set up fanotify marks on upper layer
  |
  +-- Drop capabilities, execve() agent binary
  |
  +-- Register pidfd with epoll for exit monitoring
```

### 2. Explore (Agent Execution)

The agent runs in its sandbox. All filesystem writes are captured in the OverlayFS upper layer. The base filesystem is never modified.

- **File reads:** Served from OverlayFS (upper layer takes precedence over lower)
- **File writes:** Copy-on-write to upper layer
- **File deletes:** Whiteout entry in upper layer; base file untouched
- **exec calls:** Gated by seccomp USER_NOTIF (checked against `exec_allowlist`)
- **Network calls:** Filtered by nftables in network namespace; HTTP proxied in Gated mode
- **Resource usage:** Bounded by cgroup limits; OOM killer targets agent cgroup only

`puzzled` monitors the agent via:
- `pidfd` on epoll -- detects agent exit
- cgroup event notifications -- detects OOM, resource pressure
- fanotify -- monitors file access patterns for behavioral triggers

### 3. Commit or Rollback

#### Commit Path (Approved)

```
puzzled CommitBranch(branch_id)
  |
  +-- Freeze agent cgroup (cgroup.freeze = 1)
  |     Prevents TOCTOU: no file changes during diff
  |
  +-- Walk OverlayFS upper layer to generate diff
  |     Filter copy-up artifacts via checksum comparison with lower layer
  |     Result: list of {path, kind, size, checksum}
  |
  +-- Evaluate OPA/Rego governance policy against diff
  |     Input: { "changes": [...] }
  |     Output: { "allow": true/false, "violations": [...] }
  |
  +-- If approved:
  |     +-- Write WAL entry (log intent)
  |     +-- Merge upper layer into base (per-file rename + fsync)
  |     +-- Mark WAL entry complete
  |     +-- Generate IMA-signed changeset manifest
  |     +-- Emit audit event
  |
  +-- Clean up: remove upper layer, destroy cgroup, free namespaces
```

#### Rollback Path (Rejected or Failed)

```
puzzled RollbackBranch(branch_id)
  |
  +-- Kill PID 1 of agent's PID namespace
  |     Kernel sends SIGKILL to all processes in namespace
  |
  +-- Remove upper layer directory (rm -rf)
  |     Zero residue -- base filesystem untouched
  |
  +-- Destroy cgroup scope
  |
  +-- Free mount namespace, network namespace
  |
  +-- Emit audit event with rejection reason
```

---

## Module Breakdown

### puzzled Internal Modules

The `puzzled` crate is organized into the following modules:

| Module | File(s) | Responsibility |
|---|---|---|
| `sandbox/` | `mod.rs`, `namespace.rs`, `cgroup.rs`, `landlock.rs`, `overlay.rs`, `network.rs`, `capabilities.rs`, `selinux.rs`, `quota.rs`, `bpf_lsm.rs`, `fanotify.rs` | Agent sandbox construction: `clone3()`, namespace creation, /proc remount, cgroup setup, OverlayFS mount, network namespace, capability dropping, SELinux context, XFS quotas, BPF LSM, fanotify marks |
| `sandbox/seccomp/` | `mod.rs`, `filter.rs`, `notif.rs` | seccomp-BPF filter: static deny (~57 escape-vector syscalls), USER_NOTIF for execve/connect/bind, notification fd handling |
| `branch.rs` | `branch.rs` | Branch lifecycle management: create, activate, list, inspect, commit, rollback. OverlayFS mount setup and teardown |
| `commit.rs` | `commit.rs` | Commit orchestration: freeze → diff → policy evaluate → WAL → merge → audit |
| `diff.rs` | `diff.rs` | Diff engine: walks OverlayFS upper layer, filters copy-up artifacts via checksum comparison, generates changeset manifest |
| `wal.rs` | `wal.rs` | Write-ahead log for crash-safe commit. Log entry format, journal recovery on startup |
| `policy.rs` | `policy.rs` | OPA/Rego policy engine via `regorus` (pure-Rust Rego evaluator). Evaluates changeset against governance rules |
| `profile.rs` | `profile.rs` | Agent profile loading, validation against JSON schema, Landlock/seccomp/cgroup configuration derivation |
| `dbus.rs` | `dbus.rs` | D-Bus API implementation via `zbus`. 40+ method handlers, 10 signals (see D-Bus API Reference) |
| `trust.rs` | `trust.rs` | Per-UID graduated trust scoring. 5 tiers (Untrusted/Restricted/Standard/Elevated/Trusted). Score adjustments on commit outcomes. Tier transition signals |
| `provenance.rs` | `provenance.rs` | Provenance chain tracking: tool versions, model identifiers, source metadata per branch |
| `attestation.rs` | `attestation.rs` | Ed25519 signature generation, Merkle tree construction, inclusion/consistency proof generation and verification |
| `audit_store.rs` | `audit_store.rs` | Persistent audit event storage with HMAC integrity, Merkle leaf indexing, query/export/filtering |
| `identity.rs` | `identity.rs` | SPIFFE-compatible workload identity: JWT-SVID generation, JWKS public key export, token verification (requires `ima` feature) |
| `audit.rs` | `audit.rs` | Audit event types and Linux Audit integration |
| `ima.rs` | `ima.rs` | IMA manifest signing for changeset integrity |
| `config.rs` | `config.rs` | Daemon configuration loading and validation |
| `conflict.rs` | `conflict.rs` | Cross-branch conflict detection for overlapping file modifications |
| `budget.rs` | `budget.rs` | Adaptive resource budget engine: cumulative resource tracking and trust-based escalation |
| `metrics.rs` | `metrics.rs` | Prometheus metrics exposition |
| `error.rs` | `error.rs` | Error types |
| `seccomp_handler.rs` | `seccomp_handler.rs` | seccomp USER_NOTIF event processing: execve/connect/bind argument inspection |
| `seccomp_profile.rs` | `seccomp_profile.rs` | OCI seccomp profile generation for Podman-native mode |
| `landlock_rules.rs` | `landlock_rules.rs` | Landlock ruleset JSON generation for Podman-native mode |

### puzzlectl Internal Modules

| Module | Responsibility |
|---|---|
| `branch.rs` | `puzzlectl branch` subcommands (list, inspect, approve, reject, rollback, create, diff, activate) |
| `agent.rs` | `puzzlectl agent` subcommands (list, info, kill) |
| `profile.rs` | `puzzlectl profile` subcommands (list, show, validate, test) |
| `policy.rs` | `puzzlectl policy` subcommands (reload, test) |
| `audit.rs` | `puzzlectl audit` subcommands (list, export, verify) |
| `compliance.rs` | `puzzlectl compliance` subcommand: evidence generation for regulatory frameworks |
| `sim.rs` | `puzzlectl sim` subcommand: governance simulator for testing governance policies (gated behind `sim` Cargo feature) |

### puzzled-types Shared Types

```rust
/// Represents a filesystem branch for an agent.
pub struct Branch {
    pub id: BranchId,
    pub agent_id: AgentId,
    pub profile: String,
    pub base_path: PathBuf,
    pub upper_path: PathBuf,
    pub state: BranchState,
    pub created_at: SystemTime,
}

pub enum BranchState {
    Active,
    Frozen,
    CommitPending,
    Committed,
    RolledBack,
}

/// A single file change in a branch's upper layer.
pub struct Change {
    pub path: PathBuf,
    pub kind: ChangeKind,
    pub size: u64,
    pub checksum: String,
}

pub enum ChangeKind {
    Created,
    Modified,
    Deleted,
    MetadataChanged,
}

/// Result of a commit governance evaluation.
pub struct CommitResult {
    pub allowed: bool,
    pub violations: Vec<Violation>,
}

pub struct Violation {
    pub rule: String,
    pub message: String,
    pub severity: Severity,
}

pub enum Severity {
    Critical,
    Error,
    Warning,
    Info,
}
```

---

## Writing Custom Profiles

Agent profiles are YAML files that define the complete access control and resource configuration for an agent.

### Complete Profile Reference

```yaml
# Required: unique name for the profile
name: my-custom-agent

# Required: human-readable description
description: >
  Custom profile for a specific agent workload.

# Filesystem access control
filesystem:
  # Paths the agent can read (in addition to the branch's base path).
  # Each entry is a directory; all files underneath are included.
  read_allowlist:
    - /usr/share
    - /usr/lib
    - /usr/lib64
    - /usr/include

  # Paths the agent can write outside the OverlayFS branch.
  # Typically empty -- all writes go to the branch upper layer.
  write_allowlist: []

  # Paths always denied, even if they match an allowlist entry.
  # Evaluated after allowlists; takes precedence.
  denylist:
    - /etc/shadow
    - /etc/gshadow
    - /etc/ssh
    - /root/.ssh
    - /home/*/.ssh

# List of executable binaries the agent is permitted to invoke.
# Gated via seccomp USER_NOTIF on execve().
exec_allowlist:
  - /usr/bin/python3
  - /usr/bin/git
  - /usr/bin/cargo
  - /usr/bin/rustc

# cgroup and XFS resource limits
resource_limits:
  memory_bytes: 536870912      # Hard memory limit in bytes (512 MiB)
  cpu_shares: 100              # CPU weight (1-10000, relative)
  io_weight: 100               # I/O weight (1-10000, relative)
  max_pids: 64                 # Maximum process count
  storage_quota_mb: 1024       # XFS project quota for upper layer (MiB)
  inode_quota: 10000           # Maximum inode count in upper layer

# Network access control
network:
  # Blocked: no network access (network namespace with no interfaces)
  # Gated: HTTP proxy intercepts requests; GET allowed, POST/PUT/DELETE queued
  # Monitored: full access with logging
  mode: Gated

  # Domains reachable when mode is Gated
  allowed_domains:
    - pypi.org
    - github.com
    - api.github.com

# Behavioral monitoring thresholds (fanotify-based)
behavioral:
  max_deletions: 50              # Alert after N file deletions
  max_reads_per_minute: 1000     # Alert on excessive read rate
  credential_access_alert: true  # Alert on access to credential-like paths

# Fail mode for safety-critical deployments
# FailClosed:       rollback on any governance failure (default)
# FailSilent:       hold last safe state
# FailOperational:  reduced capability fallback
# FailSafeState:    controlled stop / return to base
fail_mode: FailClosed
```

### Validation

All profiles are validated against the JSON schema at `policies/schemas/profile.schema.json`:

```bash
puzzlectl profile validate /path/to/my-profile.yaml
```

---

## Writing Rego Governance Policies

Governance policies are OPA/Rego rules in the `puzzlepod.commit` package. They are evaluated at commit time against the changeset manifest.

### Policy Input Format

```json
{
  "changes": [
    {
      "path": "/home/user/project/src/main.rs",
      "kind": "Modified",
      "size": 2048,
      "checksum": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    {
      "path": "/home/user/project/target/debug/app",
      "kind": "Created",
      "size": 10485760,
      "checksum": "sha256:..."
    }
  ]
}
```

### Policy Output Format

The policy must produce:
- `allow` (boolean): whether the commit is permitted
- `violations` (set of objects): each with `rule`, `message`, and `severity`

### Writing a Custom Rule

```rego
package puzzlepod.commit

import future.keywords.if
import future.keywords.in

# Block commits that include binary files larger than 10 MiB
violations[v] if {
    some change in input.changes
    change.kind != "Deleted"
    change.size > 10485760
    not endswith(change.path, ".rs")
    not endswith(change.path, ".py")
    not endswith(change.path, ".js")
    v := {
        "rule": "no_large_binaries",
        "message": sprintf("large binary file (%d bytes): %s", [change.size, change.path]),
        "severity": "error",
    }
}
```

### Default Rules

The default policy (`policies/rules/commit.rego`) enforces 10+ rule categories:

| Rule | Description | Severity |
|---|---|---|
| `no_empty_paths` | Rejects changes with empty path strings | critical |
| `deny_null_in_path` | Rejects paths containing null bytes (injection prevention) | critical |
| `no_sensitive_files` | Blocks `.env`, `.ssh/`, SSH keys, credentials, cloud provider configs, shell history, container registry auth, etc. (40+ regex patterns) | critical |
| `no_persistence` | Three sub-rules: (a) path-prefix match (`etc/cron*`, `etc/systemd/system/`, `var/spool/at/`, etc.), (b) exact-match files (`etc/ld.so.preload`, `etc/anacrontab`), (c) user-directory suffix match (`.bashrc`, `.config/autostart/`, `.config/systemd/user/`) | critical |
| `no_exec_permission_changes` | Blocks any `MetadataChanged` file (potential `chmod +x`) | error |
| `max_changeset_size` | Blocks changesets exceeding 100 MiB total | error |
| `missing_change_size` | Rejects changes missing the `size` field (prevents unlimited data commit) | critical |
| `no_system_modifications` | Blocks writes to `/usr/bin/`, `/usr/sbin/`, `/etc/`, `/boot/`, `/proc/`, `/sys/`, `/dev/`, etc. | critical |
| `max_file_count` | Blocks changesets with more than 10,000 files | error |
| `profile_storage_quota` | Profile-aware size limits (restricted: 10 MiB, standard: 100 MiB, privileged: 500 MiB) | error |
| `dynamic_storage_quota` | Enforces `input.storage_quota_bytes` from profile YAML | error |
| `deny_symlink` | Blocks symlinks unless profile is `privileged` | critical |
| `deny_symlink_outside_workspace` | Blocks symlink targets pointing outside workspace root | critical |
| `deny_symlink_parent_traversal` | Blocks relative symlinks with `..` traversal | critical |
| `deny_outside_workspace` | Blocks absolute paths outside workspace boundary | critical |
| `deny_path_traversal_in_changeset` | Blocks paths containing `..` components | critical |
| `deny_missing_workspace_root` | Blocks absolute paths when `workspace_root` is not set | critical |

---

## Agent Framework Integration

Three integration patterns are supported, from zero-code to native API:

### 1. Transparent Integration via Podman

No agent code changes required. Use the `puzzle-podman` wrapper:

```bash
# Run a governed container
puzzle-podman run --profile=standard my-agent-image ./agent.py

# Branch management
puzzle-podman agent list
puzzle-podman agent inspect <branch-id>
puzzle-podman agent approve <branch-id>
puzzle-podman agent reject <branch-id>
```

Zero Podman source code changes — all integration uses documented extension points (OCI hooks, container annotations, bind mounts, seccomp profiles).

### 2. Native Integration via Rust Crate

For Rust-based agent frameworks, use the `puzzled-client` crate:

```rust
use puzzled_client::PuzzledClient;

#[tokio::main]
async fn main() -> Result<()> {
    let client = PuzzledClient::connect_system().await?;

    // Create a branch with a command to execute
    let branch = client.create_branch(
        "standard",                  // profile name
        "/home/user/project",        // base path
        &serde_json::to_string(&["my-agent", "--workspace", "."]).unwrap(),
    ).await?;

    println!("Branch created: {}", branch.id);

    // Agent does its work inside the branch...

    // Request commit
    let result = client.commit_branch(&branch.id).await?;
    if result.allowed {
        println!("Commit approved");
    } else {
        for v in &result.violations {
            eprintln!("Violation: {} ({})", v.message, v.severity);
        }
    }

    Ok(())
}
```

### 3. CLI Integration via puzzlectl

For any language or framework, use `puzzlectl` as a subprocess:

```bash
# Create a branch and get its ID
BRANCH_ID=$(puzzlectl branch exec --profile standard --base /home/user/project -- my-agent-command)

# Inspect the branch
puzzlectl branch inspect "$BRANCH_ID" --output json

# Approve the commit
puzzlectl branch approve "$BRANCH_ID"

# Or reject and rollback
puzzlectl branch reject "$BRANCH_ID" --reason "Policy violation"
```

Python example:

```python
import subprocess
import json

def create_branch(profile: str, base_path: str) -> str:
    result = subprocess.run(
        ["puzzlectl", "branch", "exec", "--profile", profile, "--base", base_path,
         "--output", "json", "--", "my-agent"],
        capture_output=True, text=True
    )
    data = json.loads(result.stdout)
    return data["branch_id"]

def inspect_branch(branch_id: str) -> dict:
    result = subprocess.run(
        ["puzzlectl", "branch", "inspect", branch_id, "--output", "json"],
        capture_output=True, text=True
    )
    return json.loads(result.stdout)

def approve_branch(branch_id: str):
    subprocess.run(["puzzlectl", "branch", "approve", branch_id], check=True)
```

---

## D-Bus API Reference

`puzzled` exposes its API on the system bus at `org.lobstertrap.PuzzlePod1.Manager`.

### Interface: org.lobstertrap.PuzzlePod1.Manager

All methods are idempotent.

#### Methods — Core Branch Lifecycle

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `CreateBranch` | `profile: s, base_path: s, command_json: s` | `branch_id: s` | Create a new agent branch with the specified profile |
| `ActivateBranch` | `branch_id: s` | `pid: u` | Spawn sandboxed process inside branch (clone3 + Landlock + seccomp + cgroup) |
| `CommitBranch` | `branch_id: s` | `result: (bs)` | Evaluate governance and commit if approved |
| `RollbackBranch` | `branch_id: s` | `()` | Discard branch and kill all agent processes |
| `ApproveBranch` | `branch_id: s` | `()` | Manually approve a branch in GovernanceReview state |
| `RejectBranch` | `branch_id: s, reason: s` | `()` | Manually reject a branch |
| `InspectBranch` | `branch_id: s` | `changes: a(ssut)` | Return changeset manifest |
| `DiffBranch` | `branch_id: s` | `diff_json: s` | Return diff as JSON |
| `ListBranches` | `()` | `branches: a(sss)` | Return all branches: (id, profile, state) |
| `EnsureBranch` | `branch_id: s, profile: s, base_path: s` | `branch_id: s` | Idempotent create-if-not-exists |

#### Methods — Agent Management

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `ListAgents` | `()` | `agents: a(ssu)` | Return all agents: (agent_id, profile, pid) |
| `AgentInfo` | `agent_id: s` | `info_json: s` | Return detailed agent information |
| `KillAgent` | `agent_id: s` | `()` | Kill agent and rollback its branch |
| `UnregisterAgent` | `agent_id: s` | `()` | Clean up agent registration |
| `ReloadPolicy` | `()` | `()` | Reload OPA/Rego policies |

#### Methods — Trust & Identity (Phase A/B)

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `GetTrustScore` | `uid: u` | `(us)` | Get trust score and level for a UID. Non-root can only query own UID |
| `SetTrustOverride` | `uid: u, score: u, reason: s` | `()` | Admin override of trust score (root only) |
| `ResetTrustScore` | `uid: u` | `()` | Reset trust score to baseline (root only) |
| `GetBaseline` | `uid: u` | `u` | Get baseline trust score for a UID |
| `ListTrustHistory` | `uid: u` | `s` | Get trust score change history as JSON |
| `GetIdentityToken` | `branch_id: s, audience: s` | `s` | Get JWT-SVID token for a branch. Caller must own the branch or be root |
| `GetSpiffeId` | `branch_id: s` | `s` | Get SPIFFE ID for a branch |
| `GetIdentityJwks` | `()` | `s` | Get JWKS JSON with Ed25519 public key |

#### Methods — Provenance & Audit (Phase A/B)

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `ReportProvenance` | `branch_id: s, provenance_json: s` | `()` | Record provenance metadata for a branch |
| `GetProvenance` | `branch_id: s` | `s` | Get provenance records as JSON |
| `QueryAuditEvents` | `filter_json: s` | `s` | Query audit events by branch, type, time range |
| `ExportAuditEvents` | `filter_json: s, format: s` | `s` | Export audit events in JSON or CSV |
| `VerifyAttestationChain` | `branch_id: s` | `(bs)` | Verify Merkle + Ed25519 attestation chain integrity |
| `GetInclusionProof` | `branch_id: s, leaf_index: u` | `s` | Get Merkle inclusion proof for an audit event |
| `GetConsistencyProof` | `old_size: u, new_size: u` | `s` | Get Merkle consistency proof between tree sizes |
| `ExportAttestationBundle` | `branch_id: s` | `s` | Export full attestation bundle (events + proofs + signatures) |
| `GetAttestationPublicKey` | `()` | `s` | Get Ed25519 public key hex for attestation verification |

#### Methods — Podman-Native Mode

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `GenerateSeccompProfile` | `branch_id: s` | `s` | Generate OCI seccomp profile JSON with USER_NOTIF |
| `GenerateLandlockRules` | `branch_id: s` | `s` | Generate Landlock rules JSON for puzzle-init shim |
| `AttachGovernance` | `branch_id: s, container_pid: u` | `()` | Attach BPF LSM + fanotify to a running container |
| `TriggerGovernance` | `branch_id: s` | `(bs)` | Trigger governance evaluation (called by OCI poststop hook) |

#### Methods — Credential Isolation (Section 3.4 of Advanced Capabilities PRD)

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `ProvisionCredentials` | `branch_id: s` | `(u s a{ss} s)` | Provision phantom tokens + proxy for a branch; returns proxy_port, ca_cert_path, phantom_env_vars, proxy_config_path |
| `RevokeCredentials` | `branch_id: s` | `()` | Revoke all phantom tokens and shut down proxy for a branch |
| `RotateCredential` | `branch_id: s, credential_name: s` | `()` | Re-fetch credential from backend and update in-place in secure memory |
| `ListCredentials` | `branch_id: s` | `aa{sv}` | List credential metadata (names, backends, domains — never values) for a branch |
| `UnlockCredential` | `credential_name: s, passphrase: s` | `b` | Unlock a passphrase-encrypted credential after puzzled restart |

#### Signals

| Signal | Parameters | Description |
|---|---|---|
| `BranchCreated` | `branch_id: s, profile: s` | Emitted when a new branch is created |
| `BranchCommitted` | `branch_id: s, changeset_hash: s, profile: s` | Emitted when a branch is committed |
| `BranchRolledBack` | `branch_id: s, reason: s` | Emitted when a branch is rolled back |
| `PolicyViolation` | `branch_id: s, violations_json: s, changeset_hash: s, reason: s, profile: s` | Emitted on governance rejection |
| `BehavioralTrigger` | `branch_id: s, trigger_json: s` | Emitted when a behavioral threshold is exceeded |
| `TrustTransition` | `uid: u, old_level: s, new_level: s, score: u, trigger_event: s` | Emitted when a UID crosses a trust tier boundary |
| `AgentTimeout` | `branch_id: s, timeout_duration_secs: t` | Emitted when a branch exceeds watchdog timeout |
| `GovernanceReviewPending` | `branch_id: s, diff_summary: s` | Emitted when a branch enters GovernanceReview state |
| `BranchEvent` | `branch_id: s, event_type: s, details_json: s` | Generic extensible event signal |
| `DlpViolation` | `branch_id: s, rule_name: s, action: s, domain: s` | Emitted when DLP blocks or quarantines a request |

#### Properties

| Property | Type | Description |
|---|---|---|
| `Version` | `s` | puzzled version string |
| `ActiveBranches` | `u` | Number of currently active branches |
| `MaxBranches` | `u` | Configured maximum branches |
| `EnforcementMode` | `s` | Current enforcement mode (monitor, audit, enforce, full) |

### Output Format

`puzzlectl` supports machine-parseable output:

```bash
# JSON output
puzzlectl branch list --output json

# Table output (default)
puzzlectl branch list --output table
```

---

## Building from Source

### Prerequisites

- Rust 1.75+ (stable)
- clang/LLVM (for BPF program compilation)
- `libbpf-dev` (for BPF program loading)
- `libseccomp-dev` (for seccomp filter construction)
- `libselinux-dev` (for SELinux integration)
- `pkg-config`

### Building

```bash
# Clone the repository
git clone https://github.com/LobsterTrap/PuzzlePod.git
cd puzzlepod

# Build all crates
cargo build --release

# Binaries are in target/release/
ls target/release/puzzled target/release/puzzlectl

# Build BPF programs
cd bpf && make

# Build SELinux module
cd selinux && make
```

### Cargo Workspace Layout

```
Cargo.toml              # Workspace root
crates/
  puzzled/               # Governance daemon
    Cargo.toml
    src/
    tests/              # 25 integration test files
  puzzlectl/             # CLI tool + agent simulator + compliance
    Cargo.toml
    src/
  puzzle-proxy/          # HTTP proxy for network gating
    Cargo.toml
    src/
  puzzled-types/         # Shared types (Branch, Change, TrustLevel, etc.)
    Cargo.toml
    src/
  puzzle-hook/         # OCI runtime hook (Podman-native, proposed)
    Cargo.toml
    src/
  puzzle-init/         # Landlock shim entrypoint (Podman-native, proposed)
    Cargo.toml
    src/
  puzzle-sandbox-demo/         # Phase 1 demo binary (Landlock + seccomp + cgroup)
    Cargo.toml
    src/
  puzzle-phase2-demo/          # Phase 2 demo binary (10 hardening features)
    Cargo.toml
    src/
fuzz/                   # cargo-fuzz targets (diff, policy, profile)
  Cargo.toml
  fuzz_targets/
```

### Key Dependencies

| Crate | Used For |
|---|---|
| `tokio` | Async runtime for concurrent branch monitoring and D-Bus serving |
| `zbus` | D-Bus client and server (async, pure Rust) |
| `regorus` | OPA/Rego policy evaluation (pure Rust, no Wasm dependency) |
| `clap` | CLI argument parsing (derive macros) |
| `serde` / `serde_yaml` | Profile and configuration deserialization |
| `nix` | Linux-specific syscall wrappers (clone3, pidfd, namespaces) |

---

## Testing

### Test Organization

| Directory | Framework | Scope |
|---|---|---|
| `tests/unit/` | Rust `#[test]` | Component-level: diff engine, WAL, sandbox setup, policy evaluation |
| `tests/integration/` | Rust `#[test]` + `testcontainers-rs` | Full fork-explore-commit cycle, concurrent branches, crash recovery |
| `tests/security/` | Custom shell scripts | Escape testing, privilege escalation, policy bypass, namespace escape |
| `tests/performance/` | `fio` + custom | I/O overhead, branch creation latency, commit throughput, diff generation time |

### Running Tests

```bash
# Unit tests for puzzled
cd crates/puzzled && cargo test

# Unit tests for puzzlectl
cd crates/puzzlectl && cargo test

# All unit tests in the workspace
cargo test --workspace

# Integration tests (requires root for namespace/cgroup operations)
sudo cargo test --test integration

# Security escape tests (requires root)
cd tests/security && sudo ./run_all.sh

# Performance benchmarks (requires root + XFS partition)
cd tests/performance && sudo ./bench.sh
```

### Performance Targets

| Operation | x86_64 Target | aarch64 Target |
|---|---|---|
| Branch creation | < 50 ms | < 100 ms |
| File I/O overhead (OverlayFS) | < 10% | < 10% |
| Branch commit (1K files) | < 2 s | < 3 s |
| Branch rollback | < 10 ms | < 10 ms |
| Landlock check | < 1 us | < 1 us |
| BPF LSM check | < 1 us | < 1 us |
| seccomp USER_NOTIF (per call) | ~50-100 us | ~50-100 us |
| Concurrent branches | 64 | 8 (edge) |
| puzzled memory | < 50 MB + 5 MB/branch | < 30 MB + 3 MB/branch |

---

## Running Demos

PuzzlePod includes five demo scripts that exercise real kernel primitives and Rust binaries. For full details, see `docs/demo-guide.md`.

### Building Demo Binaries

```bash
cargo build --workspace --release
# Produces: target/release/puzzle-sandbox-demo (Phase 1) and target/release/puzzle-phase2-demo (Phase 2)
```

### Phase 1 Demo (Core Fork-Explore-Commit)

```bash
sudo demo/run_demo_phase1.sh
```

Demonstrates: OverlayFS branch creation, copy-on-write isolation, OPA/Rego policy evaluation (approve and reject), WAL-based commit, IMA signing, and live Landlock + seccomp + cgroup enforcement via the `puzzle-sandbox-demo` binary.

### Phase 2 Demo (Hardening Features)

```bash
sudo demo/run_demo_phase2.sh
```

Exercises each Phase 2 feature through the `puzzle-phase2-demo` binary:

```bash
# Run individual features:
target/release/puzzle-phase2-demo profiles --profiles-dir policies/profiles/
target/release/puzzle-phase2-demo conflict
target/release/puzzle-phase2-demo budget
target/release/puzzle-phase2-demo audit
target/release/puzzle-phase2-demo journal
target/release/puzzle-phase2-demo proxy
target/release/puzzle-phase2-demo seccomp    # Linux only
target/release/puzzle-phase2-demo fanotify   # Linux only
target/release/puzzle-phase2-demo bpf-lsm   # Linux only
```

The demo script also includes a shell-driven network namespace isolation section demonstrating Blocked, Gated, and Monitored network modes with real `ip netns` and `nftables` rules.

### E2E Governance Demo

```bash
# Runs as a Rust integration test (no puzzled needed)
sudo cargo test -p puzzled --test e2e_governance_lifecycle -- --include-ignored --nocapture 2>&1 | head -500
```

Exercises cross-cutting governance modules (TrustManager, ProvenanceStore, AuditStore/MerkleTree, IdentityManager) through a 3-act narrative: cooperative agent → rogue attempt → redemption, with third-party JWT-SVID verification.

### Rootless Demo (No Root Required)

```bash
demo/run_demo_rootless.sh
```

Demonstrates the full Fork-Explore-Commit lifecycle without root privileges: fuse-overlayfs branching, OPA/Rego governance (approve + reject), Landlock & seccomp verification, rootless degradation matrix, and Podman rootless integration. Requires `fuse-overlayfs` and `fuse3` installed.

### Demo Crate Layout

| Crate | Location | Description |
|---|---|---|
| `puzzle-sandbox-demo` | `crates/puzzle-sandbox-demo/` | Phase 1 binary: live Landlock + seccomp + cgroup enforcement |
| `puzzle-phase2-demo` | `crates/puzzle-phase2-demo/` | Phase 2 binary: 10 hardening feature demonstrations (profiles, conflict, budget, audit, journal, proxy, seccomp, fanotify, bpf-lsm, network) |

### Sample Changesets

Pre-built test changesets are in `demo/sample_changesets/`:

| File | Purpose |
|---|---|
| `safe_changeset.json` | Normal agent work — passes all governance rules |
| `malicious_changeset.json` | `.env` file + cron backdoor + system binary exploit — rejected |
| `credential_theft.json` | Credential exfiltration attempt — rejected |
| `concurrent_branch_a.json` | Concurrent branch scenario for conflict detection |
| `concurrent_branch_b.json` | Concurrent branch scenario for conflict detection |

---

## Phase 2 Features

Phase 2 (Hardening) is complete. The following features are fully implemented and demonstrated by the Phase 2 demo.

### seccomp USER_NOTIF Dynamic Gating

Low-frequency syscalls (`execve`, `connect`, `bind`) are intercepted via seccomp `SECCOMP_RET_USER_NOTIF`. Instead of a static allow/deny decision, the seccomp notification is forwarded to `puzzled`, which makes a policy-based decision:

```
Agent calls execve("/usr/bin/curl", ...)
  |
  +-- Kernel: seccomp filter returns SECCOMP_RET_USER_NOTIF
  +-- Kernel: agent process is blocked
  +-- puzzled: reads notification from seccomp notification fd
  +-- puzzled: checks /usr/bin/curl against exec_allowlist in profile
  +-- puzzled: sends SECCOMP_IOCTL_NOTIF_SEND (allow or EPERM)
  +-- Kernel: agent process resumes (or gets EPERM)
```

Latency: ~50-100 us per intercepted call. Only applied to low-frequency syscalls to minimize overhead.

### fanotify Behavioral Monitoring

`puzzled` uses fanotify with FID (file ID) support to monitor agent file access patterns in real time. Configurable triggers fire when thresholds are exceeded:

| Trigger | Threshold | Action |
|---|---|---|
| Mass deletion | `max_deletions` files deleted | Alert + optional freeze |
| Excessive reads | `max_reads_per_minute` exceeded | Alert + optional throttle |
| Credential access | Access to `*/.ssh/*`, `*/.env`, `*/credentials*` | Alert + audit event |

Triggers are configured per-profile in the `behavioral` section.

### Network Side-Effect Gating

HTTP proxy (`puzzle-proxy`) runs inside each agent's network namespace:

| Method | Behavior |
|---|---|
| GET / HEAD | Pass-through (read-only, no side effects) |
| POST / PUT / DELETE | Queued; replayed only after commit is approved |

Domain allowlists restrict which endpoints the agent can reach. DNS queries are routed through a controlled resolver.

### Conflict Detection

When multiple agents operate on branches derived from the same base, commit-time conflict detection identifies overlapping file modifications:

- Scope-partition: agents are assigned non-overlapping path scopes at branch creation
- Optimistic: concurrent modifications to the same file detected at commit time
- Resolution: first-committer wins; later agents must rebase or rollback

### Budget Engine

Resource budgets track cumulative resource consumption across an agent's lifetime (not just instantaneous limits):

- Total CPU seconds consumed
- Total bytes written
- Total network bytes transferred
- Total exec calls made

Budget exhaustion triggers agent termination and rollback regardless of current instantaneous resource usage.
