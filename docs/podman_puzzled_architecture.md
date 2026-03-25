# Product Requirements Document: Podman-Native Architecture for PuzzlePod

**Document ID:** RHEL-AGENTIC-ARCH-2026-002
**Version:** 2.0
**Date:** 2026-03-12
**Author:** Francis Chow
**Contributors:** Adam Miller
**Status:** Approved — Architecture Baseline
**Related:** PuzzlePod Core PRD (RHEL-AGENTIC-PRD-2026-001 v2.2), PuzzlePod Advanced PRD (RHEL-AGENTIC-ADV-2026-001), Kernel vs. Userspace Analysis (RHEL-AGENTIC-ARCH-2026-001), OWASP Top 10 for Agentic Applications (Dec 2025), NIST AI Agent Standards Initiative (Feb 2026), CSA Agentic Trust Framework (Feb 2026), MCP Specification (AAIF/Linux Foundation)

### Change History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-11 | Francis Chow | Initial document. Proposes architectural pivot: puzzled as governance-only daemon composing with unmodified podman for container lifecycle. Zero podman code changes. |
| 2.0 | 2026-03-12 | Adam Miller | Consolidated merge of architecture-v2 (D-Bus 3-interface split, Cockpit, Podman Desktop, crate decomposition, MCP, phases 8-12), gap-analysis (limitations, competitive positioning, priority matrix), and gap-analysis-v2 (rootless architecture, OWASP mapping, threat model additions, "Is puzzled Necessary?" rationale) into single authoritative document. Added Sections 22-26, Appendix A. Extended Sections 5, 6, 7, 10, 14, 18, 20. Renumbered References to Section 27. |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Architectural Decision](#3-architectural-decision)
4. [Proposed Architecture](#4-proposed-architecture)
5. [Component Design: puzzle-podman Wrapper](#5-component-design-puzzle-podman-wrapper)
6. [Component Design: puzzle-hook (OCI Runtime Hook)](#6-component-design-puzzle-hook-oci-runtime-hook)
7. [Component Design: puzzled (Governance Daemon)](#7-component-design-puzzled-governance-daemon)
8. [seccomp USER_NOTIF Integration via crun](#8-seccomp-user_notif-integration-via-crun)
9. [Developer Experience](#9-developer-experience)
10. [Rootless and User-Instance Operation](#10-rootless-and-user-instance-operation)
11. [Mac, Windows, and Remote Development](#11-mac-windows-and-remote-development)
12. [IDE and Dev Container Integration](#12-ide-and-dev-container-integration)
13. [Quadlet and Production Deployment](#13-quadlet-and-production-deployment)
14. [Security Model](#14-security-model)
15. [Migration from Current Architecture](#15-migration-from-current-architecture)
16. [Performance Requirements](#16-performance-requirements)
17. [Testing Strategy](#17-testing-strategy)
18. [Phased Implementation Plan](#18-phased-implementation-plan)
19. [Risk Analysis](#19-risk-analysis)
20. [Open Questions](#20-open-questions)
21. [Cockpit Integration](#21-cockpit-integration)
22. [Podman Desktop Integration](#22-podman-desktop-integration)
23. [Library-First Crate Architecture](#23-library-first-crate-architecture)
24. [MCP Server Integration](#24-mcp-server-integration)
25. [Competitive Analysis](#25-competitive-analysis)
26. [References](#26-references)
- [Appendix A: Architectural Decision — Is puzzled Necessary?](#appendix-a-architectural-decision--is-puzzled-necessary)

---

## 1. Executive Summary

The current PuzzlePod architecture has `puzzled` performing two fundamentally different jobs: **container runtime** (process creation via `clone3()`, namespace setup, cgroup configuration, mount management) and **governance engine** (OverlayFS branch semantics, OPA/Rego policy evaluation, seccomp USER_NOTIF mediation, behavioral monitoring, audit chain, trust scoring). This dual role means puzzled effectively reimplements what Podman, crun, and conmon already provide — rootless containers, OCI image management, network configuration, Mac/Windows VM support, Quadlet integration, and decades of hardening.

This document proposes an architectural pivot: **puzzled becomes a governance-only daemon** that composes with **unmodified Podman** for all container lifecycle management. The key constraint is **zero Podman source code changes** — the architecture relies entirely on existing Podman extension points (OCI runtime hooks, standard `podman run` flags, container annotations, and crun's seccomp notification socket support).

The result is:

- **Less code** — deletion of ~3,200 lines of sandbox setup from puzzled (`sandbox/namespace.rs`, spawn logic in `sandbox/mod.rs`, `sandbox/capabilities.rs`, `sandbox/selinux.rs`, parts of `sandbox/cgroup.rs`, `sandbox/network.rs`, `sandbox/overlay.rs`, `sandbox/quota.rs`); net ~2,150 lines removed after new component additions (see §15.2)
- **Better developer experience** — rootless operation, Mac/Windows support via `podman machine`, IDE integration via Dev Containers
- **Faster delivery** — no dependency on the Podman team's roadmap; all integration via documented, stable extension points
- **Stronger containment** — Podman's container isolation (namespaces, cgroups, seccomp, SELinux) is battle-tested and continuously maintained; puzzled's governance layer (branch semantics, OPA policy, behavioral monitoring, audit) adds the agentic-specific value on top

The governance properties that make PuzzlePod unique — Fork, Explore, Commit with OPA-gated commit/rollback, seccomp USER_NOTIF mediation of execve/connect, Landlock filesystem ACLs, BPF LSM exec rate limiting, fanotify behavioral monitoring, HMAC-chained audit, trust scoring, and human-in-the-loop approval — are **entirely preserved**. What changes is who creates the container: Podman instead of puzzled.

**Target platforms:** RHEL 10+, Fedora 42+, CentOS Stream 10
**Target architectures:** x86_64, aarch64
**Podman version:** 5.0+ (OCI hooks, rootless, `podman machine`)
**crun version:** 1.14+ (seccomp notification socket support)

---

## 2. Problem Statement

### 2.1 puzzled Is Doing Two Jobs

The current `puzzled` codebase (~25,100 lines in `crates/puzzled/src/`) contains two orthogonal subsystems:

| Subsystem | Lines (est.) | What It Does | Unique to PuzzlePod? |
|---|---|---|---|
| **Sandbox creation** | ~9,200 (of which ~3,200 is commodity container runtime code that duplicates Podman/crun — see §15.2 for per-file breakdown; the remaining ~6,000 — Landlock, BPF LSM, fanotify, seccomp USER_NOTIF — is governance-specific and **retained**) | `clone3()` with `CLONE_NEWPID \| CLONE_NEWNS \| CLONE_NEWIPC \| CLONE_NEWUTS \| CLONE_NEWCGROUP \| CLONE_PIDFD` (network namespace is joined via `setns()` into a pre-created named netns, not created at `clone3()` time), cgroup setup, mount namespace, OverlayFS mount, `/proc` and `/sys` masking, network namespace, capability dropping, XFS quota setup, SELinux context, process environment (`namespace.rs`, `mod.rs`, `cgroup.rs`, `overlay.rs`, `network.rs`, `capabilities.rs`, `quota.rs`, `selinux.rs`, `seccomp/`, `landlock.rs`, `bpf_lsm.rs`, `fanotify.rs`) | **Partially** — process creation and namespace setup (~3,200 lines) duplicates container runtimes; Landlock, BPF LSM, fanotify, and seccomp USER_NOTIF (~6,000 lines) are governance-specific and retained |
| **Governance** | ~15,900 | Branch management (diff/commit/rollback), OPA/Rego policy evaluation, seccomp USER_NOTIF handling, D-Bus API, audit chain, IMA signing, trust scoring, governance review workflow, metrics, TUI, WAL commit, conflict detection | **Yes** — this is the unique value |

The sandbox creation subsystem is a partial reimplementation of what Podman/crun already does, but without:

| Capability | Podman | puzzled |
|---|---|---|
| Rootless containers (user namespaces) | Yes | No |
| OCI image pull/cache/management | Yes | No |
| Mac/Windows support (podman machine) | Yes | No |
| Quadlet (systemd declarative containers) | Yes | No |
| CNI/netavark network plugins | Yes | No |
| Health checks, restart policies | Yes | No |
| Pod support, compose compatibility | Yes | No |
| Container registry authentication | Yes | No |
| Security audit history (CVE fixes, penetration testing) | Decades | Months |

### 2.2 Developer Experience Gap

The current architecture requires:

1. **Linux only** — `clone3()`, Landlock, seccomp, namespaces are Linux kernel features. No Mac/Windows development story.
2. **Root required** — mount namespace setup, cgroup creation, BPF program loading require root or specific capabilities. No rootless mode.
3. **No OCI images** — agents run as bare processes, not containers. Developers cannot use their existing container workflows.
4. **Custom tooling** — developers must learn `puzzlectl` instead of using `podman` commands they already know.

### 2.3 The Podman Dependency Question

A previous analysis considered modifying Podman source code to add `--puzzle-branch` as a native flag. This approach was rejected because:

- **Alignment overhead** — Podman is a multi-team, multi-year project. Getting feature alignment takes quarters, not weeks.
- **Upstream maintenance burden** — any Podman-internal code becomes a long-term maintenance obligation tied to Podman's release cycle.
- **Unnecessary** — Podman already provides all needed extension points without code changes.

**Design constraint for this PRD:** Zero Podman source code modifications. All integration via documented, stable extension points.

### 2.4 What This PRD Does Not Change

The governance model — the unique value of PuzzlePod — is entirely preserved:

| Property | Status |
|---|---|
| Fork, Explore, Commit execution model | **Unchanged** |
| OverlayFS branching with diff/commit/rollback | **Unchanged** |
| OPA/Rego governance-gated commit | **Unchanged** |
| seccomp USER_NOTIF for execve/connect mediation | **Unchanged** (integration method changes) |
| Landlock irrevocable filesystem ACLs | **Unchanged** |
| BPF LSM exec rate limiting | **Unchanged** |
| fanotify behavioral monitoring | **Unchanged** |
| HMAC-chained audit log with IMA signing | **Unchanged** |
| GovernanceReview workflow (human-in-the-loop) | **Unchanged** |
| Trust scoring | **Unchanged** |
| D-Bus API (16 methods, 8 signals) | **Extended** (4 new methods proposed by this PRD: `GenerateSeccompProfile`, `GenerateLandlockRules`, `AttachGovernance`, `TriggerGovernance`; existing 16 methods + 8 signals unchanged) |
| Prometheus metrics (18 metrics) | **Unchanged** |
| puzzlectl CLI + TUI | **Extended** (3 new subcommands proposed by this PRD: `branch ensure`, `branch seccomp-profile`, `branch landlock-rules` — see §13.1) |

---

## 3. Architectural Decision

### 3.1 Decision Summary

| Question | Decision |
|---|---|
| Who creates the container process? | **Podman/crun** (not puzzled) |
| Who provides namespace isolation? | **Podman/crun** |
| Who configures cgroups? | **Podman** |
| Who manages the container lifecycle? | **Podman/conmon** |
| Who creates the OverlayFS branch? | **puzzled** (governance) |
| Who applies Landlock to the container? | **puzzle-init shim** inside container (puzzled generates the rules; shim calls `landlock_restrict_self()`) |
| Who handles seccomp USER_NOTIF? | **puzzled** via crun's notif socket |
| Who loads BPF LSM programs? | **puzzled** via OCI hook |
| Who monitors fanotify events? | **puzzled** |
| Who evaluates OPA policies? | **puzzled** |
| Who manages the audit chain? | **puzzled** |
| Who provides the developer CLI? | **`puzzle-podman`** wrapper (delegates to both podman and puzzled) |

### 3.2 Podman Extension Points Used (No Code Changes Required)

| Extension Point | Podman Feature | How We Use It |
|---|---|---|
| **OCI runtime hooks** | `--hooks-dir` / `/usr/share/containers/oci/hooks.d/` | `puzzle-hook` binary triggered on `createRuntime` and `poststop` stages for containers with `run.oci.handler=puzzlepod` annotation |
| **Container annotations** | `--annotation key=value` | `run.oci.handler=puzzlepod` triggers the OCI hook; `org.lobstertrap.puzzlepod.branch=ID` carries branch identity |
| **Container labels** | `--label key=value` | `org.lobstertrap.puzzlepod.profile=standard` carries profile identity |
| **Bind mounts** | `--mount type=bind,src=...,dst=...` | Branch merged directory mounted at `/workspace` |
| **Custom seccomp profile** | `--security-opt seccomp=profile.json` | OCI seccomp profile with `SCMP_ACT_NOTIFY` for execve/connect and `listenerPath` for puzzled |
| **Environment variables** | `--env KEY=VALUE` | `PUZZLEPOD_BRANCH_ID`, `PUZZLEPOD_WORKSPACE` |
| **SELinux labels** | `--security-opt label=type:puzzlepod_t` | SELinux type enforcement for agent domain |
| **Podman events** | `podman events --filter` | Optional: subscribe to container lifecycle events |

### 3.3 crun Extension Points Used (No Code Changes Required)

| Extension Point | crun Feature | How We Use It |
|---|---|---|
| **seccomp notification socket** | `listenerPath` field in OCI seccomp profile | crun creates the seccomp filter with `SCMP_ACT_NOTIFY`, connects to the Unix socket at `listenerPath` (which puzzled must have already created and be listening on), and sends the notification fd via `SCM_RIGHTS`. puzzled receives the fd on this socket. |
| **OCI state** | `/run/user/$UID/crun/$CONTAINER_ID/state.json` | OCI hook reads container PID from state |

---

## 4. Proposed Architecture

### 4.1 System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     Developer Interface                          │
│                                                                 │
│  puzzle-podman run --profile=standard myimage ./agent.py         │
│  puzzle-podman agent list | inspect | approve | reject | diff    │
│                                                                 │
│  (bash wrapper, currently 294 lines — enhanced to ~350-400 lines) │
└───────────┬────────────────────────────────────┬────────────────┘
            │                                    │
     podman flags                          D-Bus calls
     (standard CLI)                        (puzzlectl/puzzled)
            │                                    │
            ▼                                    ▼
┌───────────────────────┐          ┌──────────────────────────────┐
│   Podman (unmodified) │          │   puzzled (governance daemon) │
│                       │          │                              │
│ - OCI image mgmt      │          │ - Branch management          │
│ - clone3() + NS setup  │   ┌────►│   (OverlayFS upper layer     │
│ - cgroup v2 limits     │   │     │    create/diff/commit/rollback│
│ - Network (netavark)   │   │     │ - OPA/Rego policy engine     │
│ - Rootless mode        │   │     │ - seccomp USER_NOTIF handler │
│ - podman machine (VM)  │   │     │ - Landlock ruleset generation│
│ - conmon lifecycle     │   │     │ - BPF LSM program loading   │
│                       │   │     │ - fanotify monitoring        │
│  ┌─────────────────┐  │   │     │ - Audit chain (HMAC + IMA)  │
│  │ crun (OCI runtime│  │   │     │ - Trust scoring             │
│  │                  │  │   │     │ - GovernanceReview workflow  │
│  │ seccomp notif ───┼──┼───┘     │ - D-Bus API (20 methods¹)   │
│  │  fd passthrough  │  │         │ - Prometheus metrics (18)    │
│  │                  │  │         │ - Dashboard / TUI            │
│  │ OCI hooks ───────┼──┼────────►│                              │
│  │  (createRuntime, │  │         └──────────────────────────────┘
│  │   poststop)      │  │
│  └─────────────────┘  │
└───────────────────────┘
```

> ¹ 20 methods = 16 existing (implemented in `crates/puzzled/src/dbus.rs`) + 4 proposed Podman-native methods (`GenerateSeccompProfile`, `GenerateLandlockRules`, `AttachGovernance`, `TriggerGovernance`). Phase 8 proposes 4 additional long-running agent methods (24 total on Manager), plus Audit (4 methods) and Policy (6 methods) on separate interfaces.

### 4.2 Execution Flow

```
1. Developer runs:
   puzzle-podman run --profile=standard python:3.12 ./agent.py

2. puzzle-podman wrapper:
   a. Calls puzzled (D-Bus: CreateBranch) → receives branch_id, merged_dir
   b. Calls puzzled (D-Bus: GenerateSeccompProfile) → receives profile path
   c. Calls puzzled (D-Bus: GenerateLandlockRules) → receives rules file path on host
   d. Runs: podman run \
        --mount type=bind,src=$MERGED_DIR,dst=/workspace \
        --mount type=bind,src=/usr/libexec/puzzle-init,dst=/puzzle-init,ro \
        --mount type=bind,src=$LANDLOCK_RULES,dst=/run/puzzlepod/landlock.json,ro \
        --entrypoint /puzzle-init \
        --security-opt seccomp=$SECCOMP_PROFILE \
        --annotation run.oci.handler=puzzlepod \
        --annotation org.lobstertrap.puzzlepod.branch=$BRANCH_ID \
        --label org.lobstertrap.puzzlepod.profile=standard \
        --env PUZZLEPOD_BRANCH_ID=$BRANCH_ID \
        --env PUZZLEPOD_WORKSPACE=/workspace \
        --security-opt label=type:puzzlepod_t \
        python:3.12 ./agent.py
      (puzzle-init shim applies Landlock via landlock_restrict_self(),
       then exec's the real command — ./agent.py)
      NOTE: Do NOT place `--` between the image and command — Podman passes
      `--` as a literal argv[1] to the entrypoint, not as a flag separator.

3. podman delegates to crun:
   a. crun creates container (namespaces, cgroups, rootfs, network)
   b. crun installs seccomp filter with SCMP_ACT_NOTIFY for execve/connect
   c. crun sends seccomp notif fd to puzzled via listenerPath socket
   d. crun invokes OCI createRuntime hook → puzzle-hook

4. puzzle-hook (createRuntime stage):
   a. Reads container PID from OCI state JSON
   b. Calls puzzled (D-Bus) to:
      - Load BPF LSM hooks on container cgroup
      - Start fanotify monitoring on branch upper layer
      - Register container PID for seccomp USER_NOTIF handling
   (Landlock rules file was already generated in step 2c and bind-mounted
    into the container — the puzzle-init shim reads it at container start)

5. Container runs:
   - Filesystem writes captured by OverlayFS upper layer (in /workspace)
   - execve/connect syscalls mediated by puzzled via seccomp USER_NOTIF
   - Landlock restricts filesystem access (kernel-enforced, irrevocable)
   - BPF LSM rate-limits exec calls
   - fanotify monitors file access patterns

6. Container exits:
   a. crun invokes OCI poststop hook → puzzle-hook
   b. puzzle-hook calls puzzled (D-Bus) to trigger governance:
      - cgroup.freeze (if still alive — TOCTOU protection)
      - Walk OverlayFS upper layer → generate diff
      - Evaluate OPA/Rego policy against diff
      - If approved: WAL-based commit to base filesystem
      - If rejected: discard upper layer (zero residue)
   c. If require_human_approval=true:
      - Transition to GovernanceReview state
      - Emit governance_review_pending D-Bus signal
      - Wait for ApproveBranch/RejectBranch or timeout
   d. puzzle-podman wrapper displays result and prompts user
```

### 4.3 Component Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        KERNEL (unmodified)                       │
│                                                                 │
│  ┌───────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────┐    │
│  │ Landlock  │ │ seccomp  │ │ BPF LSM  │ │ Namespaces     │    │
│  │ (ABI v4+) │ │ (NOTIFY) │ │ (5.7+)   │ │ (PID,mount,net)│    │
│  └───────────┘ └──────────┘ └──────────┘ └────────────────┘    │
│  ┌───────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────┐    │
│  │ OverlayFS │ │ cgroups  │ │ SELinux  │ │ fanotify       │    │
│  │ (CoW)     │ │ v2       │ │          │ │ (monitoring)   │    │
│  └───────────┘ └──────────┘ └──────────┘ └────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│                     USERSPACE                                    │
│                                                                 │
│  Configured by podman/crun:      Configured by puzzled:          │
│  ┌────────────────────────┐      ┌──────────────────────────┐   │
│  │ PID namespace          │      │ Landlock ruleset (shim)   │   │
│  │ Mount namespace        │      │ seccomp USER_NOTIF handler│   │
│  │ Network namespace      │      │ BPF LSM programs          │   │
│  │ UTS namespace          │      │ fanotify marks            │   │
│  │ Cgroup namespace       │      │ OverlayFS branch (upper)  │   │
│  │ User namespace         │      │ OPA/Rego policy engine    │   │
│  │ cgroup v2 limits       │      │ Audit chain               │   │
│  │ seccomp filter (NOTIFY)│      │ Trust scoring             │   │
│  │ SELinux context        │      │                            │   │
│  └────────────────────────┘      └──────────────────────────┘   │
│       ▲                                ▲                        │
│       │ OCI runtime spec               │ D-Bus + OCI hooks      │
│       │                                │                        │
│  ┌────┴──────┐  ┌──────────┐    ┌──────┴──────┐                │
│  │ podman    │  │ crun     │    │ puzzled      │                │
│  │           │──│          │    │             │                │
│  │ container │  │ OCI      │    │ governance  │                │
│  │ lifecycle │  │ runtime  │    │ daemon      │                │
│  └───────────┘  └──────────┘    └─────────────┘                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Component Design: puzzle-podman Wrapper

### 5.1 Current State

The `puzzle-podman` wrapper already exists at `podman/puzzle-podman` (294 lines of bash). It supports `run` with `--puzzle-branch` flags and `agent` subcommands (`list`, `inspect`, `approve`, `reject`, `diff`). The current implementation creates a branch via `puzzlectl`, passes the overlay as a bind mount, and offers interactive commit/rollback on exit.

**Components that do not yet exist** (to be created by this PRD):
- `crates/puzzle-hook/` — Rust OCI runtime hook binary (~500 lines). Currently a bash script at `podman/hooks/puzzle-branch-hook.sh` (74 lines).
- `puzzle-init/` — Landlock shim static binary (~200 lines).
- `seccomp_listener.rs` — Unix socket listener for crun seccomp notification fd (~200 lines).
- 4 new D-Bus methods: `GenerateSeccompProfile`, `GenerateLandlockRules`, `AttachGovernance`, `TriggerGovernance`.
- 3 new `puzzlectl` subcommands: `branch ensure`, `branch seccomp-profile`, `branch landlock-rules`.

### 5.2 Enhanced Design

The wrapper gains three new responsibilities:

1. **Seccomp profile generation** — request a seccomp profile from puzzled that includes `SCMP_ACT_NOTIFY` actions and the `listenerPath` for puzzled's notification socket.
2. **OCI annotation injection** — add the `run.oci.handler=puzzlepod` annotation so the OCI hook fires.
3. **Podman machine detection** — on Mac/Windows, transparently proxy puzzled calls through the VM.

```bash
#!/bin/bash
# puzzle-podman — enhanced for podman-native architecture
set -euo pipefail

PROG=$(basename "$0")
PUZZLECTL="${PUZZLECTL:-puzzlectl}"
PODMAN="${PODMAN:-podman}"

# Detect podman machine (Mac/Windows)
detect_podman_machine() {
    if podman machine inspect &>/dev/null 2>&1; then
        PUZZLECTL="podman machine ssh -- puzzlectl"
        IS_REMOTE=1
    else
        IS_REMOTE=0
    fi
}

# Create branch and generate seccomp profile
setup_branch() {
    local profile="$1"
    local base="$2"

    # Create the branch via puzzled D-Bus
    BRANCH_OUTPUT=$($PUZZLECTL branch create \
        --profile="$profile" --base="$base" --output=json 2>&1)
    BRANCH_ID=$(echo "$BRANCH_OUTPUT" | \
        grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -z "$BRANCH_ID" ]; then
        echo "[$PROG] Error: failed to create branch." >&2
        echo "$BRANCH_OUTPUT" >&2
        exit 1
    fi

    # Get merged directory
    MERGED_DIR=$($PUZZLECTL branch inspect "$BRANCH_ID" --output=json 2>/dev/null | \
        grep -o '"merged_dir":"[^"]*"' | head -1 | cut -d'"' -f4)

    # Generate seccomp profile with USER_NOTIF for execve/connect
    SECCOMP_PROFILE=$($PUZZLECTL branch seccomp-profile \
        "$BRANCH_ID" --output=path 2>/dev/null)

    # Generate Landlock rules file for the puzzle-init shim
    LANDLOCK_RULES=$($PUZZLECTL branch landlock-rules \
        "$BRANCH_ID" --output=path 2>/dev/null)

    echo "[$PROG] Branch: $BRANCH_ID"
    echo "[$PROG] Workspace: $MERGED_DIR"
}

# Resolve image ENTRYPOINT/CMD when user provides no explicit command.
# --entrypoint override clears the image's original ENTRYPOINT and CMD,
# so we must retrieve them and pass them as arguments to puzzle-init.
resolve_image_command() {
    local image="$1"
    shift
    local -a user_cmd=("$@")

    if [ ${#user_cmd[@]} -gt 0 ]; then
        # User provided an explicit command — use it as-is
        RESOLVED_CMD=("${user_cmd[@]}")
        return
    fi

    # No explicit command — retrieve the image's original ENTRYPOINT + CMD
    local ep_json cmd_json
    ep_json=$($PODMAN inspect "$image" --format '{{json .Config.Entrypoint}}' 2>/dev/null) || ep_json="null"
    cmd_json=$($PODMAN inspect "$image" --format '{{json .Config.Cmd}}' 2>/dev/null) || cmd_json="null"

    # Parse JSON arrays into bash arrays (handles shell-form entrypoints like
    # ["/bin/sh", "-c", "python3"] correctly by preserving all tokens)
    local -a ep_arr=() cmd_arr=()
    if [ "$ep_json" != "null" ] && [ -n "$ep_json" ]; then
        readarray -t ep_arr < <(echo "$ep_json" | python3 -c 'import json,sys; [print(x) for x in json.load(sys.stdin)]' 2>/dev/null)
    fi
    if [ "$cmd_json" != "null" ] && [ -n "$cmd_json" ]; then
        readarray -t cmd_arr < <(echo "$cmd_json" | python3 -c 'import json,sys; [print(x) for x in json.load(sys.stdin)]' 2>/dev/null)
    fi

    RESOLVED_CMD=("${ep_arr[@]}" "${cmd_arr[@]}")

    if [ ${#RESOLVED_CMD[@]} -eq 0 ]; then
        echo "[$PROG] Error: no command provided and image has no ENTRYPOINT or CMD." >&2
        exit 1
    fi
}

# Run container with governance
run_governed() {
    local image="$1"
    shift
    local cmd=("$@")

    # Resolve the command (handles no-command case by inspecting image metadata)
    resolve_image_command "$image" "${cmd[@]}"
    cmd=("${RESOLVED_CMD[@]}")

    $PODMAN run \
        --mount "type=bind,src=$MERGED_DIR,dst=/workspace" \
        --mount "type=bind,src=/usr/libexec/puzzle-init,dst=/puzzle-init,ro" \
        --mount "type=bind,src=$LANDLOCK_RULES,dst=/run/puzzlepod/landlock.json,ro" \
        --entrypoint /puzzle-init \
        --security-opt "seccomp=$SECCOMP_PROFILE" \
        --annotation "run.oci.handler=puzzlepod" \
        --annotation "org.lobstertrap.puzzlepod.branch=$BRANCH_ID" \
        --label "org.lobstertrap.puzzlepod.profile=$AGENT_PROFILE" \
        --env "PUZZLEPOD_BRANCH_ID=$BRANCH_ID" \
        --env "PUZZLEPOD_WORKSPACE=/workspace" \
        "${PODMAN_ARGS[@]}" \
        "$image" "${cmd[@]}"
}
```

### 5.3 Command Interface

```
puzzle-podman run [OPTIONS] IMAGE [COMMAND...]
puzzle-podman agent <list|inspect|approve|reject|diff> [ARGS...]

Run Options:
  --profile=PROFILE       Agent profile (default: standard). The codebase ships 23
                          profiles including the 3 core profiles (restricted, standard,
                          privileged) and 20 domain-specific profiles (safety-critical,
                          edge-minimal, code-assistant, ml-training, etc.). See
                          policies/profiles/ for the full list.
  --base=PATH             Base workspace directory (default: /var/agent-workspace)
  --auto-commit           Automatically commit on clean exit
  --auto-rollback         Automatically rollback on exit
  --no-seccomp-notif      Disable seccomp USER_NOTIF (static filter only)
  -h, --help              Show this help

All other options are passed through to 'podman run'.

Examples:
  puzzle-podman run --profile=restricted alpine sh
  puzzle-podman run --profile=standard -v ./src:/workspace/src python:3.12 ./agent.py
  puzzle-podman run --profile=standard --gpus all nvidia/cuda:12 ./ml-agent.py
  puzzle-podman agent list
  puzzle-podman agent approve abc-123
```

Note: because all unknown flags pass through to `podman run`, the full power of Podman is available — GPUs, volumes, network configuration, resource limits, etc.

### 5.4 The Sequencing Problem

Podman's OCI hooks fire at `createRuntime` — *after* the container's namespaces, cgroups, and mounts are already configured. But governance attachment requires three artifacts to exist *before* `podman run` executes, because Podman needs them as command-line arguments:

1. **The OverlayFS branch** (upper/work/merged directories) — Podman bind-mounts the merged dir into the container via `--mount`
2. **A seccomp profile JSON** with `listenerPath` pointing to puzzled's notification socket — Podman passes this to crun via `--security-opt seccomp=`
3. **A Landlock rules JSON** — Podman bind-mounts it into the container so the puzzle-init shim can read it at startup

No existing Podman extension point fires early enough to create these. The OCI hook can attach BPF LSM programs, start fanotify monitoring, and register the container PID *after* creation, but the three artifacts above must already be on disk when `podman run` is invoked. This is why `puzzle-podman` exists.

### 5.5 Detailed Execution Flow

```
puzzle-podman run --profile=standard python:3.12 ./agent.py

  Step 1: Create branch via puzzled
    puzzlectl branch ensure my-branch --profile=standard --base=$PWD
    → branch_id, merged_dir

  Step 2: Generate seccomp profile via puzzled
    puzzlectl branch seccomp-profile $BRANCH_ID --output=path
    → /var/lib/puzzled/branches/$BRANCH_ID/seccomp.json

  Step 3: Generate Landlock rules via puzzled
    puzzlectl branch landlock-rules $BRANCH_ID --output=path
    → /var/lib/puzzled/branches/$BRANCH_ID/landlock.json

  Step 4: Run podman with all governance artifacts wired in
    podman run \
      --mount type=bind,src=$MERGED_DIR,dst=/workspace \
      --mount type=bind,src=/usr/libexec/puzzle-init,dst=/puzzle-init,ro \
      --mount type=bind,src=$LANDLOCK_RULES,dst=/run/puzzlepod/landlock.json,ro \
      --entrypoint /puzzle-init \
      --security-opt seccomp=$SECCOMP_PROFILE \
      --security-opt label=type:puzzlepod_t \
      --annotation run.oci.handler=puzzlepod \
      --annotation org.lobstertrap.puzzlepod.branch=$BRANCH_ID \
      --label org.lobstertrap.puzzlepod.profile=standard \
      --env PUZZLEPOD_BRANCH_ID=$BRANCH_ID \
      --env PUZZLEPOD_WORKSPACE=/workspace \
      python:3.12 ./agent.py

  Step 5: On container exit, prompt for commit/rollback
    (or auto-commit/auto-rollback based on flags)
```

All unknown flags pass through to `podman run` transparently — GPUs, volumes, resource limits, network configuration, etc.

### 5.6 Running Without puzzle-podman (Manual Steps)

The wrapper is convenience, not magic. Every step can be performed manually with `puzzlectl` and `podman`:

```bash
# Prerequisites: puzzled is running, puzzle-init is installed at /usr/libexec/puzzle-init

# 1. Create the branch and governance artifacts
BRANCH_ID=$(puzzlectl branch create \
    --profile=standard \
    --base=/home/user/project \
    --output=json | jq -r .id)

# 2. Get the merged directory path
MERGED_DIR=$(puzzlectl branch inspect "$BRANCH_ID" --output=json | jq -r .merged_dir)

# 3. Generate the seccomp profile (writes to well-known path)
SECCOMP_PROFILE=$(puzzlectl branch seccomp-profile "$BRANCH_ID" --output=path)

# 4. Generate the Landlock rules (writes to well-known path)
LANDLOCK_RULES=$(puzzlectl branch landlock-rules "$BRANCH_ID" --output=path)

# 5. Run the container with podman directly
podman run \
    --mount "type=bind,src=$MERGED_DIR,dst=/workspace" \
    --mount "type=bind,src=/usr/libexec/puzzle-init,dst=/puzzle-init,ro" \
    --mount "type=bind,src=$LANDLOCK_RULES,dst=/run/puzzlepod/landlock.json,ro" \
    --entrypoint /puzzle-init \
    --security-opt "seccomp=$SECCOMP_PROFILE" \
    --security-opt "label=type:puzzlepod_t" \
    --annotation "run.oci.handler=puzzlepod" \
    --annotation "org.lobstertrap.puzzlepod.branch=$BRANCH_ID" \
    --label "org.lobstertrap.puzzlepod.profile=standard" \
    --env "PUZZLEPOD_BRANCH_ID=$BRANCH_ID" \
    --env "PUZZLEPOD_WORKSPACE=/workspace" \
    python:3.12 ./agent.py

# 6. After container exits, inspect the diff
puzzlectl branch diff "$BRANCH_ID"

# 7. Commit or rollback
puzzlectl branch approve "$BRANCH_ID"
# or: puzzlectl branch reject "$BRANCH_ID" --reason="unwanted changes"
```

### 5.7 Running Without puzzle-podman (Quadlet / systemd)

For production deployments managed by systemd, Quadlet `.container` files replace the wrapper. The `ExecStartPre` commands handle the pre-creation steps. See §13.1 for the full Quadlet example.

### 5.8 Component Lifecycle Table

The pre-creation steps are handled by the wrapper, Quadlet, or manual CLI calls (§5.4 explains why). The `createRuntime` and `poststop` steps are handled by the OCI hook (§6 describes the hook implementation in detail).

| Lifecycle Phase | puzzle-podman wrapper (interactive) | Quadlet (production) | Manual (no wrapper) |
|---|---|---|---|
| **Pre-creation:** create branch | `puzzlectl branch ensure` | `ExecStartPre=puzzlectl branch ensure` | `puzzlectl branch create` |
| **Pre-creation:** generate seccomp | `puzzlectl branch seccomp-profile` | `ExecStartPre=puzzlectl branch seccomp-profile` | `puzzlectl branch seccomp-profile` |
| **Pre-creation:** generate Landlock | `puzzlectl branch landlock-rules` | `ExecStartPre=puzzlectl branch landlock-rules` | `puzzlectl branch landlock-rules` |
| **Creation:** start container | `podman run` (with flags) | systemd starts Quadlet unit | `podman run` (with flags) |
| **createRuntime hook:** attach BPF LSM, fanotify, register PID | puzzle-hook (automatic) | puzzle-hook (automatic) | puzzle-hook (automatic) |
| **Runtime:** seccomp USER_NOTIF mediation | puzzled (automatic) | puzzled (automatic) | puzzled (automatic) |
| **Container exit:** trigger governance | puzzle-hook poststop (automatic) | puzzle-hook poststop (automatic) | puzzle-hook poststop (automatic) |
| **Post-exit:** review and commit/rollback | Interactive prompt | Automatic per policy | `puzzlectl branch approve/reject` |

### 5.9 Could puzzle-podman Be Eliminated?

Yes, if any of the following happened:

- **Podman adds a pre-run hook** — a hook stage that fires before container creation, allowing puzzled to generate artifacts before `podman run` assembles its arguments. No such stage exists in the OCI runtime spec today.
- **Podman adds plugin support** — a mechanism for plugins to modify the container spec before creation. Podman does not currently have a plugin API.
- **puzzled manages podman run** — puzzled could invoke `podman run` itself, but this would make puzzled a container orchestrator, violating the architecture's core principle (Podman contains, puzzled governs).
- **Podman adds `podman agent` subcommand** - we could contribute effectively the wrapper functionality directly to podman as a the `podman agent` subcommand, but this would be prohibitively slow for this project in terms of development and go to market timeline. We might do this in the future and have the wrapper script effectively pass through to `podman agent`, but we would keep the wrapper script for backwards compatibility until it was deemed reasonable to phase out.

Until one of these happens, `puzzle-podman` is the thinnest viable glue between puzzled's governance setup and Podman's container lifecycle. It adds no state, no daemon, no configuration — it is a script that calls `puzzlectl` three times, then calls `podman run` once.

---

## 6. Component Design: puzzle-hook (OCI Runtime Hook)

### 6.1 OCI Hooks Background

OCI runtime hooks are executables invoked by the OCI runtime (crun) at specific container lifecycle stages. They are configured via JSON files in `/usr/share/containers/oci/hooks.d/` or directories specified by `--hooks-dir`. This is a documented, stable Podman/crun feature that requires no source code changes.

**Note on hook JSON format:** The standalone hook JSON files with `when` clause filtering (e.g., `when.annotations` to match specific containers) and the `stages` array are a **Podman/CRI-O-specific extension**, not part of the OCI runtime spec itself. The OCI runtime spec defines hooks in the container's `config.json` bundle configuration (separate arrays per hook type). Podman's hook manager evaluates the `when` clause and injects matching hooks into the container's `config.json` before passing it to crun. This means the hook filtering mechanism works with Podman and CRI-O but **not with Docker or containerd**. Since this PRD targets Podman exclusively, this is acceptable. The distinction matters for future portability (e.g., the Kubernetes operator path in §23.3 using CRI-O is compatible; a containerd path would require a different hook registration mechanism).

### 6.2 Hook Configuration

```json
{
  "version": "1.0.0",
  "hook": {
    "path": "/usr/libexec/puzzle-hook",
    "args": ["puzzle-hook"],
    "env": []
  },
  "when": {
    "annotations": {
      "run.oci.handler": "puzzlepod"
    }
  },
  "stages": ["createRuntime", "poststop"]
}
```

**Key design point:** The hook only fires for containers with the `run.oci.handler=puzzlepod` annotation. All other containers are completely unaffected. The annotation is injected by the `puzzle-podman` wrapper.

**Migration note:** The current codebase uses a different annotation (`org.lobstertrap.puzzlepod.branch` in `podman/hooks/puzzle-branch.json`) and a bash hook (`podman/hooks/puzzle-branch-hook.sh`, 74 lines, `createRuntime` only). This PRD replaces both with the new `run.oci.handler=puzzlepod` annotation, a compiled Rust hook binary, and adds the `poststop` stage. Existing Quadlet files and wrapper invocations using the old annotation must be updated during Migration Phase 2 (§15.1).

### 6.3 Hook Binary Design

```rust
// crates/puzzle-hook/src/main.rs (~500 lines)

use anyhow::Result;
use serde::Deserialize;
use std::io::Read;

/// OCI state passed to hooks via stdin (OCI runtime spec §5.2)
#[derive(Deserialize)]
struct OciState {
    /// Container's OCI ID
    id: String,
    /// Container's PID (init process in the container's PID namespace)
    pid: Option<u32>,
    /// Container status
    status: String,
    /// Container annotations
    annotations: Option<std::collections::HashMap<String, String>>,
}

fn main() -> Result<()> {
    // OCI hooks receive the container state on stdin
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let state: OciState = serde_json::from_str(&input)?;

    // Determine lifecycle stage from OCI state.
    // The hook fires at both createRuntime and poststop (per hook JSON config).
    // We distinguish by checking the container status field in the OCI state:
    // - "creating" → createRuntime stage (status is "creating" during create-phase hooks;
    //   it transitions to "created" only after all create hooks complete successfully)
    // - "stopped" → poststop stage
    let stage = detect_stage_from_state(&state);

    // Extract branch ID from annotation
    let branch_id = state.annotations.as_ref()
        .and_then(|a| a.get("org.lobstertrap.puzzlepod.branch"))
        .ok_or_else(|| anyhow::anyhow!("missing branch annotation"))?;

    match stage.as_str() {
        "createRuntime" => handle_create_runtime(&state, branch_id)?,
        "poststop" => handle_poststop(&state, branch_id)?,
        _ => {} // Ignore other stages
    }

    Ok(())
}

fn handle_create_runtime(state: &OciState, branch_id: &str) -> Result<()> {
    let pid = state.pid
        .ok_or_else(|| anyhow::anyhow!("no PID in createRuntime state"))?;

    // Connect to puzzled via D-Bus and request governance attachment
    let client = PuzzledHookClient::connect()?;

    // NOTE: Landlock rules file was already generated by the puzzle-podman
    // wrapper (via puzzlectl) and bind-mounted into the container before
    // podman run. The puzzle-init shim reads it at container start and
    // calls landlock_restrict_self(). No Landlock work needed in the hook.

    // 1. Load BPF LSM hooks on the container's cgroup
    //    puzzled identifies the cgroup from /proc/{pid}/cgroup and
    //    attaches the exec rate limiter
    client.attach_bpf_lsm(branch_id, pid)?;

    // 2. Start fanotify monitoring on the branch upper layer
    client.start_fanotify(branch_id)?;

    // 3. Register the container PID for seccomp USER_NOTIF handling
    //    (puzzled is already listening on the notif socket via crun)
    client.register_container(branch_id, pid)?;

    Ok(())
}

fn handle_poststop(state: &OciState, branch_id: &str) -> Result<()> {
    let client = PuzzledHookClient::connect()?;

    // Trigger governance evaluation
    // puzzled will: freeze → diff → OPA evaluate → commit/rollback
    client.trigger_governance(branch_id)?;

    Ok(())
}
```

### 6.4 Landlock Application via Entrypoint Shim

A critical design question is how Landlock is applied to a container process that puzzled did not create. `landlock_restrict_self()` must be called by the target process itself — it cannot be applied externally.

**Solution: Landlock shim entrypoint.**

puzzled generates a small static binary (`puzzle-init`) that:

1. Reads the Landlock ruleset from a JSON file bind-mounted at `/run/puzzlepod/landlock.json`
2. Creates a Landlock ruleset fd, adds rules, and calls `landlock_restrict_self()` to apply the ruleset (irrevocable)
3. Calls `execve()` to replace itself with the user's actual command

The `puzzle-podman` wrapper prepends this shim to the container entrypoint:

```bash
$PODMAN run \
    --mount "type=bind,src=/usr/libexec/puzzle-init,dst=/puzzle-init,ro" \
    --mount "type=bind,src=$LANDLOCK_RULES,dst=/run/puzzlepod/landlock.json,ro" \
    --entrypoint /puzzle-init \
    "$IMAGE" "$ORIGINAL_ENTRYPOINT" "${ORIGINAL_ARGS[@]}"
```

The shim binary is ~200 lines of statically-linked C (or Rust with `#![no_std]`), compiled for both x86_64 and aarch64. It is bind-mounted read-only from the host.

**Properties:**
- Landlock is applied before the user process runs — no window of unrestricted access
- The shim execs into the real command — zero ongoing overhead
- Landlock is irrevocable — survives even if puzzled crashes (kernel-enforced)
- The shim is a static binary — no dependency on container's libc

### 6.5 Hook Lifecycle Guarantees

| Stage | Guarantee | Failure Behavior |
|---|---|---|
| `createRuntime` | Runs after container creation, before user process starts | If hook fails, crun aborts container start. Container never runs ungoverned. |
| `poststop` | Runs after container exits (including crash/OOM/signal) | If hook fails, governance falls back to puzzled cleanup thread. Branch is not leaked. |

The `createRuntime` failure guarantee is critical: **a container annotated with `run.oci.handler=puzzlepod` will never run without governance**. If puzzled is down and the hook cannot connect, the container fails to start. This is fail-closed behavior.

**Behavioral change from current hook:** The existing bash hook (`puzzle-branch-hook.sh`) is **fail-open** — it uses `exit 0` on all error paths, allowing the container to start even if branch creation or puzzled communication fails. The proposed `puzzle-hook` reverses this to **fail-closed** by returning a non-zero exit code on failure, causing crun to abort the container start. This is a deliberate security improvement but represents a behavioral change that operators must be aware of during migration (see §15.1, Migration Phase 2).

### 6.6 Current vs. Proposed Implementation

| Aspect | Current (bash hook) | Proposed (puzzle-hook) |
|---|---|---|
| **Binary** | `podman/hooks/puzzle-branch-hook.sh` (bash, ~75 lines) | `crates/puzzle-hook/` (Rust, ~500 lines) |
| **Trigger annotation** | `org.lobstertrap.puzzlepod.branch` | `run.oci.handler=puzzlepod` |
| **Lifecycle stages** | `createRuntime` only | `createRuntime` + `poststop` |
| **Failure behavior** | Fail-open (`exit 0`) — container runs ungoverned | Fail-closed (non-zero exit) — crun aborts container start |
| **Post-exit governance** | Manual (`puzzlectl approve/reject`) | Automatic via `poststop` hook |
| **Branch creation** | Inside hook (at createRuntime) | Before hook (in wrapper or Quadlet ExecStartPre) |
| **D-Bus transport** | Shell subprocess (`puzzlectl`) | Direct D-Bus via `zbus` |

### 6.7 Per-Stage Behavior Detail

**`createRuntime` stage** (fires after container creation, before user process starts):

The hook reads the OCI runtime state from stdin, extracts the container PID and annotations, then calls puzzled via D-Bus:

1. `AttachGovernance(branch_id, container_pid, container_id)` — registers the container with puzzled
2. BPF LSM attachment — loads exec counting/rate limiting BPF programs on the container's cgroup
3. fanotify start — begins file access monitoring on the branch's upper layer

If any D-Bus call fails, the hook exits with a non-zero status code. crun treats this as a container start failure and aborts — the container **never runs ungoverned**.

**`poststop` stage** (fires after container exits, including crash/OOM/signal):

1. `TriggerGovernance(branch_id)` — instructs puzzled to run the governance evaluation:
   - Freeze the cgroup (if processes remain)
   - Generate diff from the OverlayFS upper layer
   - Evaluate OPA/Rego policy against the changeset
   - If approved: WAL-based commit to base filesystem
   - If rejected: discard upper layer (zero residue)

If the `poststop` hook fails (e.g., puzzled is temporarily down), governance falls back to puzzled's cleanup thread, which discovers orphaned branches on the next scan. The branch is not leaked.

### 6.8 Hook Registration

The hook is registered via OCI hooks configuration (no Podman source changes required):

```json
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
```

This file is installed at `/usr/share/containers/oci/hooks.d/puzzlepod.json`. The hook only fires for containers with the `run.oci.handler=puzzlepod` annotation. All other containers are completely unaffected.

### 6.9 Migration Considerations

The switch from fail-open to fail-closed is a **behavioral change** that operators must be aware of during migration. Containers that previously started (with degraded governance) will now fail to start if puzzled is down or the hook encounters an error. This is the intended security posture — governed containers shall never run ungoverned — but existing deployments using the current `org.lobstertrap.puzzlepod.branch` annotation must update to `run.oci.handler=puzzlepod` and ensure puzzled is running before container start.

The branch creation timing also changes: the current bash hook creates branches inside the hook at `createRuntime`, while the proposed architecture creates branches **before** `podman run` (in the wrapper or Quadlet `ExecStartPre`). Operators migrating from hook-only workflows must add the wrapper or `ExecStartPre` step.

---

## 7. Component Design: puzzled (Governance Daemon)

### 7.1 What puzzled Drops

The following code is removed or deprecated:

| Module | Current Purpose | Lines | Replacement |
|---|---|---|---|
| `sandbox/namespace.rs` | `clone3()` with namespace flags, `CLONE_INTO_CGROUP`. Note: `allocate_child_stack()` is already dead code (custom stacks cause SIGSEGV; `clone3` uses `stack=0, stack_size=0`). | ~441 | Podman/crun |
| `sandbox/mod.rs` (spawn logic) | Process creation, environment setup, `procfs`/`sysfs` masking, pivot_root | ~1,756 | Podman/crun |
| `sandbox/cgroup.rs` (creation) | cgroup v2 directory creation, limit writes | ~581 | Podman (via `--memory`, `--cpus`, `--pids-limit`) |
| `sandbox/network.rs` (namespace) | Network namespace creation, `ip netns add`, veth pair setup | ~755 | Podman/netavark |
| `sandbox/capabilities.rs` | Linux capability dropping for agent processes | ~592 | Podman (via `--cap-drop`, `--cap-add`) |
| `sandbox/quota.rs` | XFS project quota setup on OverlayFS upper layer | ~364 | Partially dropped — use `podman --storage-opt size=` for rootless; keep quota logic for root mode branches |
| `sandbox/selinux.rs` | SELinux context setup for agent domain | ~161 | Podman (via `--security-opt label=type:puzzlepod_t`) |

**Estimated deletion: ~3,200 lines** (of ~9,200 sandbox lines; Landlock, BPF LSM, fanotify, seccomp modules are retained). See Section 15.2 for the detailed per-file breakdown.

### 7.2 What puzzled Keeps

| Module | Purpose | Changes |
|---|---|---|
| `branch.rs` (~2,691 lines) | Branch management, diff, commit, rollback, governance review, state serialization | Significant refactoring: `create()` currently orchestrates full sandbox setup including `SandboxBuilder::build()`, seccomp handler registration, network isolation, BPF LSM, and fanotify init (lines 162-397). Must be refactored to create OverlayFS upper layer and return `merged_dir` without spawning a process; governance attachment (BPF LSM, fanotify, seccomp handler registration) moves to the new `AttachGovernance` D-Bus method, called from the OCI hook. |
| `policy.rs` (~766 lines) | OPA/Rego policy evaluation | None |
| `dbus.rs` (~1,632 lines) | D-Bus API (16 methods, 8 signals) | New methods: `GenerateSeccompProfile`, `GenerateLandlockRules`, `AttachGovernance`, `TriggerGovernance` |
| `audit_store.rs` (~805 lines) | HMAC-chained audit log | None |
| `ima.rs` (~779 lines) | Ed25519 changeset signing | None |
| `config.rs` (~767 lines) | DaemonConfig | Minor: remove sandbox-specific fields; add hook configuration |
| `metrics.rs` (~565 lines) | Prometheus metrics (18 metrics), Unix socket HTTP server | None |
| `seccomp_handler.rs` (~1,415 lines) | seccomp USER_NOTIF dispatch and gating logic | Minor: fd source changes (see seccomp_listener.rs) |
| `sandbox/landlock.rs` (~600 lines) | Landlock ruleset generation | Modified: generates rules JSON file for `puzzle-init` shim instead of calling `landlock_restrict_self()` directly |
| `sandbox/seccomp/` (~1,508 lines) | seccomp filter generation and notification handling | Modified: receives notif fd from crun socket instead of from `clone3()` return |
| `sandbox/bpf_lsm.rs` (~936 lines) | BPF LSM exec rate limiter | Modified: attaches to container's cgroup (discovered via `/proc/PID/cgroup`) instead of self-created cgroup |
| `sandbox/fanotify.rs` (~851 lines) | Behavioral monitoring | Minor: monitors same upper layer path |
| `sandbox/overlay.rs` (~661 lines) | OverlayFS upper layer management and mount | Modified: creates upper layer directory and performs `mount -t overlay` to produce merged dir; puzzled still owns the OverlayFS mount (podman only bind-mounts the resulting `merged_dir` into the container) |
| `wal.rs` (~1,213 lines) | Write-ahead log for crash-safe commit | None |
| `diff.rs` (~826 lines) | OverlayFS upper layer diff engine | None |
| `conflict.rs` (~874 lines) | Merge conflict detection | None |
| `budget.rs` (~827 lines) | Resource budget tracking | None |
| `error.rs` (~385 lines) | Error types | None |
| `audit.rs` (~793 lines) | Linux Audit event generation | None |
| `profile.rs` (~452 lines) | Agent profile loading and validation | None |
| `commit.rs` (~835 lines) | Commit orchestration logic | None |
| `main.rs` (~267 lines) | Daemon entry point, tokio runtime setup | None |
| `lib.rs` (~22 lines) | Crate re-exports | None |

**Note:** The `puzzle-proxy` crate (`crates/puzzle-proxy/`, ~4,100 lines across 4 modules: `lib.rs`, `handler.rs`, `replay.rs`, `tls.rs`) provides an HTTP proxy for application-layer network gating (domain allow/deny lists, write-operation journaling for replay at commit). This crate is **unchanged** by the architecture pivot — it runs in-process within puzzled and operates at L7, independent of how the container's L3/L4 network is configured. In the podman-native architecture, the container's `http_proxy`/`https_proxy` environment variables point to puzzled's proxy listener, same as in the current architecture.

### 7.3 D-Bus Interface Design

The D-Bus API is split into three interfaces for cleaner separation of concerns. The split enables Cockpit plugins to subscribe only to relevant interfaces — an audit viewer does not need branch lifecycle signals. All three interfaces are served on the same object path (`/org/lobstertrap/PuzzlePod1`) on either the system bus (root mode) or session bus (rootless mode), following systemd's `systemctl` / `systemctl --user` pattern.

| Mode | Bus | Object Path | When |
|---|---|---|---|
| System (`puzzled`) | System bus | `/org/lobstertrap/PuzzlePod1` | Root or system-managed, multi-user |
| User (`puzzled --user`) | Session bus | `/org/lobstertrap/PuzzlePod1` | Rootless, single-user, developer desktop |

#### 7.3.1 Interface: org.lobstertrap.PuzzlePod1.Manager

Branch lifecycle, governance operations, and container attachment. Contains the 16 existing methods (implemented in `crates/puzzled/src/dbus.rs`), the 4 Podman-native methods proposed by this PRD (`GenerateSeccompProfile`, `GenerateLandlockRules`, `AttachGovernance`, `TriggerGovernance`), totaling 20. Phase 8 proposes 4 additional long-running agent methods (`CommitPartial`, `CheckpointBranch`, `RestoreBranch`, `RequestPermission`) for 24 total on Manager.

```xml
<node>
  <interface name="org.lobstertrap.PuzzlePod1.Manager">
    <!-- Existing methods (15) — signatures match dbus/org.lobstertrap.PuzzlePod1.Manager.xml -->
    <method name="CreateBranch">
      <arg name="profile" type="s" direction="in"/>
      <arg name="base_path" type="s" direction="in"/>
      <arg name="command_json" type="s" direction="in"/>
      <arg name="branch_id" type="s" direction="out"/>
    </method>
    <method name="CommitBranch">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="result_json" type="s" direction="out"/>
    </method>
    <method name="RollbackBranch">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="reason" type="s" direction="in"/>
      <arg name="success" type="b" direction="out"/>
    </method>
    <method name="InspectBranch">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="info_json" type="s" direction="out"/>
    </method>
    <method name="DiffBranch">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="diff_json" type="s" direction="out"/>
    </method>
    <method name="ListBranches">
      <arg name="branches_json" type="s" direction="out"/>
    </method>
    <method name="ListAgents">
      <arg name="agents_json" type="s" direction="out"/>
    </method>
    <method name="KillAgent">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="success" type="b" direction="out"/>
    </method>
    <method name="ApproveBranch">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="result_json" type="s" direction="out"/>
    </method>
    <method name="RejectBranch">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="reason" type="s" direction="in"/>
      <arg name="success" type="b" direction="out"/>
    </method>
    <method name="UnregisterAgent">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="success" type="b" direction="out"/>
    </method>
    <method name="AgentInfo">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="agent_info_json" type="s" direction="out"/>
    </method>
    <method name="ReloadPolicy">
      <arg name="success" type="b" direction="out"/>
      <arg name="detail_message" type="s" direction="out"/>
    </method>
    <method name="QueryAuditEvents">
      <arg name="filter_json" type="s" direction="in"/>
      <arg name="events_json" type="s" direction="out"/>
    </method>
    <method name="ExportAuditEvents">
      <arg name="format" type="s" direction="in"/>
      <arg name="export_data" type="s" direction="out"/>
    </method>

    <!-- Podman-native methods (4) — container governance attachment -->
    <method name="GenerateSeccompProfile">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="profile_path" type="s" direction="out"/>
    </method>
    <method name="GenerateLandlockRules">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="rules_path" type="s" direction="out"/>
    </method>
    <method name="AttachGovernance">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="container_pid" type="u" direction="in"/>
      <arg name="container_id" type="s" direction="in"/>
      <arg name="success" type="b" direction="out"/>
    </method>
    <method name="TriggerGovernance">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="result_json" type="s" direction="out"/>
    </method>

    <!-- Long-running agent support (4) — incremental commit, checkpoint, permissions -->
    <method name="CommitPartial">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="path_prefixes" type="as" direction="in"/>
      <arg name="result_json" type="s" direction="out"/>
    </method>
    <method name="CheckpointBranch">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="checkpoint_id" type="s" direction="out"/>
    </method>
    <method name="RestoreBranch">
      <arg name="checkpoint_id" type="s" direction="in"/>
      <arg name="branch_id" type="s" direction="out"/>
    </method>
    <method name="RequestPermission">
      <arg name="branch_id" type="s" direction="in"/>
      <arg name="resource_type" type="s" direction="in"/>
      <arg name="resource_path" type="s" direction="in"/>
      <arg name="justification" type="s" direction="in"/>
      <arg name="approved" type="b" direction="out"/>
    </method>

    <!-- Signals: 8 existing (implemented) + 2 proposed (Phase 8) = 10 -->
    <!-- Existing signals (8) — signatures match dbus/org.lobstertrap.PuzzlePod1.Manager.xml -->
    <signal name="BranchCreated">
      <arg name="branch_id" type="s"/>
      <arg name="profile" type="s"/>
    </signal>
    <signal name="BranchCommitted">
      <arg name="branch_id" type="s"/>
      <arg name="changeset_hash" type="s"/>
      <arg name="profile" type="s"/>
    </signal>
    <signal name="BranchRolledBack">
      <arg name="branch_id" type="s"/>
      <arg name="reason" type="s"/>
    </signal>
    <signal name="PolicyViolation">
      <arg name="branch_id" type="s"/>
      <arg name="violations_json" type="s"/>
      <arg name="changeset_hash" type="s"/>
      <arg name="reason" type="s"/>
      <arg name="profile" type="s"/>
    </signal>
    <signal name="BehavioralTrigger">
      <arg name="branch_id" type="s"/>
      <arg name="trigger_json" type="s"/>
    </signal>
    <signal name="AgentTimeout">
      <arg name="branch_id" type="s"/>
      <arg name="timeout_duration_secs" type="t"/>
    </signal>
    <signal name="GovernanceReviewPending">
      <arg name="branch_id" type="s"/>
      <arg name="diff_summary" type="s"/>
    </signal>
    <signal name="BranchEvent">
      <arg name="branch_id" type="s"/>
      <arg name="event_type" type="s"/>
      <arg name="details_json" type="s"/>
    </signal>
    <!-- Proposed signals (Phase 8) — for long-running agent support -->
    <signal name="PermissionRequested">
      <arg name="branch_id" type="s"/>
      <arg name="resource_type" type="s"/>
      <arg name="resource_path" type="s"/>
      <arg name="justification" type="s"/>
    </signal>
    <signal name="CommitRejected">
      <arg name="branch_id" type="s"/>
      <arg name="violations" type="as"/>
    </signal>

    <!-- Properties (for Cockpit status bar / dashboard) -->
    <property name="ActiveBranches" type="u" access="read"/>
    <property name="TotalCommitted" type="t" access="read"/>
    <property name="TotalRolledBack" type="t" access="read"/>
    <property name="TotalRejected" type="t" access="read"/>
    <property name="DaemonVersion" type="s" access="read"/>
    <property name="Uptime" type="t" access="read"/>
  </interface>
</node>
```

**BranchState transitions for proposed Phase 8 operations:**

| Operation | State Transition | Notes |
|---|---|---|
| `CommitPartial` | `Active → Frozen → (partial commit) → Active` | Branch stays Active after partial commit; only selected path prefixes are committed |
| `CheckpointBranch` | No state change | Snapshot is metadata (upper layer tarball); branch continues in current state |
| `RestoreBranch` | Creates new branch in `Active` state | New branch created from checkpoint; original branch unaffected |
| `RequestPermission` | No state change | Emits `PermissionRequested` signal; blocks until `ApproveBranch`/`RejectBranch` response |

**Profile field usage in proposed Podman-native methods:**

| Method | Profile Fields Used |
|---|---|
| `GenerateSeccompProfile` | `exec_allowlist` (SCMP_ACT_NOTIFY), `exec_denylist` (SCMP_ACT_ERRNO), `allow_exec_overlay` (overlay exec policy), `enforcement.require_seccomp` |
| `GenerateLandlockRules` | `filesystem.read_allowlist`, `filesystem.write_allowlist`, `filesystem.denylist`, `allow_symlinks` (H10, controls `LANDLOCK_ACCESS_FS_REFER`), `enforcement.require_landlock` |

#### 7.3.2 Interface: org.lobstertrap.PuzzlePod1.Audit

Separated so a Cockpit audit plugin can subscribe without Manager lifecycle noise.

```xml
<node>
  <interface name="org.lobstertrap.PuzzlePod1.Audit">
    <method name="QueryEvents">
      <arg name="filter_json" type="s" direction="in"/>
      <arg name="events_json" type="s" direction="out"/>
    </method>
    <method name="ExportEvents">
      <arg name="format" type="s" direction="in"/>
      <arg name="filter_json" type="s" direction="in"/>
      <arg name="data" type="s" direction="out"/>
    </method>
    <method name="VerifyManifest">
      <arg name="manifest_hash" type="s" direction="in"/>
      <arg name="valid" type="b" direction="out"/>
      <arg name="details_json" type="s" direction="out"/>
    </method>
    <method name="GetMetrics">
      <arg name="metrics_text" type="s" direction="out"/>
    </method>
  </interface>
</node>
```

#### 7.3.3 Interface: org.lobstertrap.PuzzlePod1.Policy

Policy management and profile operations.

```xml
<node>
  <interface name="org.lobstertrap.PuzzlePod1.Policy">
    <method name="Reload">
      <arg name="success" type="b" direction="out"/>
      <arg name="errors" type="as" direction="out"/>
    </method>
    <method name="Test">
      <arg name="policy_name" type="s" direction="in"/>
      <arg name="input_json" type="s" direction="in"/>
      <arg name="result_json" type="s" direction="out"/>
    </method>
    <method name="ListProfiles">
      <arg name="profiles_json" type="s" direction="out"/>
    </method>
    <method name="GetProfile">
      <arg name="name" type="s" direction="in"/>
      <arg name="profile_yaml" type="s" direction="out"/>
    </method>
    <method name="ValidateProfile">
      <arg name="profile_yaml" type="s" direction="in"/>
      <arg name="valid" type="b" direction="out"/>
      <arg name="errors" type="as" direction="out"/>
    </method>
    <method name="SuggestProfile">
      <arg name="agent_type" type="s" direction="in"/>
      <arg name="audit_days" type="u" direction="in"/>
      <arg name="suggested_yaml" type="s" direction="out"/>
    </method>
  </interface>
</node>
```

#### 7.3.4 New Method Specifications

**CommitPartial (OQ4 — Incremental Commits)**

Resolves OQ4 from the Core PRD. Enables long-running agents (Devin, Claude Code extended sessions) to commit work-in-progress without terminating.

```
CommitPartial(branch_id, path_prefixes) -> CommitResult

Flow:
  1. Freeze the cgroup (cgroup.freeze)
  2. Diff only files matching the specified path prefixes from the upper layer
  3. Evaluate OPA/Rego governance on the subset
  4. If approved: merge those files to base via WAL, remove from upper layer
  5. Thaw the cgroup — agent continues working on remaining files

Constraint: The agent must not hold open file descriptors to files being
partially committed. puzzled checks /proc/<pid>/fd before proceeding.
```

**CheckpointBranch / RestoreBranch (Long-Running Agent Support)**

For infrastructure agents (Devin-class) running for days:

```
CheckpointBranch(branch_id) -> checkpoint_id

  Snapshots the current branch state (upper layer directory, metadata,
  WAL state, behavioral counters) to a checkpoint directory.
  The branch continues operating — this is non-destructive.

RestoreBranch(checkpoint_id) -> branch_id

  Creates a new branch from a checkpoint. The agent process is not
  restored — only the filesystem state. The caller must start a new
  container with the restored branch's merged_dir.
```

**RequestPermission (Agent-Initiated Permission Requests)**

When an agent hits a Landlock denial or seccomp block, this provides a structured channel for requesting access instead of silent `-EACCES`:

```
RequestPermission(branch_id, resource_type, resource_path, justification) -> approved

  1. puzzled emits PermissionRequested signal (consumed by Cockpit/IDE)
  2. Human approves/denies via Cockpit plugin, IDE extension, or puzzlectl
  3. If approved: puzzled adds a session-scoped exception
     (cannot weaken Landlock — but can extend seccomp USER_NOTIF whitelist)
  4. Returns approval result to the agent
```

**SuggestProfile (Profile Auto-Generation)**

Addresses the cold-start adoption problem:

```
SuggestProfile(agent_type, audit_days) -> suggested_yaml

  1. Query AuditStore for N days of audit data for the given agent_type
  2. Extract: files accessed (read/write), executables run, network domains,
     peak resource usage
  3. Generate a profile YAML that would have allowed those operations with
     minimal additional scope
  4. Return the YAML for admin review
```

#### 7.3.5 Migration from Single-Interface to Split Interfaces

The current codebase implements all 16 methods on a single `org.lobstertrap.PuzzlePod1.Manager` interface. The proposed split into Manager, Audit, and Policy interfaces requires a migration path:

| Current (Manager) | New Interface | New Method Name | Change Type |
|---|---|---|---|
| `QueryAuditEvents` | Audit | `QueryEvents` | Rename (breaking) |
| `ExportAuditEvents` | Audit | `ExportEvents` | Rename (breaking) |
| `ReloadPolicy` | Policy | `Reload` | Move + rename (breaking) |

**Migration strategy:**
- **Phase 8a:** Add new interfaces (`Audit`, `Policy`) with new method names. Keep deprecated aliases on Manager that forward to the new interfaces. Emit deprecation warnings in puzzled logs when aliases are called.
- **Phase 8b:** Remove deprecated aliases from Manager after one release cycle.

Note: `SuggestProfile` is proposed only on the `Policy` interface (no Manager duplicate), since it is new functionality with no existing callers.

### 7.4 seccomp Notification Socket Listener

puzzled runs a persistent listener on a well-known Unix socket:

```rust
// crates/puzzled/src/seccomp_listener.rs

/// Listen for seccomp notification file descriptors from crun.
///
/// crun's SCMP_ACT_NOTIFY support sends the notification fd to a
/// Unix socket specified in the seccomp profile's `listenerPath` field.
/// puzzled listens on this socket and dispatches the fd to the
/// per-branch seccomp handler (existing code in sandbox/seccomp/).
pub async fn serve_seccomp_listener(
    socket_path: PathBuf,      // /run/puzzled/seccomp-notify.sock
    branch_manager: Arc<BranchManager>,
) -> Result<()> {
    let listener = tokio::net::UnixListener::bind(&socket_path)?;

    loop {
        let (stream, _) = listener.accept().await?;

        // Receive the seccomp notification fd via SCM_RIGHTS
        let notif_fd = receive_fd_via_scm_rights(&stream)?;

        // Look up which branch this fd belongs to.
        // crun sends the listenerMetadata (from the seccomp profile JSON)
        // alongside the fd. We parse the branch_id from it.
        let metadata = read_listener_metadata(&stream)?;
        let branch_id = metadata.branch_id;

        // Register the fd with the existing per-branch seccomp handler
        branch_manager.register_seccomp_notif(branch_id, notif_fd)?;
    }
}
```

This replaces the current code path where puzzled creates the seccomp filter itself during `clone3()` and obtains the notification fd directly.

---

## 8. seccomp USER_NOTIF Integration via crun

### 8.1 How crun's seccomp Notification Works

crun (the OCI runtime used by Podman on Fedora/RHEL) supports `SCMP_ACT_NOTIFY` actions in OCI seccomp profiles. When a seccomp profile contains `listenerPath`, crun:

1. Creates the seccomp filter with `SECCOMP_RET_USER_NOTIF` for specified syscalls
2. Obtains the notification fd from `seccomp(SECCOMP_SET_MODE_FILTER)`
3. Opens a Unix socket at `listenerPath`
4. Sends the notification fd to the listening daemon via `SCM_RIGHTS`

This is an existing, upstream crun feature. No crun code changes are required.

### 8.2 Generated Seccomp Profile

puzzled generates an OCI-format seccomp profile per branch:

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "listenerPath": "/run/puzzled/seccomp-notify.sock",
  "listenerMetadata": "{\"branch_id\":\"abc-123\"}",
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_AARCH64"
  ],
  "syscalls": [
    {
      "names": ["execve", "execveat"],
      "action": "SCMP_ACT_NOTIFY",
      "comment": "SC1: Daemon-mediated exec gating via USER_NOTIF"
    },
    {
      "names": ["connect"],
      "action": "SCMP_ACT_NOTIFY",
      "comment": "SC2: Daemon-mediated network connection gating"
    },
    {
      "names": ["bind"],
      "action": "SCMP_ACT_NOTIFY",
      "comment": "SC3: Daemon-mediated bind gating (prevent listening)"
    },
    {
      "names": ["clone", "clone3"],
      "action": "SCMP_ACT_NOTIFY",
      "comment": "SC2: Conditionally included when BPF clone guard is not active (e.g., rootless mode). Lets puzzled inspect clone flags and deny namespace escape while allowing thread creation (CLONE_VM|CLONE_FS). Omitted when BPF LSM clone guard is active."
    },
    {
      "names": [
        "ptrace", "process_vm_readv", "process_vm_writev",
        "mount", "umount2", "pivot_root",
        "unshare", "setns",
        "init_module", "finit_module", "delete_module",
        "reboot", "swapon", "swapoff",
        "kexec_load", "kexec_file_load",
        "acct", "settimeofday", "clock_settime",
        "ioperm", "iopl",
        "open_by_handle_at", "name_to_handle_at",
        "personality",
        "userfaultfd",
        "keyctl", "add_key", "request_key",
        "bpf",
        "move_mount", "open_tree", "fsopen", "fspick", "fsconfig", "fsmount",
        "mount_setattr",
        "perf_event_open",
        "lookup_dcookie",
        "io_uring_setup", "io_uring_enter", "io_uring_register",
        "kcmp", "syslog",
        "memfd_create", "chroot",
        "shmget", "shmat", "shmctl", "shmdt",
        "semget", "semop", "semctl", "semtimedop",
        "msgget", "msgsnd", "msgrcv", "msgctl"
      ],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1,
      "comment": "H1-H7: Static deny for 57 escape-vector syscalls. Matches deny_syscalls[] in sandbox/seccomp/filter.rs."
    },
    {
      "names": ["socket"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1,
      "args": [
        { "index": 1, "value": 3, "valuetwo": 15, "op": "SCMP_CMP_MASKED_EQ" }
      ],
      "comment": "A1: Block SOCK_RAW (type & 0x0F == 3). Separate rule blocks SOCK_PACKET (type & 0x0F == 10)."
    },
    {
      "names": ["socket"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1,
      "args": [
        { "index": 1, "value": 10, "valuetwo": 15, "op": "SCMP_CMP_MASKED_EQ" }
      ],
      "comment": "A1: Block SOCK_PACKET (type & 0x0F == 10). Raw L2 socket access."
    },
    {
      "names": [
        "landlock_create_ruleset",
        "landlock_add_rule",
        "landlock_restrict_self"
      ],
      "action": "SCMP_ACT_ALLOW",
      "comment": "H8: Landlock syscalls use SCMP_ACT_ALLOW (not NOTIFY or ERRNO) because: (1) the puzzle-init shim must call landlock_restrict_self() before exec'ing the user command, and crun loads the seccomp filter before the shim runs; (2) Landlock is self-ratcheting — once applied with PR_SET_NO_NEW_PRIVS (which is irrevocable and inherited across fork/exec), the process can only create additional Landlock domains that further restrict access, never remove existing restrictions; (3) using ALLOW eliminates a race condition where the shim's Landlock notifications could arrive at puzzled before the OCI hook registers the container PID, which would leave puzzled unable to determine whether to allow or deny the call. An agent that calls landlock_restrict_self() after the shim has already applied rules can only further restrict itself — this is not a security concern."
    }
  ]
}
```

### 8.3 Fallback: Static-Only Mode

For deployments where seccomp USER_NOTIF is not desired (e.g., older crun versions, performance-sensitive workloads), the `--no-seccomp-notif` flag generates a profile without `SCMP_ACT_NOTIFY` — only the static deny list. In this mode:
- `landlock_*` syscalls remain `SCMP_ACT_ALLOW` (same as the default profile — Landlock is self-ratcheting, so ALLOW is safe in all modes; see §8.2 comment H8).
- `clone`/`clone3` entries are removed (they are only present when both USER_NOTIF is active and BPF clone guard is inactive). Without USER_NOTIF, namespace escape via clone flags must be prevented by BPF LSM alone or by running in a user namespace (rootless mode) where namespace creation is already restricted. **Note on rootless mode:** since BPF LSM is also unavailable rootless (requires `CAP_BPF`, see §10.1), the rootless security model relies on the fact that Podman rootless containers run inside a user namespace, which prevents the unprivileged process from creating new PID/mount/network namespaces that could escape the container — the kernel denies `clone(CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWNET)` from within a non-initial user namespace unless the process has `CAP_SYS_ADMIN` within that namespace, which Podman drops. This is the same containment model used by all rootless Podman containers.

Containment is still strong (Landlock + static seccomp + BPF LSM + namespaces + cgroups), but per-call execve/connect decisions are not available.

```bash
puzzle-podman run --profile=standard --no-seccomp-notif alpine sh
```

### 8.3.1 Security Mode Decision Matrix

The interaction between three deployment modes (full, static-only, rootless) affects which enforcement primitives are active. This matrix summarizes the security posture for each combination:

| Primitive | Full (root, USER_NOTIF) | Static-Only (root, no USER_NOTIF) | Rootless (USER_NOTIF available) |
|---|---|---|---|
| **Landlock** | Active (shim, ALLOW-gated) | Active (shim, ALLOW-gated) | Active (shim, ALLOW-gated) |
| **seccomp static deny** (57 escape syscalls) | Active | Active | Active |
| **seccomp USER_NOTIF** (execve/connect/bind) | Active — per-call mediation | **Disabled** — no per-call gating | **Available** — crun supports USER_NOTIF rootless; enabled by default. Per-call exec/connect gating works fully. Disable with `--no-seccomp-notif` if latency-sensitive. |
| **BPF LSM** (exec rate limiting, clone guard) | Active | Active | **Disabled** (requires `CAP_BPF`) |
| **clone/clone3 namespace escape prevention** | seccomp USER_NOTIF inspects flags | BPF LSM clone guard | seccomp USER_NOTIF inspects flags (when enabled) + user namespace (kernel denies `CLONE_NEW*` without `CAP_SYS_ADMIN` in userns, which Podman drops) |
| **execve allowlist enforcement** | seccomp USER_NOTIF | BPF LSM exec guard only (no per-path gating) | seccomp USER_NOTIF (when enabled; disable with `--no-seccomp-notif` reduces to static deny only) |
| **Namespaces** (PID/mount/net/IPC/UTS) | Podman/crun | Podman/crun | Podman/crun (inside user namespace) |
| **cgroups v2** | Podman | Podman | Podman (delegated subtree) |
| **SELinux** | Active (`puzzlepod_t`) | Active (`puzzlepod_t`) | Active (`puzzlepod_t`) |
| **fanotify behavioral monitoring** | Full (`FAN_REPORT_FID`) | Full (`FAN_REPORT_FID`) | **Partial** (path-based only; mass deletion detection unavailable) |
| **OPA policy at commit** | Active | Active | Active |

**Recommendation:** Use *Full* mode for production data center deployments. Use *Static-Only* for performance-sensitive workloads where per-call latency matters but root is available. Use *Rootless* for developer workstations and environments where root is unavailable — the security model is narrower (no BPF LSM, partial fanotify) but still provides strong containment via Landlock + seccomp (including USER_NOTIF for per-call exec/connect gating) + user namespace isolation + OPA governance.

### 8.4 seccomp USER_NOTIF Comparison

| Property | Current Architecture | Podman-Native Architecture |
|---|---|---|
| Who creates the filter? | puzzled (via `seccomp(2)` before `execve` in child) | crun (via OCI seccomp profile) |
| How does puzzled get the fd? | Directly from `seccomp()` call (parent process) | Via Unix socket `SCM_RIGHTS` from crun |
| TOCTOU safety (SECCOMP_ADDFD) | Same | Same — fd resolution behavior is identical regardless of who loaded the filter |
| Latency per intercepted syscall | ~50-100 μs | ~50-100 μs (no difference — the kernel path is identical) |
| Filter loaded before user code? | Yes (loaded in child before `execve`) | Yes (crun loads filter before container init) |

---

## 9. Developer Experience

### 9.1 Workflow Comparison

**Current architecture (Linux only, root required):**

```bash
# Requires root, Linux only, no OCI images
sudo puzzlectl branch create --profile=standard --base=$PWD
sudo puzzlectl branch exec $BRANCH_ID -- python3 ./agent.py
# Must manually inspect and commit/rollback
sudo puzzlectl branch inspect $BRANCH_ID
sudo puzzlectl branch approve $BRANCH_ID
```

**Podman-native architecture (any OS, rootless):**

```bash
# Works rootless, on Mac/Windows, with OCI images
puzzle-podman run --profile=standard python:3.12 ./agent.py
# Interactive commit/rollback on exit (existing wrapper behavior)
# Or: puzzle-podman agent approve abc-123
```

### 9.2 Familiar Interface

Developers already know Podman. The `puzzle-podman` wrapper accepts all standard Podman flags:

```bash
# GPU workloads
puzzle-podman run --profile=standard --gpus all nvidia/cuda:12 ./ml-agent.py

# Custom volumes
puzzle-podman run --profile=standard -v ./data:/workspace/data python:3.12 ./agent.py

# Resource limits (passed to podman)
puzzle-podman run --profile=standard --memory=4g --cpus=2 myimage ./agent.py

# Interactive debugging
puzzle-podman run --profile=standard -it python:3.12 bash

# Network mode
puzzle-podman run --profile=standard --network=host myimage ./agent.py
```

### 9.3 Transparent Governance

From inside the container, the agent sees:

```
/workspace/          ← Branch overlay (OverlayFS merged dir)
$PUZZLEPOD_BRANCH_ID   ← Branch ID for SDK integration
$PUZZLEPOD_WORKSPACE    ← /workspace

# Landlock is active — access outside allowed paths returns EACCES
# seccomp USER_NOTIF — execve/connect calls are mediated by puzzled
# fanotify — file access patterns are monitored
# All of this is invisible to the agent process
```

---

## 10. Rootless and User-Instance Operation

### 10.1 Rootless Capability Matrix

| Kernel Primitive | Rootless? | Mechanism |
|---|---|---|
| Landlock | **Yes** | Unprivileged since kernel 5.13 (applied by puzzle-init shim inside container) |
| seccomp SCMP_ACT_NOTIFY | **Yes** | crun handles filter creation in rootless mode |
| User namespace | **Yes** | Podman rootless via `newuidmap`/`newgidmap` |
| fuse-overlayfs | **Yes** | Podman rootless storage driver |
| cgroups v2 (delegation) | **Yes** | systemd user session delegates cgroup subtree |
| BPF LSM | **No** | Requires `CAP_BPF` — degraded to static seccomp in rootless mode |
| fanotify | **Partial** | `FAN_REPORT_FID` requires `CAP_SYS_ADMIN`; path-based fanotify available unprivileged |

### 10.2 puzzled User Instance

```ini
# ~/.config/systemd/user/puzzled.service
[Unit]
Description=PuzzlePod Governance Daemon (user instance)
After=dbus.service

[Service]
Type=notify
ExecStart=/usr/bin/puzzled --config %h/.config/puzzled/puzzled.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
WatchdogSec=30

[Install]
WantedBy=default.target
```

User instance configuration:

```yaml
# ~/.config/puzzled/puzzled.conf
bus_type: session                              # D-Bus session bus (not system)
branch_root: ~/.local/share/puzzled/branches    # User-writable storage
runtime_dir: /run/user/1000/puzzled             # XDG_RUNTIME_DIR
profiles_dir: ~/.config/puzzled/profiles        # User profiles
policies_dir: ~/.config/puzzled/policies        # User policies
max_branches: 8                                # Reasonable for desktop
log_level: info
bpf_lsm:
  enable: false                                # Requires CAP_BPF — disabled rootless
```

### 10.3 Rootless Degradation

When running rootless, some features degrade gracefully:

| Feature | Root Mode | Rootless Mode | Security Impact |
|---|---|---|---|
| BPF LSM exec rate limiting | Active | **Disabled** | Exec rate not limited; static seccomp deny list still blocks escape vectors. Per-path `exec_allowlist` enforcement is still available via seccomp USER_NOTIF (enabled by default rootless). |
| fanotify (FAN_REPORT_FID) | Full behavioral monitoring | **Path-based only** | File event counting (mass deletion detection) unavailable; file access monitoring via `FAN_OPEN` still works. |
| OverlayFS | Kernel OverlayFS | **fuse-overlayfs** | puzzled invokes `fuse-overlayfs` as a subprocess to create branch mounts (rootless puzzled cannot call `mount -t overlay` on the host without `CAP_SYS_ADMIN`). Podman bind-mounts the FUSE-backed merged directory into the container. Writes flow through the bind mount, through the FUSE layer, to the upper directory on the underlying filesystem. ~15-20% I/O overhead vs ~5-10% for kernel OverlayFS; same CoW semantics. See §10.6 for details. |
| XFS project quotas | Per-branch storage limits | **Disk-based limits only** | No per-branch inode/storage quota; use `podman --storage-opt size=1G` instead. |
| Landlock | Full (kernel 5.13+) | **Full** | No degradation — Landlock is unprivileged. |
| seccomp USER_NOTIF | Full | **Available** | crun supports USER_NOTIF rootless; enabled by default. Per-call exec/connect gating works fully. Disable with `--no-seccomp-notif` if latency-sensitive (see §8.3.1). |
| OPA policy evaluation | Full | **Full** | No degradation. |
| Audit chain | Full | **Full** | HMAC chain writes to user-writable directory. |

**Note:** The current `CLAUDE.md` describes puzzled as "runs as root" and lists root-required operations (mount namespace setup, cgroup creation, BPF program loading). If this PRD is adopted, `CLAUDE.md` must be updated to document both root and rootless operating modes, including the degradation table above.

### 10.4 User-Mode Agent Slice

```ini
# ~/.config/systemd/user/puzzle.slice
[Unit]
Description=Agent Workload Slice (user)
Before=slices.target

[Slice]
MemoryMax=80%
CPUQuota=400%
TasksMax=1024
IOWeight=50
```

### 10.5 Rootless Stack Composition

Both Podman and puzzled run rootless, communicating via the session D-Bus:

```
systemd --user
  ├── podman (rootless)              -> containment
  ├── puzzled --user (rootless)       -> governance via session bus
  └── puzzled-mcp (optional)          -> MCP server, wraps D-Bus client
```

The rootless capability matrix and degradation behavior are covered in §10.1-10.3 above.

### 10.6 Rootless OverlayFS Branch Management (PQ6 — Resolved)

**Decision:** Rootless puzzled uses **fuse-overlayfs** as a subprocess for branch OverlayFS mounts. This resolves PQ6.

**Rationale:** A rootless puzzled process running on the host (outside any user namespace) cannot call `mount -t overlay` because kernel OverlayFS requires `CAP_SYS_ADMIN` (either real or within a user namespace). The three alternatives considered were:

1. **Kernel OverlayFS inside Podman's user namespace** — would require rearchitecting so the mount happens inside the container's namespace, conflicting with the bind-mount design (the mount must exist on the host before `podman run`). Rejected.
2. **Unprivileged `unshare(CLONE_NEWUSER)` + `mount()`** — the resulting mount would only be visible within the temporary user namespace, not on the host where Podman needs to bind-mount it. Rejected.
3. **fuse-overlayfs** — creates a FUSE-backed overlay mount visible in the host mount namespace (FUSE mounts by unprivileged users are permitted via `fusermount3`). This is the same approach Podman uses for its own container storage in rootless mode. Selected.

**Implementation:** `sandbox/overlay.rs` gains a rootless path that invokes `fuse-overlayfs` as a subprocess instead of calling `nix::mount::mount()`:

```rust
// Root mode: kernel OverlayFS
nix::mount::mount(Some("overlay"), &merged_path, Some("overlay"), ...)?;

// Rootless mode: fuse-overlayfs subprocess
Command::new("fuse-overlayfs")
    .arg("-o").arg(format!("lowerdir={},upperdir={},workdir={}", lower, upper, work))
    .arg(&merged_path)
    .status()?;
```

**Cleanup:** On branch rollback or commit completion, puzzled calls `fusermount3 -u $MERGED_PATH` to unmount the FUSE overlay before removing the branch directory.

**Dependency:** `fuse-overlayfs` is already a runtime dependency of rootless Podman and is installed by default on Fedora/RHEL. No additional packaging required.

### 10.7 Rootless UID Mapping at Commit

In rootless Podman with user namespaces, UIDs inside the container are mapped to host UIDs via `/etc/subuid`. Files written to the OverlayFS upper layer have **host-mapped UIDs**, not container UIDs. This affects the commit engine.

**UID mapping example:**

| Container UID | Host UID | Notes |
|---|---|---|
| 0 (root) | 1000 (host user) | Container root = host user's own UID |
| 1-65535 | 100000-165535 | Subordinate UID range from `/etc/subuid` |

**Behavior:**

- **Diff generation:** Works correctly — puzzled runs as the same host user (UID 1000) and can read all files in the upper layer regardless of mapped UIDs.
- **Commit to base filesystem:** Files written by container UID 0 are committed with host UID 1000 (the user's own UID), which is the expected behavior. Files written by other container UIDs (e.g., UID 33 for `www-data`) are committed with host UIDs in the subordinate range (e.g., 100032), which may not match what the user expects.

**Design decision:** The commit engine **preserves host-mapped UIDs** by default (no reverse mapping). This is the simplest and most predictable behavior:

- The common case (agent running as container root → host user UID) works correctly.
- The uncommon case (agent creating files as non-root container UIDs) preserves the mapping, which the user can adjust with `chown` after commit.
- Reverse UID mapping would require puzzled to store the container's `uid_map` (captured from `/proc/<pid>/uid_map` during the `createRuntime` hook) and apply it during commit — added complexity for a rare edge case.

**Future option:** If reverse UID mapping is needed, the `AttachGovernance` D-Bus method can capture the container's `uid_map` from `/proc/<pid>/uid_map` and store it as branch metadata. The commit engine can then apply `lchown()` with reverse-mapped UIDs during the WAL commit phase. This is deferred unless user feedback indicates it is needed.

---

## 11. Mac, Windows, and Remote Development

### 11.1 Architecture

```
┌────────────────────────────────────────┐
│  Developer Machine (Mac / Windows)      │
│                                        │
│  puzzle-podman run --profile=standard   │
│  python:3.12 ./agent.py                │
│       │                                │
│       │ detects podman machine          │
│       │                                │
│       ├──► podman run (remote)          │
│       │    (podman machine handles      │
│       │     transparent forwarding)     │
│       │                                │
│       └──► puzzlectl (via SSH proxy)     │
│            podman machine ssh --        │
│            puzzlectl branch create ...   │
│                                        │
└────────────┬───────────────────────────┘
             │ SSH + gvproxy
             ▼
┌────────────────────────────────────────┐
│  Podman Machine VM (Fedora CoreOS)     │
│  (runs on Apple Silicon or x86_64)     │
│                                        │
│  ┌──────────────┐  ┌────────────────┐  │
│  │ podman       │  │ puzzled         │  │
│  │ (container   │  │ (governance    │  │
│  │  runtime)    │  │  daemon)       │  │
│  └──────────────┘  └────────────────┘  │
│                                        │
│  Full kernel primitive support:        │
│  Landlock, seccomp, BPF LSM,          │
│  OverlayFS, namespaces, cgroups       │
│                                        │
└────────────────────────────────────────┘
```

### 11.2 Setup

```bash
# One-time setup (Mac)
brew install podman puzzle-podman   # or: dnf install on Fedora
podman machine init --cpus=4 --memory=8192 --disk-size=50
podman machine start

# Install puzzled in the VM
podman machine ssh -- sudo dnf install puzzlepod

# Verify
puzzle-podman run --profile=standard alpine echo "governance works"
```

### 11.3 Transparent Proxying

The `puzzle-podman` wrapper detects `podman machine` and proxies puzzled calls:

```bash
# Detect if we're on a machine with podman machine
if command -v podman &>/dev/null && podman machine inspect &>/dev/null 2>&1; then
    # Proxy puzzlectl commands through the VM
    puzzlectl_cmd() {
        podman machine ssh -- puzzlectl "$@"
    }
else
    # Direct local execution
    puzzlectl_cmd() {
        puzzlectl "$@"
    }
fi
```

The developer's workflow is identical on Mac, Windows, and Linux. The governance happens inside the VM where all kernel primitives are available.

---

## 12. IDE and Dev Container Integration

### 12.1 VS Code Dev Containers

```jsonc
// .devcontainer/devcontainer.json
{
  "name": "Governed Development",
  "image": "python:3.12",

  // Option A: Use puzzle-podman as container runtime
  // (puzzle-podman passes non-run commands through to podman unmodified)
  "dockerPath": "puzzle-podman",
  "runArgs": ["--profile=standard"],

  // Option B: Use standard podman with annotation (if OCI hook is installed)
  // "runArgs": [
  //   "--annotation", "run.oci.handler=puzzlepod",
  //   "--label", "org.lobstertrap.puzzlepod.profile=standard"
  // ],

  "customizations": {
    "vscode": {
      "extensions": [
        "lobstertrap.puzzlepod"  // Status bar: branch state, trust score, diff count
      ],
      "settings": {
        "puzzlepod.autoCommitOnSave": false,
        "puzzlepod.showDiffOnClose": true
      }
    }
  }
}
```

### 12.2 JetBrains Gateway / Remote Development

JetBrains Gateway supports Podman as a remote interpreter. The `puzzle-podman` wrapper works as a drop-in:

```
Settings → Build → Docker → Docker executable: /usr/local/bin/puzzle-podman
```

### 12.3 GitHub Codespaces / Gitpod

For cloud-hosted development environments, the governance daemon runs as a sidecar:

```dockerfile
# .devcontainer/Dockerfile
FROM python:3.12

# Install puzzled (runs as user service inside the container)
RUN dnf install -y puzzlepod

# Start puzzled as a background service
COPY .devcontainer/puzzled-user.conf /home/vscode/.config/puzzled/puzzled.conf
```

---

## 13. Quadlet and Production Deployment

### 13.1 Quadlet Integration

Quadlet is Podman's systemd-native container deployment mechanism. Governed containers use standard Quadlet directives with annotations:

```ini
# /etc/containers/systemd/code-review-agent.container
#
# NOTE: The branch and seccomp profile must be pre-created via puzzlectl before
# the container starts. The ExecStartPre commands below handle this:
#   1. `puzzlectl branch ensure` — idempotent create-if-not-exists
#   2. `puzzlectl branch seccomp-profile` — generates the seccomp profile JSON
# The merged_dir and seccomp profile path are at well-known locations under
# /var/lib/puzzled/branches/<name>/.

[Unit]
Description=Code Review Agent (governed)
After=puzzled.service

[Container]
Image=registry.internal/agents/code-review:latest
Entrypoint=/puzzle-init
Exec=./review-agent.py --repo=/workspace/project
Annotation=run.oci.handler=puzzlepod
Annotation=org.lobstertrap.puzzlepod.branch=code-review
Label=org.lobstertrap.puzzlepod.profile=standard
SecurityOpt=seccomp=/var/lib/puzzled/branches/code-review/seccomp.json
Mount=type=bind,src=/var/lib/puzzled/branches/code-review/merged,dst=/workspace
Mount=type=bind,src=/usr/libexec/puzzle-init,dst=/puzzle-init,ro
Mount=type=bind,src=/var/lib/puzzled/branches/code-review/landlock.json,dst=/run/puzzlepod/landlock.json,ro
SecurityLabelType=puzzlepod_t
Environment=PUZZLEPOD_BRANCH_ID=code-review
Environment=PUZZLEPOD_WORKSPACE=/workspace

[Service]
Restart=on-failure
ExecStartPre=/usr/bin/puzzlectl branch ensure code-review --profile=standard
ExecStartPre=/usr/bin/puzzlectl branch seccomp-profile code-review --output=path
ExecStartPre=/usr/bin/puzzlectl branch landlock-rules code-review --output=path

[Install]
WantedBy=multi-user.target
```

No custom Quadlet directives are needed. Standard `Annotation=`, `Label=`, `SecurityOpt=`, and `Mount=` directives carry the governance metadata. The first `ExecStartPre` ensures the branch exists before the container starts (idempotent — no-op if branch already exists). The second generates the seccomp profile JSON, and the third generates the Landlock rules JSON, both at well-known paths under the branch directory. All three are idempotent and safe to re-run on service restart.

**New puzzlectl subcommands required:** Both the Quadlet example and the `puzzle-podman` wrapper (Section 5.2) use `puzzlectl branch ensure`, `puzzlectl branch seccomp-profile`, and `puzzlectl branch landlock-rules`. These are **new subcommands** that must be added to `puzzlectl` as thin CLI wrappers around the corresponding new D-Bus methods (`GenerateSeccompProfile`, `GenerateLandlockRules`). `branch ensure` is an idempotent create-if-not-exists operation. `seccomp-profile` and `landlock-rules` are idempotent generation commands that write to well-known paths under the branch directory. Implementation cost is minimal (~50-100 lines of clap subcommand definitions in `crates/puzzlectl/src/main.rs`).

### 13.2 systemd Service Dependencies

```ini
# /etc/systemd/system/puzzled.service (existing, unchanged)
[Unit]
Description=PuzzlePod Governance Daemon
Before=code-review-agent.service  # Start before governed containers

[Service]
Type=notify
ExecStart=/usr/bin/puzzled
ExecReload=/bin/kill -HUP $MAINPID
WatchdogSec=30
Restart=on-failure
```

Governed containers declare `After=puzzled.service` to ensure the governance daemon is running before any governed container starts. If puzzled is not running, the OCI hook fails and the container does not start (fail-closed).

### 13.3 Ansible Integration

The existing Ansible collection (`ansible/`) works unchanged. The `puzzlepod` role installs the OCI hook config alongside the other components:

```yaml
# ansible/roles/puzzlepod-core/tasks/main.yml (additions)
- name: Install OCI hook configuration
  copy:
    src: puzzle-hook.json
    dest: /usr/share/containers/oci/hooks.d/puzzlepod.json
    mode: '0644'

- name: Install OCI hook binary
  copy:
    src: puzzle-hook
    dest: /usr/libexec/puzzle-hook
    mode: '0755'

- name: Install Landlock shim binary
  copy:
    src: puzzle-init
    dest: /usr/libexec/puzzle-init
    mode: '0755'
```

### 13.4 RPM Packaging

The architecture pivot introduces two new binaries and an OCI hook config that require packaging. The existing RPM spec (`puzzlepod.spec`) is extended:

| New RPM Subpackage | Contents | Dependencies |
|---|---|---|
| `puzzle-hook` | `/usr/libexec/puzzle-hook`, `/usr/share/containers/oci/hooks.d/puzzlepod.json` | `puzzled` (D-Bus client) |
| `puzzle-init` | `/usr/libexec/puzzle-init` (static binary, no dependencies) | None |

These are added to the existing `puzzlepod` meta-package. The `puzzlepod-minimal` meta-package (for edge) should include both. No changes to `puzzled`, `puzzlectl`, `puzzled-selinux`, `puzzled-profiles`, or `puzzled-policies` packages.

New runtime dependency for the `puzzlepod` meta-package: `Requires: podman >= 5.0 crun >= 1.14`.

---

## 14. Security Model

### 14.1 Defense-in-Depth Layers

The podman-native architecture preserves all defense-in-depth layers from the original design:

| Layer | Mechanism | Configured By | Enforced By | Survives puzzled Crash? |
|---|---|---|---|---|
| 0 | Landlock | puzzle-init shim | Kernel LSM | **Yes** — attached to process |
| 1 | seccomp static deny | crun (OCI profile) | Kernel | **Yes** — irrevocable filter |
| 2 | seccomp USER_NOTIF | crun + puzzled | Kernel + puzzled | Partially — filter persists, but if puzzled crashes the notification fd is closed and USER_NOTIF-gated syscalls return `ENOSYS`. Container must be restarted to restore mediation. See §14.4. |
| 3 | PID namespace | podman/crun | Kernel | **Yes** |
| 4 | Mount namespace | podman/crun | Kernel | **Yes** |
| 5 | Network namespace | podman/crun | Kernel | **Yes** |
| 6 | cgroups v2 | podman | Kernel | **Yes** |
| 7 | SELinux (`puzzlepod_t`) | podman (`--security-opt label=type:puzzlepod_t`) | Kernel | **Yes** |
| 8 | BPF LSM | puzzled (via hook) | Kernel | **Yes** — attached to cgroup |
| 9 | User namespace | podman (rootless) | Kernel | **Yes** |

### 14.2 Fail-Closed Guarantees

| Failure | Behavior |
|---|---|
| puzzled not running when container starts | OCI hook fails → crun aborts container start → container never runs ungoverned |
| puzzled crashes while container is running | Landlock remains enforced (kernel). seccomp static deny remains enforced (kernel). seccomp USER_NOTIF notification fd is closed → gated syscalls return `ENOSYS` (see §14.4). BPF LSM remains attached to cgroup (kernel). Container is isolated; USER_NOTIF-gated actions (execve, connect) fail until container restart. |
| OCI hook binary missing | crun logs error and aborts container start → fail-closed |
| Seccomp notification socket not available | crun fails to connect to `listenerPath` socket → container creation aborts entirely → fail-closed (crun does not downgrade to SCMP_ACT_ERRNO; it hard-fails) |
| Landlock shim fails | Container entrypoint fails → container exits → fail-closed |

### 14.3 Threat Model Preservation

Every attack scenario from the Core PRD (Section 4) is addressed identically:

| Scenario | Core PRD Defense | Podman-Native Defense | Difference |
|---|---|---|---|
| Lateral file access | Landlock read_deny | Landlock read_deny (via shim) | None — same kernel enforcement |
| Destructive hallucination | OverlayFS branch | OverlayFS branch (via bind mount) | None — same CoW semantics |
| Prompt injection exec | seccomp USER_NOTIF on execve | seccomp USER_NOTIF on execve (via crun) | Same — fd source differs but kernel path is identical |
| Credential exfiltration | Landlock + network gating | Landlock + network gating | None |
| Resource exhaustion | cgroups v2 | cgroups v2 (via podman) | None — Podman's cgroup implementation is more mature |
| Agent persistence | Landlock + OPA policy | Landlock + OPA policy | None |
| Namespace escape | PID/mount/net namespace | PID/mount/net namespace (via podman) | None — Podman's namespace implementation has years more hardening |

### 14.4 seccomp USER_NOTIF and puzzled Crash

If puzzled crashes while a container is running with seccomp USER_NOTIF:

1. The seccomp filter remains loaded in the kernel (irrevocable)
2. Any `execve` or `connect` syscall from the container will send a notification to the notification fd
3. Since puzzled's process held the notification fd and has exited, the kernel closes the fd. The kernel then returns `ENOSYS` to any pending or future `SECCOMP_RET_USER_NOTIF` syscalls from the container (see `seccomp(2)` — when the notification fd is closed, blocked syscalls fail with `ENOSYS`).
4. The container process cannot execute new binaries (`execve` → `ENOSYS`) or make network connections (`connect` → `ENOSYS`). It can continue running existing code (pure computation, file I/O within Landlock scope).
5. systemd restarts puzzled (`Restart=on-failure`)
6. **The notification fd cannot be recovered** — it was a one-time transfer from crun via `SCM_RIGHTS` at container creation, and crun has already exited. The affected container must be terminated and restarted to restore USER_NOTIF mediation. puzzled's cleanup thread detects orphaned branches (branches with no live notification fd) on restart and marks them for operator review or automatic rollback.

This is **fail-safe**: the container cannot execute new binaries or make network connections while puzzled is down (static seccomp deny + Landlock remain kernel-enforced regardless). The trade-off is that USER_NOTIF-gated syscalls fail rather than being mediated — the container must be restarted to restore dynamic governance.

### 14.5 Extended Threat Model

The following threats extend the Core PRD's threat model (T1-T7) with attack vectors identified through competitive landscape research, OWASP Agentic Top 10 analysis, and MCP security research:

| Threat ID | Name | Description | Mitigation |
|---|---|---|---|
| T8 | Indirect Access / Tool Chaining | Agents use allowed operations to achieve denied outcomes — e.g., `docker compose config` to extract `.env` secrets, chaining `grep` + `curl` to exfiltrate data within allowlist | OPA governance rules that detect suspicious operation sequences, not just individual operations. Content scanning at commit for credential patterns regardless of source file. |
| B1 | Memory/Context Poisoning (OWASP ASI06) | Adversaries persistently corrupt agent context files (`.context`, `.memory`, `*.embedding`). Unlike prompt injection (T2), poisoning persists across sessions — committed context files influence future agent behavior. | OPA rules that flag new/modified files matching agent memory patterns. Require human review for files that could influence future agent behavior. Branch agent memory separately from work output with different governance policies. |
| B2 | Rogue Agent Persistence via Allowed Mechanisms (OWASP ASI10) | Agents persist through workspace-allowed mechanisms: git hooks, Makefiles, CI configs, `.bashrc`, `package.json` scripts — all within the allowed write scope and passing governance checks. | Heuristic governance rules that flag "files that execute on trigger" (Makefiles, CI configs, git hooks, `package.json` scripts, `pyproject.toml` scripts). New OPA rule category: `no_execution_triggers`. Document as inherent limitation for workspace-level persistence. |
| B3 | Human-Agent Trust Exploitation (OWASP ASI09) | Agents actively manipulate human reviewers through confident assertions, fabricated rationales, authority bias exploitation, and social engineering in commit messages or PR descriptions. Distinct from approval fatigue (passive) — trust exploitation is active manipulation. | Governance gate presents raw diffs WITHOUT agent-generated descriptions or justifications. OPA policies evaluate changesets independently of agent-provided metadata. Reviewer training documentation on trust exploitation. |
| B4 | MCP Token Aggregation Risk | Compromised MCP server exposes all connected service tokens — a "keys to the kingdom" scenario. If puzzled intercepts MCP tool calls for governance, it becomes a high-value aggregation target. | puzzled-mcp does NOT store MCP tokens — it forwards authentication opaquely. Branch-scoped credentials, not user-level credentials. Token rotation and scope-limiting are part of the MCP integration design (see §24). |
| B6 | Agent-to-Agent Filesystem Timing Channels | Agents with overlapping read access to base filesystem paths can communicate through `stat()` timing differences, atime modifications, or file locking as signaling — even within separate branches. | Landlock ABI v6 `LANDLOCK_SCOPE_SIGNAL` mitigates signal-based communication. Filesystem timing channels are a known-hard problem (full mitigation requires physical isolation). Documented as residual risk. |
| B7 | Audit Trail Integrity Under Daemon Compromise | If puzzled is compromised, the attacker can forge audit records (including IMA signatures if the signing key is in daemon memory). Historical records remain valid, but the attacker can create false records during the compromise window. | IMA signing key rotation (90-day threshold). Write audit records to append-only external store (syslog with remote forwarding via audisp) as defense-in-depth. |

### 14.6 OWASP Agentic Top 10 (ASI01-ASI10) Mapping

| OWASP ID | Threat | PuzzlePod Mitigation | Gap |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | OPA governance reviews changeset intent | No runtime goal monitoring |
| ASI02 | Tool Misuse | seccomp USER_NOTIF exec allowlist | No tool-chaining detection (see T8) |
| ASI03 | Identity/Privilege Abuse | Landlock + empty capability bounding set + SELinux | Covered |
| ASI04 | Supply Chain Vulnerabilities | Governance content scanning + exec allowlist | No MCP supply chain protection (Phase 2-3) |
| ASI05 | Unexpected Code Execution | BPF LSM exec counting + seccomp static deny | Covered |
| ASI06 | Memory/Context Poisoning | Not fully addressed | New blindspot (B1 above) — OPA rules for context files recommended |
| ASI07 | Insecure Inter-Agent Communication | PID namespace + Landlock ABI v6 IPC scoping | Requires ABI v6 adoption (see §14.8) |
| ASI08 | Cascading Failures | cgroup isolation + branch-scoped OOM | Covered |
| ASI09 | Human-Agent Trust Exploitation | Partially — OPA evaluates independently of agent metadata | New blindspot (B3 above) |
| ASI10 | Rogue Agents | Branch rollback + audit trail | Workspace persistence gap (B2 above) |

### 14.7 CSA Agentic Trust Framework Mapping

The Cloud Security Alliance's Agentic Trust Framework (Feb 2026) defines four trust levels with explicit promotion criteria. PuzzlePod profiles map to this framework:

| CSA Level | PuzzlePod Profile | Promotion Criteria |
|---|---|---|
| Intern | `restricted` | Default for new agents |
| Junior | `standard` | N clean commits, zero governance rejections over M sessions |
| Senior | `privileged` | Extended track record, supervisor approval |
| Principal | Custom | Admin-designated, full access with monitoring |

This gives enterprises a compliance-ready trust model that maps to an emerging standard. Profile promotion can be automated via the `SuggestProfile` D-Bus method (§7.3.4), which analyzes audit data to recommend profile upgrades.

### 14.8 Landlock ABI v6/v7/v8 Evolution

The PRD references Landlock up to ABI v4 (kernel 6.7). Newer ABI versions provide capabilities directly relevant to agent containment:

| ABI Version | Kernel | New Capabilities | Impact on PuzzlePod |
|---|---|---|---|
| ABI v6 | 6.12 | `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` — prevents agents from connecting to abstract Unix sockets outside their domain. `LANDLOCK_SCOPE_SIGNAL` — prevents agents from sending signals to processes outside their domain. | Closes abstract socket escape vector (PRD §6.2.2). Closes cross-agent signaling attack. |
| ABI v7 | 6.15 | Audit framework integration — Landlock denials logged via Linux Audit by default. | puzzled no longer needs to log denials manually; kernel-level audit for Landlock. |
| ABI v8 | In development | Thread synchronization across processes | Relevant for future multi-agent coordination |

RHEL 10's target kernel (6.12+) supports ABI v6. The Landlock ruleset builder in `sandbox/landlock.rs` already implements ABI version negotiation (v1-v4) and shall be extended to v6 with scope rules.

---

## 15. Migration from Current Architecture

### 15.1 Migration Strategy

The migration is a **refactoring** of puzzled, not a rewrite. The governance code (~80-85% of the codebase) is unchanged. The ~12-15% being deleted is commodity sandbox setup that Podman/crun already provide.

| Migration Phase | Scope | Impl. Phases (§18) | Risk |
|---|---|---|---|
| **Migration 1: Add** | Add `puzzle-hook`, seccomp listener, Landlock shim. Both architectures work simultaneously. | Phases 1-2 (Weeks 1-4) | Low — additive only |
| **Migration 2: Default** | `puzzle-podman` defaults to podman-native path. Direct `clone3()` path remains via `puzzlectl branch exec --legacy`. | Phases 3-5 (Weeks 4-10) | Low — fallback available |
| **Migration 3: Remove** | Delete `sandbox/namespace.rs` spawn logic. `puzzlectl branch exec` uses podman internally. **Exception:** retain legacy path behind `--legacy` flag if edge device or functional safety evaluation (see §16.3, §16.4) determines Podman overhead is unacceptable for those deployment targets. | Phase 6 (Weeks 10-12) | Medium — removes fallback |

**Hook failure behavior change:** The current bash hook is **fail-open** (`exit 0` on error — container starts even if governance setup fails). The proposed `puzzle-hook` is **fail-closed** (non-zero exit on error — container start is aborted by crun). This reversal is intentional (see §6.5) but operators should verify that puzzled is running and healthy before deploying the new hook in production, as it will prevent governed containers from starting if puzzled is unavailable.

**Branch creation timing change:** The current architecture creates the branch at two different points depending on the entry path: the `puzzle-podman` wrapper creates it *before* `podman run` (via `puzzlectl branch create`), while the OCI hook (`puzzle-branch-hook.sh`) creates it *during* `createRuntime` (inside the hook itself). The proposed architecture standardizes on creating the branch **before** `podman run` — always in the wrapper or via `puzzlectl branch ensure` in Quadlet's `ExecStartPre` (§4.2 step 2a, §13.1). The proposed OCI hook (`puzzle-hook`) no longer creates branches; it only attaches governance primitives (BPF LSM, fanotify) and triggers post-exit governance. This means the OCI hook alone is no longer sufficient to set up a governed container — the wrapper or Quadlet pre-start commands must run first. Operators migrating from hook-only workflows must add the wrapper or `ExecStartPre` step.

**Label to annotation migration:** The current `puzzle-podman` wrapper uses `--label` for branch and profile metadata (`org.lobstertrap.puzzlepod.branch`, `org.lobstertrap.puzzlepod.profile`). The proposed architecture uses `--annotation` for the branch ID (required for OCI hook filtering via `when.annotations`) and retains `--label` for the profile. Existing Quadlet files and wrapper invocations using `--label org.lobstertrap.puzzlepod.branch=...` must switch to `--annotation org.lobstertrap.puzzlepod.branch=...` during Migration Phase 2.

**Wrapper flag migration:** The `puzzle-podman` wrapper CLI flags change between the current and proposed architecture. The current flags (`--puzzle-branch`, `--profile=`, `--agent-auto-commit`, `--agent-auto-rollback`) are renamed to simpler forms (`--profile=`, `--auto-commit`, `--auto-rollback`) and `--puzzle-branch` becomes implicit (always enabled when using `puzzle-podman run`). The `--no-seccomp-notif` flag is new. These renames should be applied during Migration Phase 2 (Weeks 3-4) when the wrapper is enhanced.

### 15.2 Code Impact

| File | Action | Lines Changed |
|---|---|---|
| `sandbox/namespace.rs` | Delete entirely (spawn logic + `allocate_child_stack`, which is already dead code — custom stacks cause SIGSEGV; `clone3` uses `stack=0, stack_size=0`). | -441 |
| `sandbox/mod.rs` | Remove spawn logic, keep Landlock/BPF/fanotify/seccomp module orchestration | -900 |
| `sandbox/cgroup.rs` | Remove cgroup directory creation. Keep cgroup discovery (for BPF attachment). | -290 |
| `sandbox/network.rs` | Remove network namespace creation. Keep nftables rule generation if needed. | -500 |
| `sandbox/capabilities.rs` | Delete entirely — podman handles capability dropping | -592 |
| `sandbox/selinux.rs` | Delete entirely — podman handles SELinux context via `--security-opt` | -161 |
| `sandbox/quota.rs` | Partially remove — keep XFS quota logic for root-mode branches; rootless uses `podman --storage-opt` | -182 |
| `sandbox/overlay.rs` | Remove unmount logic. Keep upper layer directory creation and `mount -t overlay` (puzzled still owns the OverlayFS mount; podman bind-mounts the merged dir). | -130 |
| `dbus.rs` | Add `GenerateSeccompProfile`, `GenerateLandlockRules`, `AttachGovernance`, `TriggerGovernance` methods | +150 |
| `branch.rs` | Refactor `create()` to return `merged_dir` without spawning process. Current `create()` (lines 162-397) orchestrates sandbox setup including `SandboxBuilder::build()`, seccomp registration, network setup, BPF LSM init, and fanotify init — significant refactoring to decouple governance setup from process creation. | +100/-200 |
| `seccomp_listener.rs` | New: Unix socket listener for crun notif fd | +200 |
| `crates/puzzle-hook/` | New crate: OCI hook binary | +500 |
| `puzzle-init/` | New: Landlock shim binary | +200 |
| `podman/puzzle-podman` | Enhanced wrapper | +100 |
| **Net** | | **~-2,146 lines** |

### 15.3 Testing Migration

All existing tests remain valid with minor modifications:

| Test Category | Changes |
|---|---|
| Unit tests (diff, WAL, policy) | None — governance code unchanged |
| Integration tests (branch_lifecycle, concurrent_branches) | Modify to use podman-native path |
| Security tests (escape vectors) | Modify test harness to use `puzzle-podman run` instead of direct `clone3()` |
| Benchmarks (branch, diff, policy, WAL) | None — governance code unchanged |
| E2E adversarial tests | Modify to use podman containers |

---

## 16. Performance Requirements

### 16.1 Overhead Comparison

| Operation | Current (clone3) | Podman-Native | Difference |
|---|---|---|---|
| Branch creation (OverlayFS upper layer) | < 50ms | < 50ms | None — same operation |
| Container start (namespace + cgroup) | ~20ms (clone3) | ~100-200ms (podman) | +80-180ms — podman has more setup overhead. Acceptable: this is a one-time cost amortized over the agent's lifetime (minutes to hours). |
| seccomp USER_NOTIF per call | ~50-100 μs | ~50-100 μs | None — same kernel path regardless of who installed the filter |
| Landlock check per file access | < 1 μs | < 1 μs | None — same kernel LSM hook |
| OCI hook execution | N/A | ~50ms | New cost, but runs once (createRuntime) and once (poststop) |
| Diff generation | Same | Same | None — same upper layer walk |
| Commit (WAL) | Same | Same | None — same commit engine |
| Policy evaluation (OPA) | Same | Same | None — same regorus engine |

### 16.2 PRD Target Compliance

| Target | Current | Podman-Native | Met? |
|---|---|---|---|
| Branch creation < 50ms (x86_64) | Yes | Yes (OverlayFS upper layer only; podman container start is separate) | **Yes** |
| File I/O overhead < 10% | Yes | Yes (kernel OverlayFS in root mode; fuse-overlayfs ~15-20% in rootless) | **Yes** (root), **Partial** (rootless) |
| Commit (1K files) < 2s | Yes | Yes | **Yes** |
| Rollback < 10ms | Yes | Yes | **Yes** |
| Concurrent branches: 64 | Yes | Yes (podman can run hundreds of containers) | **Yes** |
| puzzled memory < 50MB + 5MB/branch | Yes | Yes (puzzled is smaller — no sandbox creation code) | **Yes** |

### 16.3 Edge Device Considerations

The Core PRD targets resource-constrained edge devices (4GB+ RAM, 8 concurrent branches). The podman-native architecture adds Podman, crun, conmon, and netavark as runtime dependencies, increasing the minimum footprint:

| Component | Disk (RPM installed) | Resident Memory |
|---|---|---|
| Podman | ~45 MB | ~15-30 MB per `podman run` |
| crun | ~1 MB | Minimal (execs into container) |
| conmon | ~2 MB | ~3-5 MB per container |
| netavark + aardvark-dns | ~12 MB | ~5-10 MB |
| **Total added** | **~60 MB disk** | **~25-45 MB per container** |

For edge deployments with tight memory budgets, this overhead may be significant. Mitigations:

1. **Minimal Podman install** — `podman-remote` (client-only, ~15 MB) can be used when a central Podman instance manages containers.
2. **Shared conmon** — multiple governed containers share a single conmon instance when run as a pod.
3. **Legacy mode retention** — for edge devices where Podman overhead is unacceptable, the direct `clone3()` code path can be retained behind a `--legacy` flag (deleted in Phase 6 of the implementation plan). An alternative is to defer Phase 6 deletion and maintain both paths, with `puzzlectl branch exec --legacy` for edge and `puzzle-podman run` for general use.

**Recommendation:** Evaluate edge memory impact during Phase 4 (rootless testing). If the added footprint exceeds 10% of the 4GB edge target, retain the legacy code path for edge-only deployments.

### 16.4 Functional Safety Implications

The Core PRD (Section 18) defines a **real-time profile** that uses only in-kernel primitives with bounded WCET and disables daemon-mediated decisions on the critical path. The podman-native architecture affects this profile:

| Property | Current Architecture | Podman-Native | Impact |
|---|---|---|---|
| Container creation latency | ~20ms (clone3) | ~100-200ms (podman) | **Higher** — one-time cost, not on critical path after startup |
| Critical-path enforcement | Landlock + static seccomp (in-kernel) | Landlock + static seccomp (in-kernel) | **Unchanged** — same kernel primitives |
| Daemon on critical path | No (real-time profile disables USER_NOTIF) | No (same) | **Unchanged** |
| Components in TCB | puzzled + kernel | puzzled + podman + crun + conmon + kernel | **Larger TCB** — more binaries in the trusted computing base |
| Safety certification scope | puzzled + kernel primitives | puzzled + podman + crun + kernel primitives | **Broader** — Podman/crun would need to be included in certification evidence |

**Key constraint:** For IEC 61508 / ISO 26262 certification, the TCB expansion from adding Podman/crun may increase the certification evidence burden. The critical scope boundary from the Core PRD still applies: the containment framework supplements but does NOT replace a certified safety controller.

**Recommendation:** Safety-critical deployments (vehicles, robots, industrial controllers) should use the real-time profile with the direct `clone3()` code path (legacy mode) to minimize the TCB. The podman-native architecture targets data center and developer workloads where TCB size is less constrained.

**Note:** The codebase already ships `safety-critical.yaml` (IEC 61508 profile: 128 MiB memory, 4 PIDs, 32 MB storage, no network, FailSafeState mode) and `edge-minimal.yaml` (4 GB edge target: 128 MiB memory, 8 PIDs, 64 MB storage, no network) profiles in `policies/profiles/`. These profiles should be evaluated with the legacy `clone3()` code path to validate TCB and performance constraints before deciding on Phase 6 deletion scope (§15.1, §18).

---

## 17. Testing Strategy

### 17.1 New Test Suites

| Test | Purpose | Mechanism |
|---|---|---|
| OCI hook unit tests | Verify hook binary correctly parses OCI state, calls puzzled | Mock D-Bus, synthetic OCI state JSON |
| OCI hook integration | Verify hook fires for annotated containers, not for others | `podman run --annotation run.oci.handler=puzzlepod` vs. plain `podman run` |
| Landlock shim tests | Verify shim applies Landlock and execs correctly | Shim + test binary that checks Landlock enforcement |
| seccomp notif socket | Verify puzzled receives fd from crun | Integration test with actual `podman run` |
| Rootless tests | Verify full governance works without root | Run entire test suite under non-root user |
| Mac/Windows tests | Verify podman machine + governance works end-to-end | CI with macOS runner + podman machine |
| Quadlet tests | Verify Quadlet `.container` files work with annotations | systemd integration test |

### 17.2 Existing Test Preservation

All 21 integration test files in `crates/puzzled/tests/` test governance logic (branch lifecycle, concurrent branches, crash recovery, policy evaluation, etc.). These tests are independent of how the container is created and remain valid.

The 10 security escape test scripts in `tests/security/` (plus `helpers.sh` and `run_all.sh`) are modified to use `puzzle-podman run` as the test harness, but the escape vectors being tested are identical.

---

## 18. Phased Implementation Plan

These implementation phases map to the three migration phases in §15.1:

| Phase | Timeline | Migration (§15.1) | Deliverables | Risk |
|---|---|---|---|---|
| **Phase 1: Hook + Shim** | Weeks 1-3 | Migration 1: Add | `puzzle-hook` binary, `puzzle-init` Landlock shim, OCI hook config JSON, `puzzled` seccomp listener socket | Low — additive, no existing code changes |
| **Phase 2: Wrapper Enhancement** | Weeks 3-4 | Migration 1: Add | Enhanced `puzzle-podman` with seccomp profile generation, annotation injection, podman machine detection | Low — bash script changes only |
| **Phase 3: puzzled Refactor** | Weeks 4-6 | Migration 2: Default | Add `GenerateSeccompProfile`, `GenerateLandlockRules`, `AttachGovernance`, `TriggerGovernance` D-Bus methods. Modify `branch.rs` `create()` to return `merged_dir` without spawn. | Medium — core puzzled changes |
| **Phase 4: Rootless** | Weeks 6-8 | Migration 2: Default | puzzled user instance service, rootless configuration, degraded-mode testing | Medium — new configuration path |
| **Phase 5: Mac/Windows** | Weeks 8-10 | Migration 2: Default | podman machine integration, transparent SSH proxy in wrapper, installation automation | Low — wrapper changes only |
| **Phase 6: Cleanup** | Weeks 10-12 | Migration 3: Remove | Delete `sandbox/namespace.rs` spawn logic, remove `clone3()` code path, update all tests. **Gate:** evaluate edge/safety findings from §16.3 and §16.4 before deleting — retain `--legacy` flag if needed for edge or safety-critical deployments. | Medium — removes fallback |
| **Phase 7: IDE Integration** | Weeks 12-14 | — | Dev Container support, VS Code extension, documentation | Low |
| **Phase 8: D-Bus Split** | Weeks 14-16 | — | Split Manager into Manager + Audit + Policy interfaces. Add CommitPartial, CheckpointBranch, RequestPermission, SuggestProfile methods. | Low-Medium |
| **Phase 9: Crate Extraction** | Weeks 16-18 | — | Extract puzzled-policy, puzzled-diff, puzzled-wal, puzzled-ima, puzzled-conflict as independent library crates. Define GovernanceBackend trait. | Medium |
| **Phase 10: MCP Server** | Weeks 18-19 | — | Expand existing puzzled-mcp crate to cover all branch operations including partial commit and checkpoint. | Low |
| **Phase 11: Cockpit Plugin** | Weeks 19-22 | — | cockpit-puzzlepod plugin with branch management, audit viewer, policy editor, permission request dialog. | Medium |
| **Phase 12: Podman Desktop Extension** | Weeks 22-24 | — | Extension showing governance status in container list, governance detail tab, notification integration. | Medium |

**Note:** Phases 8-12 are independent of Phases 1-7 and can be parallelized. The crate extraction (Phase 9) should begin as soon as the puzzled refactor (Phase 3) stabilizes.

---

## 19. Risk Analysis

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| crun seccomp notification socket behavior changes | Low | High | Pin minimum crun version. Feature is stable and used by other projects (e.g., Kata Containers). Add version check in wrapper. |
| OCI hook interface changes | Very Low | Medium | OCI hooks are part of the OCI runtime spec (v1.0.0). Highly stable. |
| Landlock shim adds attack surface | Low | Medium | Shim is ~200 lines of static binary with no dependencies. Auditable. Shim execs immediately — not a persistent process. |
| Rootless fuse-overlayfs performance | Medium | Low | Known ~15-20% I/O overhead vs. kernel OverlayFS. Acceptable for development. Production uses root mode. |
| podman machine latency on Mac | Medium | Low | podman machine uses gvproxy for transparent networking. Adds ~10-50ms to API calls. Acceptable for governance operations (not on hot path). |
| Developer confusion (two CLIs) | Medium | Medium | `puzzle-podman` is the single entry point. Developers never need `puzzlectl` directly (though it remains available for advanced use). |

---

## 20. Open Questions

| ID | Question | Impact | Target Resolution |
|---|---|---|---|
| PQ1 | Should `puzzle-podman` be a bash wrapper or a compiled Rust binary? Bash is simpler but Rust enables direct D-Bus calls without `puzzlectl` subprocess overhead. | Developer experience, latency | Phase 2 |
| PQ2 | Should the Landlock shim be statically-linked C or Rust `#![no_std]`? C is smaller and has no runtime. Rust `#![no_std]` provides memory safety but requires careful dependency management. | Binary size, safety | Phase 1 |
| PQ3 | Should we provide a `podman --puzzle-branch` alias via Podman's plugin mechanism (if one exists in future), or is the `puzzle-podman` wrapper sufficient long-term? | Developer experience | Phase 5 |
| PQ4 | How should the OCI hook handle the case where puzzled is in the process of restarting (systemd Restart=on-failure)? Should the hook retry with backoff, or fail immediately? | Availability, UX | Phase 1 |
| PQ5 | Should the wrapper support `podman compose` (via compose.yaml annotations) for multi-agent orchestration? | Multi-agent UX | Phase 7 |
| ~~PQ6~~ | ~~For rootless mode, should puzzled use fuse-overlayfs directly (matching podman) or create its own overlay management?~~ **Resolved:** puzzled uses fuse-overlayfs as a subprocess for rootless branch mounts (see §10.6). | ~~Rootless complexity~~ | ~~Phase 4~~ Resolved |
| PQ7 | GPU/accelerator containment strategy — Landlock can restrict device nodes (`/dev/nvidia*`, `/dev/dri/*`, `/dev/accel*`), but GPU memory is not controlled by cgroups. For NVIDIA, nvidia-container-toolkit handles device isolation in containers. How should puzzled profiles express GPU access constraints? | Edge AI inference, ML training workloads | Phase 2 |
| PQ8 | Secrets management via Unix domain socket vs. environment variables — puzzled could provide credentials through a socket at `/run/puzzled/secrets.sock` that the agent queries on demand, enabling audit, revocation, and scope-limiting. Should this complement or replace env var injection? | Security, auditability | Phase 2 |
| PQ9 | Memory/context poisoning mitigation (OWASP ASI06) — should OPA rules flag `.context`/`.memory`/`*.embedding` files by default, or is this a documented limitation with optional policy? | Security completeness | Phase 1 |
| PQ10 | NIST AI Agent Standards engagement — the NIST RFI on AI Agent Security received 932 public comments. A concept paper on "Software and AI Agent Identity and Authorization" is due April 2, 2026. PuzzlePod's UID-based identity, governance gate, and audit trail map directly to NIST's framework. | Compliance positioning | Immediate |
| PQ11 | Non-HTTP protocol monitoring extensibility — should puzzle-proxy support protocol-aware plugins for PostgreSQL, gRPC, and WebSocket, or is binary allow/block at the IP:port level via nftables/Landlock the documented boundary? | Infrastructure agent use cases | Phase 2 |

### 20.1 Gap Analysis Resolution

The following table maps priority items from the gap analyses to their architectural resolutions in this PRD:

| Priority | Item | Resolution |
|---|---|---|
| 1 | Incremental commits (OQ4) | `CommitPartial` D-Bus method (§7.3.4) + MCP tool (§24) |
| 2 | Landlock ABI v6/v7 adoption | `sandbox/landlock.rs` ABI version negotiation extension (§14.8) |
| 3 | OWASP/NIST/CSA compliance mapping | §14.6, §14.7, PQ10 |
| 4 | Developer lightweight mode (rootless) | Rootless Podman + puzzled --user (§10) |
| 5 | Profile auto-generation | `SuggestProfile` D-Bus method on Policy interface (§7.3.3, §7.3.4) |
| 6 | IDE integration | Dev Containers + VS Code extension (§12) + Cockpit plugin (§21) |
| 7 | MCP server for branch operations | puzzled-mcp with full tool set (§24) |
| 8 | Threat model update (B1-B3, T8) | Extended threat model (§14.5) |
| 9 | GPU/accelerator containment | Podman `--gpus` flag passthrough (§9.2) + open question PQ7 |
| 10 | Kubernetes integration | GovernanceBackend trait + shared crates (§23) |

---

## 21. Cockpit Integration

Cockpit communicates with system services via D-Bus natively. The puzzled D-Bus API (§7.3) is designed to be directly consumable by a Cockpit plugin.

### 21.1 Plugin Architecture

```
cockpit-puzzlepod/
├── manifest.json           # Cockpit plugin manifest
├── index.html              # Dashboard entry point
├── create.js               # "Launch Governed Agent" form (steps 1-4)
├── branches.js             # Branch list/inspect/approve/reject
├── audit.js                # Audit log viewer via Audit interface
├── policy.js               # Profile management via Policy interface
└── puzzlepod.css
```

### 21.2 Creating Governed Containers from Cockpit

```javascript
// cockpit-puzzlepod/create.js

const puzzled = cockpit.dbus("org.lobstertrap.PuzzlePod1", { bus: "system" });
const manager = puzzled.proxy("org.lobstertrap.PuzzlePod1.Manager",
                              "/org/lobstertrap/PuzzlePod1");

async function launchGovernedAgent(image, profile, basePath, command) {
    // Steps 1-3: identical D-Bus calls to puzzled
    const branchResult = JSON.parse(
        await manager.CreateBranch(profile, basePath, JSON.stringify(command)));
    const branchId = branchResult.id;
    const mergedDir = branchResult.merged_dir;

    const seccompPath = await manager.GenerateSeccompProfile(branchId);
    const landlockPath = await manager.GenerateLandlockRules(branchId);

    // Step 4: create the container via podman CLI
    const podmanArgs = [
        "podman", "run", "-d",
        "--mount", `type=bind,src=${mergedDir},dst=/workspace`,
        "--mount", "type=bind,src=/usr/libexec/puzzle-init,dst=/puzzle-init,ro",
        "--mount", `type=bind,src=${landlockPath},dst=/run/puzzlepod/landlock.json,ro`,
        "--entrypoint", "/puzzle-init",
        "--security-opt", `seccomp=${seccompPath}`,
        "--security-opt", "label=type:puzzlepod_t",
        "--annotation", "run.oci.handler=puzzlepod",
        "--annotation", `org.lobstertrap.puzzlepod.branch=${branchId}`,
        "--label", `org.lobstertrap.puzzlepod.profile=${profile}`,
        "--env", `PUZZLEPOD_BRANCH_ID=${branchId}`,
        "--env", "PUZZLEPOD_WORKSPACE=/workspace",
        image, ...command
    ];

    cockpit.spawn(podmanArgs, { superuser: "try" })
        .then(containerId => {
            showNotification(`Governed container started: ${containerId.trim()}`);
        })
        .catch(err => {
            manager.RollbackBranch(branchId, `container start failed: ${err.message}`);
            showError(err.message);
        });
}
```

### 21.3 Monitoring and Governance

```javascript
// cockpit-puzzlepod/branches.js

// List branches
manager.ListBranches().then(result => {
    renderBranchTable(JSON.parse(result));
});

// Subscribe to real-time events
manager.addEventListener("signal", (event, name, args) => {
    switch (name) {
        case "BranchCommitted":
            showNotification(`Branch ${args[0]} committed (${args[1]} files)`);
            break;
        case "PermissionRequested":
            showPermissionDialog(args[0], args[1], args[2], args[3]);
            break;
        case "GovernanceReviewPending":
            showReviewPanel(args[0], args[1]);
            break;
    }
});

// Approve a branch from the review panel
function approveBranch(branchId) {
    manager.ApproveBranch(branchId).then(result => {
        const r = JSON.parse(result);
        showNotification(`Committed ${r.files_committed} files`);
    });
}
```

### 21.4 D-Bus to UI Mapping Table

| Cockpit UI Element | D-Bus Source | Interface |
|---|---|---|
| **"Launch Agent" form** | Methods `CreateBranch`, `GenerateSeccompProfile`, `GenerateLandlockRules` | Manager |
| Dashboard: active branch count | Property `ActiveBranches` | Manager |
| Dashboard: commit/rollback/reject totals | Properties `Total*` | Manager |
| Branch list table | Method `ListBranches()` | Manager |
| Branch detail: diff viewer | Method `DiffBranch()` | Manager |
| Branch detail: approve/reject buttons | Methods `ApproveBranch()`, `RejectBranch()` | Manager |
| Real-time activity feed | Signals `BranchCreated`, `BranchCommitted`, etc. | Manager |
| Permission request notification | Signal `PermissionRequested` | Manager |
| Audit log viewer | Method `QueryEvents()` | Audit |
| Audit export button | Method `ExportEvents()` | Audit |
| Manifest verification | Method `VerifyManifest()` | Audit |
| Prometheus metrics graphs | Method `GetMetrics()` | Audit |
| Profile list | Method `ListProfiles()` | Policy |
| Profile editor | Method `GetProfile()` | Policy |
| Profile validator | Method `ValidateProfile()` | Policy |
| Auto-generate profile | Method `SuggestProfile()` | Policy |

---

## 22. Podman Desktop Integration

Podman Desktop is an Electron app that manages Podman via its REST API. It can both create governed containers and display governance status.

### 22.1 Creating Governed Containers

The extension follows the same four-step pattern (§5.4). The difference is the transport:

- **Steps 1-3 (puzzled):** Podman Desktop does not speak D-Bus natively (Electron limitation). Two options:
  - **Option A: D-Bus bridge** — a small sidecar process (`puzzled-bridge`) listens on a Unix socket or localhost HTTP port and proxies JSON requests to puzzled's D-Bus API (see §22.3).
  - **Option B: puzzlectl subprocess** — the extension spawns `puzzlectl` CLI commands as child processes, parsing JSON output. Simpler to implement; slightly higher latency per call.

- **Step 4 (Podman):** Podman Desktop already uses the Podman REST API. The extension adds governance-specific mounts, annotations, entrypoint, and seccomp profile to the `POST /containers/create` request.

```typescript
// podman-desktop-puzzlepod/src/extension.ts

import * as extensionApi from '@podman-desktop/api';

async function createGovernedContainer(
    image: string, profile: string, basePath: string, command: string[]
) {
    const branchJson = await runPuzzlectl(
        'branch', 'create', '--profile', profile, '--base', basePath, '--output=json');
    const branch = JSON.parse(branchJson);

    const seccompPath = await runPuzzlectl(
        'branch', 'seccomp-profile', branch.id, '--output=path');
    const landlockPath = await runPuzzlectl(
        'branch', 'landlock-rules', branch.id, '--output=path');

    const containerConfig = {
        image: image,
        entrypoint: ['/puzzle-init'],
        command: command,
        mounts: [
            { type: 'bind', source: branch.merged_dir, target: '/workspace' },
            { type: 'bind', source: '/usr/libexec/puzzle-init',
              target: '/puzzle-init', readOnly: true },
            { type: 'bind', source: landlockPath.trim(),
              target: '/run/puzzlepod/landlock.json', readOnly: true },
        ],
        annotations: {
            'run.oci.handler': 'puzzlepod',
            'org.lobstertrap.puzzlepod.branch': branch.id,
        },
        labels: { 'org.lobstertrap.puzzlepod.profile': profile },
        seccomp_profile_path: seccompPath.trim(),
        env: { PUZZLEPOD_BRANCH_ID: branch.id, PUZZLEPOD_WORKSPACE: '/workspace' },
    };

    const engine = extensionApi.provider.getContainerConnections()[0];
    const container = await engine.connection.createContainer(containerConfig);
    await container.start();
}

async function runPuzzlectl(...args: string[]): Promise<string> {
    return extensionApi.process.exec('puzzlectl', args).then(r => r.stdout);
}
```

### 22.2 Monitoring Governance Status

- **Container list column:** "Governance" — shows Active/GovernanceReview/Committed/RolledBack by matching `org.lobstertrap.puzzlepod.branch` annotation to puzzled's `ListBranches()` response.
- **Container detail tab:** "Governance" tab showing diff, policy violations, behavioral triggers, and approve/reject buttons.
- **Notifications:** Permission requests and governance review prompts surfaced as Podman Desktop notifications.

### 22.3 D-Bus Bridge for Non-D-Bus Consumers

```
Non-D-Bus consumer ──HTTP/JSON──► puzzled-bridge ──D-Bus──► puzzled
                                  (sidecar process)
```

The bridge (`puzzled-bridge`) is a thin process (~200 lines) that:
- Listens on a Unix socket (or localhost TCP for remote)
- Accepts JSON-RPC or REST requests
- Translates to D-Bus method calls on `org.lobstertrap.PuzzlePod1`
- Forwards D-Bus signals as Server-Sent Events or WebSocket messages

### 22.4 Unified API Diagram

```
                    ┌──────────────────────────────────┐
                    │     puzzled D-Bus API              │
                    │                                  │
                    │  Manager: CreateBranch,           │
                    │    GenerateSeccompProfile, ...    │
                    │  Audit: QueryEvents, GetMetrics   │
                    │  Policy: ListProfiles, Reload     │
                    └──┬──────────┬──────────┬─────────┘
                       │          │          │
              D-Bus    │   D-Bus  │   puzzlectl  │
              native   │   native │   subprocess│
                       ▼          ▼          ▼
                  ┌─────────┐ ┌────────┐ ┌──────────────┐
                  │ Cockpit │ │puzzlectl│ │Podman Desktop│
                  │ (web)   │ │(CLI)   │ │(Electron)    │
                  └────┬────┘ └───┬────┘ └──────┬───────┘
                       │          │             │
                  cockpit.spawn  podman run  Podman REST
                       │     (shell)       API
                       ▼                   ▼
                  ┌──────────────────────────────┐
                  │    Podman (container create)  │
                  └──────────────────────────────┘
```

---

## 23. Library-First Crate Architecture

### 23.1 Crate Decomposition

```
crates/
├── puzzled-types/          # Shared types. No runtime deps. PORTABLE.
├── puzzled-policy/         # OPA/Rego evaluation via regorus. PORTABLE.
│   (extract from policy.rs)
├── puzzled-diff/           # Diff engine: directory walk, checksum-filter. PORTABLE.
│   (extract from diff.rs)
├── puzzled-wal/            # Write-ahead log for crash-safe commit. PORTABLE.
│   (extract from wal.rs, commit.rs)
├── puzzled-ima/            # Ed25519 manifest signing. PORTABLE.
│   (extract from ima.rs)
├── puzzled-conflict/       # Cross-branch conflict detection. PORTABLE.
│   (extract from conflict.rs)
├── puzzled-governance/     # GovernanceBackend trait (NEW). PORTABLE.
├── puzzled-sandbox/        # Linux-specific: Landlock, seccomp, BPF LSM,
│   (existing sandbox/)      fanotify, OverlayFS, XFS quotas. NOT PORTABLE.
├── puzzled/                # Daemon binary. Composes all crates.
├── puzzled-mcp/            # MCP server. Standalone binary wrapping D-Bus client.
├── puzzlectl/              # CLI + TUI. D-Bus client.
├── puzzle-proxy/           # HTTP proxy for network side-effect gating.
├── puzzle-hook/          # OCI hook binary (NEW). ~500 lines Rust.
└── puzzle-init/          # Landlock shim binary (NEW). ~200 lines.
```

### 23.2 GovernanceBackend Trait

```rust
// crates/puzzled-governance/src/lib.rs

use puzzlepod_types::*;

pub trait GovernanceBackend: Send + Sync {
    fn attach(&self, target: &GovernanceTarget) -> Result<BranchId>;
    fn diff(&self, id: &BranchId) -> Result<Vec<FileChange>>;
    fn commit(&self, id: &BranchId) -> Result<CommitResult>;
    fn commit_partial(&self, id: &BranchId, prefixes: &[String]) -> Result<CommitResult>;
    fn rollback(&self, id: &BranchId, reason: &str) -> Result<()>;
    fn checkpoint(&self, id: &BranchId) -> Result<CheckpointId>;
    fn list(&self) -> Result<Vec<BranchInfo>>;
}

pub struct GovernanceTarget {
    pub pid: u32,
    pub cgroup_path: String,
    pub container_id: String,
    pub profile_name: String,
    pub base_path: String,
    pub annotations: HashMap<String, String>,
}
```

### 23.3 Kubernetes Operator Path

```
┌───────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                      │
│  ┌───────────────────────────┐                            │
│  │  puzzlepod-operator         │  Uses: puzzled-policy,      │
│  │  (control plane)          │  puzzled-types, puzzled-     │
│  │  Watches: AgentBranch CRD │  conflict crates           │
│  └────────────┬──────────────┘                            │
│               │ gRPC (GovernanceBackend impl)              │
│  ┌────────────▼──────────────┐                            │
│  │  puzzled DaemonSet         │  Same binary, same crates. │
│  │  (per node)               │  gRPC instead of D-Bus.    │
│  │  OverlayFS branch per pod │  CRI-O/containerd instead  │
│  │  Landlock + seccomp + OPA │  of Podman.                │
│  └───────────────────────────┘                            │
│                                                           │
│  AgentBranch CRD:                                         │
│    apiVersion: puzzlepod.lobstertrap.org/v1alpha1                │
│    kind: AgentBranch                                      │
│    spec:                                                  │
│      profile: code-assistant                              │
│      basePath: /workspace                                 │
│    status:                                                │
│      branchId: abc-123                                    │
│      state: Active                                        │
│      filesModified: 23                                    │
└───────────────────────────────────────────────────────────┘
```

The governance crates are used identically regardless of which `GovernanceBackend` implementation is active. Only the transport (D-Bus vs gRPC) and the containment provider (Podman vs CRI-O/containerd) change.

---

## 24. MCP Server Integration

### 24.1 puzzled-mcp Standalone Binary

`puzzled-mcp` is a standalone binary wrapping the D-Bus API as MCP tools. Any MCP-compatible agent framework (Claude Code, Codex, Goose, Gemini) can use PuzzlePod governance natively without custom SDK work.

### 24.2 MCP Tool Schema

```json
{
  "name": "puzzlepod-governance",
  "version": "1.0.0",
  "tools": [
    {
      "name": "branch_create",
      "description": "Create a governed branch for agent work",
      "inputSchema": {
        "type": "object",
        "properties": {
          "base_path": { "type": "string" },
          "profile": { "type": "string", "default": "standard" }
        },
        "required": ["base_path"]
      }
    },
    {
      "name": "branch_diff",
      "description": "View pending changes in current branch",
      "inputSchema": {
        "type": "object",
        "properties": { "branch_id": { "type": "string" } },
        "required": ["branch_id"]
      }
    },
    {
      "name": "branch_commit",
      "description": "Request governance-gated commit of changes",
      "inputSchema": {
        "type": "object",
        "properties": { "branch_id": { "type": "string" } },
        "required": ["branch_id"]
      }
    },
    {
      "name": "branch_commit_partial",
      "description": "Commit a subset of changes (by path prefix)",
      "inputSchema": {
        "type": "object",
        "properties": {
          "branch_id": { "type": "string" },
          "path_prefixes": { "type": "array", "items": { "type": "string" } }
        },
        "required": ["branch_id", "path_prefixes"]
      }
    },
    {
      "name": "branch_rollback",
      "description": "Discard all changes and roll back",
      "inputSchema": {
        "type": "object",
        "properties": {
          "branch_id": { "type": "string" },
          "reason": { "type": "string" }
        },
        "required": ["branch_id"]
      }
    },
    {
      "name": "branch_checkpoint",
      "description": "Save branch state for later resume",
      "inputSchema": {
        "type": "object",
        "properties": { "branch_id": { "type": "string" } },
        "required": ["branch_id"]
      }
    },
    {
      "name": "branch_status",
      "description": "Check branch governance status",
      "inputSchema": {
        "type": "object",
        "properties": { "branch_id": { "type": "string" } },
        "required": ["branch_id"]
      }
    }
  ]
}
```

### 24.3 Security Considerations

- puzzled-mcp does NOT store MCP tokens — it forwards authentication opaquely
- Branch-scoped credentials, not user-level credentials
- Token rotation and scope-limiting are part of the design
- The MCP server connects to puzzled via D-Bus — no direct kernel interaction

### 24.4 Integration Paths

| Path | Phase | Scope |
|---|---|---|
| **A: MCP Server for Branch Operations** | Phase 1 | Expose branch operations as MCP tools. Any MCP-compatible agent framework can use governance without custom SDK work. |
| **B: MCP-Aware Governance** | Phase 2 | Extend OPA policies to evaluate MCP tool calls. Gate operations per-profile. |
| **C: MCP Security Hardening** | Phase 2-3 | MCP server allowlisting per profile. Context injection governance via OPA. |

---

## 25. Competitive Analysis

### 25.1 Competitive Landscape (March 2026)

| Tool | Linux Sandboxing | Notable |
|---|---|---|
| **Cursor** | Landlock + seccomp-BPF | 2 CVEs (CVE-2026-22708, CVE-2025-59944). Background agents on AWS. |
| **Claude Code** | Bubblewrap + network NS + socat proxy | Observed attempting to disable own sandbox. |
| **OpenAI Codex** | Landlock+seccomp OR bubblewrap (dual pipeline) | Sandbox applied before execvp. |
| **Goose (Block)** | macOS Seatbelt. Linux not yet. | AAIF co-founder. |

### 25.2 Competitive Matrix

| Capability | PuzzlePod | Cursor | Claude Code | Codex | k8s-agent-sandbox |
|---|---|---|---|---|---|
| Kernel sandboxing | 7+ layers | 2 layers | 2 layers | 2 layers | VM-level |
| Governance gate | OPA/Rego | None | None | None | None |
| Transactional FS | OverlayFS | None | None | None | PVC |
| Audit trail | IMA-signed | None | None | None | None |
| Root required | No | No | No | No | Yes |
| IDE integration | DevContainers | Native | Native | Native | None |

### 25.3 Differentiation

The governance layer is the moat. Every competitor can sandbox an agent. No competitor provides governance-gated commit/rollback with policy-evaluated, audit-trailed, cryptographically signed transactional commit with zero-residue rollback.

---

## 26. References

| Reference | Description |
|---|---|
| [OCI Runtime Specification — Hooks](https://github.com/opencontainers/runtime-spec/blob/main/config.md#posix-platform-hooks) | OCI hook lifecycle stages and state format |
| [crun seccomp notification](https://github.com/containers/crun/blob/main/crun.1.md) | crun's support for `SCMP_ACT_NOTIFY` and `listenerPath` |
| [Podman Hooks Documentation](https://docs.podman.io/en/latest/markdown/podman.1.md) | Podman OCI hooks directory configuration |
| [Podman Machine](https://docs.podman.io/en/latest/markdown/podman-machine.1.md) | podman machine for Mac/Windows development |
| [Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.md) | Podman systemd container units |
| [Landlock LSM](https://landlock.io) | Unprivileged access control (kernel 5.13+) |
| [Landlock ABI v6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git) | IPC scoping + signal scoping (kernel 6.12) |
| [seccomp USER_NOTIF](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html) | Seccomp user-space notification mechanism |
| [Dev Containers Specification](https://containers.dev/implementors/spec/) | Development container specification |
| [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-agentic-applications/) | Formal threat taxonomy for AI agents (Dec 2025) |
| [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence) | Security controls for AI agents (Feb 2026) |
| [CSA Agentic Trust Framework](https://cloudsecurityalliance.org/) | Graduated trust model for AI agents (Feb 2026) |
| [MCP Specification](https://spec.modelcontextprotocol.io/) | Model Context Protocol (AAIF/Linux Foundation) |
| [Cockpit Plugin API](https://cockpit-project.org/guide/latest/development.html) | Cockpit plugin development |
| [Podman Desktop Extension API](https://podman-desktop.io/docs/extensions) | Podman Desktop extension development |
| PuzzlePod Core PRD | `docs/PuzzlePod_prd.md` (RHEL-AGENTIC-PRD-2026-001 v2.2) |
| PuzzlePod Advanced PRD | `docs/PuzzlePod_Adv_prd.md` (RHEL-AGENTIC-ADV-2026-001) |
| Kernel vs. Userspace Analysis | `docs/Kernel_vs_userspace.md` (RHEL-AGENTIC-ARCH-2026-001) |

---

## Appendix A: Architectural Decision — Is puzzled Necessary?

### A.1 What Podman/systemd Already Provide

| Capability | Podman | systemd | Notes |
|---|---|---|---|
| PID/Mount/Net namespaces | Yes | Partial | Podman does this completely |
| cgroup v2 resource limits | Yes | Yes | Both handle well |
| Static seccomp profiles | Yes | Yes | Static deny lists only |
| SELinux confinement | Yes | Yes | Kernel-enforced |
| Capability dropping | Yes | Yes | Standard |
| OverlayFS (container layers) | Yes | No | Podman manages internally |
| Rootless mode | Yes | Yes | Both support |
| Quadlet/systemd integration | Yes | Native | Declarative container units |

### A.2 What Requires a Daemon

| Capability | Static Config? | Why a Daemon is Required |
|---|---|---|
| seccomp USER_NOTIF | No | Dynamic per-call decision based on runtime argument inspection. Podman supports only static profiles. |
| Governance-gated commit | No | Coordinated multi-step operation (freeze → diff → OPA eval → WAL commit/rollback) requiring a stateful process. |
| OverlayFS branch management | No | Branches independent of container lifecycle, persistent across restarts, with upper-layer access for frozen diff. |
| Landlock configuration | No | Podman does not use Landlock. No upstream proposal. Must be applied via `landlock_restrict_self()`. |
| BPF LSM attachment | No | Privileged eBPF program loading for per-cgroup exec rate limiting. Podman does not support. |

### A.3 Three Architectural Options

**Option A: puzzled Does Everything** — Single component handles sandbox + governance. Pro: tightest integration. Con: duplicates Podman.

**Option B: Podman Containment + puzzled Governance (Selected)** — Podman handles namespaces/cgroups/SELinux/capabilities. puzzled handles branches/OPA/seccomp-NOTIF/Landlock/BPF/audit. Pro: focused, smaller, rootless. Con: two processes.

**Option C: Contribute Upstream** — Propose Landlock/USER_NOTIF to Podman. Pro: eliminates puzzled long-term. Con: 12-18+ months, uncertain acceptance.

### A.4 Decision

**Option B is selected.** The governance layer requires stateful, real-time decision-making that cannot be expressed as static configuration. Podman's containment is battle-tested — reimplementing it wastes engineering effort. The kernel enforces. Podman contains. puzzled governs.

---

*This document defines the Podman-native architecture for PuzzlePod. The kernel enforces. Podman contains. puzzled governs. D-Bus integrates.*
