# Kernel vs. Userspace: Architectural Decision for PuzzlePod

**Document ID:** RHEL-AGENTIC-ARCH-2026-001
**Date:** 2026-03-03
**Author:** Francis Chow
**Status:** Decision Pending — Engineering Review
**Related:** PuzzlePod PRD (RHEL-AGENTIC-PRD-2026-001 v1.2)

---

## Executive Summary

This document evaluates whether the PuzzlePod — kernel-level guardrails for autonomous AI agents — requires Linux kernel modifications, or whether existing kernel primitives composed by a userspace daemon are sufficient.

**Finding:** Existing kernel primitives (namespaces, cgroups v2, seccomp-BPF, Landlock, SELinux, BPF LSM, OverlayFS, XFS project quotas, pidfd, fanotify) provide approximately **85-90% of the required security containment** without any kernel changes. The remaining gaps are concentrated in **transactional filesystem semantics** — specifically, distinguishing agent changes from OverlayFS copy-up artifacts, atomic multi-file commit, and efficient change tracking.

**Recommendation:** Adopt a **userspace-first architecture**. Ship the containment daemon and governance engine using only existing kernel primitives. Propose a single, narrow kernel enhancement — an OverlayFS change log — only after Phase 0 empirically validates the gap. Do not build AgentGuard as a new LSM. Do not build a new cgroup controller. Do not introduce new system calls.

This approach:
- Eliminates upstream acceptance risk for the core product
- Deploys on existing RHEL 10 kernels without kernel rebuilds
- Delivers value immediately while preserving optionality for kernel work
- Produces a more defensible architecture (kernel enforces, userspace decides)

---

## 1. The Core Question

The PRD proposes four kernel subsystems:

| Subsystem | PRD Proposal | Core Question |
|---|---|---|
| **AgentFS** | New kernel module extending OverlayFS with transactional semantics | Can OverlayFS + userspace tooling achieve the same result? |
| **AgentGuard LSM** | New Linux Security Module for per-agent access control | Can Landlock + BPF LSM + SELinux achieve the same result? |
| **Agent cgroups** | New cgroup v2 controller for agent-specific resource accounting | Can existing cgroup controllers + XFS quotas + BPF LSM achieve the same result? |
| **Branch Context** | New system call (`branch_context_create()`) for atomic lifecycle binding | Can `clone3()` + pidfd + crun achieve the same result? |

For each, we evaluate: **Is there a security property that cannot be achieved without kernel modification?** Performance optimizations and convenience improvements are noted but do not by themselves justify kernel changes.

---

## 2. Security Containment: What Existing Primitives Provide

The following table maps every security requirement in the PRD's threat model to existing kernel primitives. No kernel modifications are needed for any of these.

| Threat | Required Containment | Existing Primitive | Kernel Version |
|---|---|---|---|
| Agent reads unauthorized files | Filesystem access control | **Landlock** (unprivileged, irrevocable, path-hierarchy ACL) + **SELinux** (label-based MAC) | 5.13+ (ABI v1) |
| Agent writes to base filesystem | Write isolation | **OverlayFS** in mount namespace (all writes go to upper layer; base is read-only) | 3.18+ |
| Agent executes unauthorized binaries | Exec control | **Landlock** `EXECUTE` per directory + **seccomp-BPF** + **SELinux** exec transition rules | 5.13+ |
| Agent escapes process containment | Process isolation | **PID namespace** (setsid harmless; kill(-1,9) scoped; PID 1 death kills all) | 3.8+ |
| Agent accesses host network | Network isolation | **Network namespace** + **nftables** rules | 2.6.29+ |
| Agent connects to unauthorized ports | Network ACL | **Landlock** `CONNECT_TCP` port restriction | 6.7+ (ABI v4) |
| Agent exhausts CPU/memory | Resource limits | **cgroups v2** (cpu, memory, io, pids controllers) | 4.5+ |
| Agent exhausts disk space | Storage quota | **XFS project quotas** on OverlayFS upper layer directory | Long-standing |
| Agent creates too many files | Inode quota | **XFS project quotas** ihard limit | Long-standing |
| Agent loads BPF/kernel modules | Syscall restriction | **Seccomp-BPF** (blocks mount, bpf, init_module, ptrace, etc.) | 3.17+ |
| Agent acquires privileges | Privilege containment | **Empty capability bounding set** + `PR_SET_NO_NEW_PRIVS` + nosuid mount | 2.6.26+ |
| Agent communicates with sibling agents | Cross-agent isolation | Separate **PID namespaces** (can't see sibling PIDs) + separate **mount namespaces** (no shared upper layers) + **Landlock** ABI v6 signal/socket scoping | 6.12+ |
| Agent exceeds exec call budget | Quantitative limit | **BPF LSM** program on `bprm_check_security` hook, keyed by cgroup ID, counting and denying | 5.7+ |
| Daemon crashes mid-containment | Crash resilience | **PID namespace** (kernel kills all on PID 1 death) + **cgroup** (freed when empty) + **mount namespace** (freed when last process exits) | Kernel-guaranteed |

**Conclusion: The security containment model does not require kernel modifications.** Every threat in the PRD's threat model (T1-T6) can be mitigated using primitives available in mainline kernels 6.7+, which is the baseline for RHEL 10.

---

## 3. The Real Gaps: Transactional Filesystem Semantics

While security containment is achievable with existing primitives, the PRD's **Fork, Explore, Commit** model requires transactional filesystem semantics that existing primitives do not fully provide. This section evaluates each gap honestly.

### 3.1 Gap: Distinguishing Agent Changes from OverlayFS Copy-Up

**The problem:** When an agent modifies a file, OverlayFS copies the entire file from the lower layer to the upper layer before applying the modification (copy-up). When walking the upper directory to compute a diff, these copy-up artifacts are **indistinguishable from intentional agent modifications**. This means the governance engine may review files the agent never intended to change.

**Severity assessment:**

For typical AI agent workloads (code generation, file editing, configuration management):
- Agents read many files (no copy-up — read-only opens don't trigger copy-up)
- Agents write to a small number of files (copy-up is accurate — these ARE real changes)
- Agents create new files (no copy-up — they're new in the upper layer)
- Copy-up pollution is primarily caused by: `open(O_RDWR)` on files the agent only reads, `mmap(MAP_PRIVATE)` with private COW, and metadata modifications (chmod, chown, touch)

**Estimated false-positive rate in diff:** 5-15% for typical agent workloads. This is manageable with userspace heuristics:
- Compare file checksums between upper and lower — if identical content, it's a pure copy-up
- Compare modification timestamps — files with mtime unchanged since copy-up time are likely artifacts
- Whitelist known copy-up patterns (library files, read-only configs)

**Userspace mitigation:** Walk the upper layer, compare each file's checksum against the lower layer, and exclude files with identical content. This adds O(n) checksum computation but produces a clean diff. For a branch with 100 modified files and 50 copy-up artifacts, this takes <1 second on modern hardware.

**Kernel solution:** A kernel-maintained change log in OverlayFS that records which inodes were modified by userspace write operations (as distinct from kernel-internal copy-up). This would provide an O(changes) diff with zero false positives. This is a **general-purpose OverlayFS improvement** that benefits container image builds, atomic updates, and other overlay users — not just agent containment.

**Verdict:** The gap is **real but manageable** in userspace for typical workloads. A kernel OverlayFS change log is a worthwhile optimization to propose upstream, but the product does not depend on it.

### 3.2 Gap: Atomic Multi-File Commit

**The problem:** Merging the OverlayFS upper layer into the base filesystem from userspace (via rsync, cp, or manual file-by-file rename) is not atomic. If puzzled crashes mid-merge, the base filesystem contains a partial update.

**Severity assessment:**

- How often does puzzled crash during the commit operation? This is a window of typically 1-5 seconds for a 1,000-file changeset. If puzzled is well-tested and runs under systemd with watchdog, crashes during this specific window are rare.
- Partial commits are **detectable and recoverable** using a write-ahead journal:

```
Userspace journal-based commit:
  1. Freeze agent cgroup (cgroup.freeze → eliminate TOCTOU)
  2. Generate changeset manifest (list of files, checksums)
  3. Write manifest to journal file: /var/lib/agentfs/journal/{branch_id}.json
  4. For each file in manifest:
     a. Copy to staging directory: /var/lib/agentfs/staging/{branch_id}/
     b. fsync the staged file
  5. fsync the staging directory
  6. For each staged file:
     a. rename() from staging to base filesystem (atomic per-file)
  7. fsync the base directory
  8. Delete journal file (marks commit as complete)

On puzzled restart:
  1. Scan /var/lib/agentfs/journal/ for incomplete commits
  2. For each incomplete commit:
     a. If staging directory exists but rename is incomplete → roll back (delete staging)
     b. If rename completed but journal not deleted → delete journal (commit succeeded)
```

This is the same approach used by databases (SQLite, PostgreSQL) and package managers (RPM, dpkg) for crash-safe transactions. It is well-understood, well-tested, and entirely userspace.

**The PRD's kernel approach:** Uses `renameat2(RENAME_EXCHANGE)` for atomic file swap. But `renameat2` is also a **per-file** operation — it does not provide a multi-file atomic transaction. The kernel approach has the same per-file granularity as the userspace journal approach; it just keeps the journal in kernel memory rather than on disk.

**Verdict:** The gap is **addressable in userspace** with a write-ahead journal. The kernel approach is marginally more reliable (journal in kernel memory survives userspace crashes) but the practical difference is small given systemd restart guarantees.

### 3.3 Gap: Diff Performance at Scale

**The problem:** Walking the OverlayFS upper directory to compute a diff is O(n) in the total upper layer size (including copy-up artifacts), not O(changes). For branches with large upper layers (10,000+ files due to extensive copy-up from a large base filesystem), this can take seconds.

**Severity assessment:**

| Upper layer files | Estimated diff time (HDD) | Estimated diff time (SSD) |
|---|---|---|
| 100 | <100ms | <50ms |
| 1,000 | ~500ms | ~200ms |
| 10,000 | ~5s | ~1s |
| 100,000 | ~50s | ~10s |

For typical AI agent workloads (modifying 10-100 files in a project), the upper layer is small. The 10,000+ case arises only when agents touch files across a very large base filesystem, triggering widespread copy-up.

**Userspace mitigation:** Use fanotify (`FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME`) to maintain a real-time change set in the userspace daemon. This provides O(1) append per change and O(changes) diff generation. Caveats:
- fanotify cannot distinguish copy-up from agent writes (same limitation as upper-layer walk)
- fanotify does not capture mmap-based writes (requires `msync`)
- fanotify permission events (`FAN_OPEN_PERM`) are fail-open on daemon crash

**Kernel solution:** The OverlayFS change log described in 3.1 would provide O(changes) diff natively.

**Verdict:** For typical workloads (100-1,000 files), userspace diff is fast enough. For large-scale workloads, fanotify-based tracking provides O(changes) performance with known limitations. The kernel change log is a desirable optimization, not a requirement.

### 3.4 Gap: Zero-Residue Rollback on Daemon Crash

**The problem:** If puzzled crashes, the OverlayFS upper layer directory persists on disk until explicitly deleted. Empty cgroup directories may also persist.

**Severity assessment:**

The kernel already guarantees cleanup for 6 of 7 containment components on process death:

| Component | Auto-cleaned on process death? | Mechanism |
|---|---|---|
| PID namespace | Yes | Kernel destroys when last process exits |
| Mount namespace | Yes | Kernel destroys when last process exits |
| Network namespace | Yes | Kernel destroys when last reference is released |
| cgroup membership | Yes | Processes removed from cgroup on death |
| Seccomp-BPF | Yes | Per-process, freed with process |
| Landlock | Yes | Per-process, freed with process |
| **OverlayFS upper layer directory** | **No** | **Persists on disk — requires userspace cleanup** |

The one component that leaks (upper layer directory) can be cleaned up by:
- systemd `ExecStopPost=` in the puzzled service unit
- puzzled's startup scan (on restart, scan `/var/lib/agentfs/branches/` for orphaned upper layers and delete them)
- A periodic systemd timer (`agentfs-cleanup.timer`) as defense-in-depth

Empty cgroup scope directories (`/sys/fs/cgroup/puzzle.slice/agent-{id}.scope/`) persist but are harmless and are cleaned up by systemd's cgroup management.

**Verdict:** The gap is **real but trivially mitigable** with systemd integration. The orphaned upper layer is detectable (it has a known path pattern) and safe to delete (it was never committed to the base filesystem).

### 3.5 Summary of Gaps

| Gap | Severity | Kernel modification justified? | Userspace mitigation |
|---|---|---|---|
| Copy-up pollution in diff | Low-medium | **No** (for typical workloads) | Checksum comparison to filter copy-ups |
| Non-atomic multi-file commit | Medium | **No** | Write-ahead journal (same approach as databases) |
| O(n) diff at scale | Low (typical workloads) to Medium (large upper layers) | **Maybe** (as upstream OverlayFS improvement) | fanotify real-time tracking |
| Orphaned upper layer on crash | Low | **No** | systemd cleanup + startup scan |
| Unified lifecycle fd | Low-medium (convenience) | **No** | pidfd + cgroup events + inotify |

---

## 4. Component-by-Component Analysis

### 4.1 AgentGuard LSM → Not Recommended for Kernel

The PRD proposes a new stackable LSM for per-agent-instance access control with path-based ACLs, quantitative limits, and BPF-accelerated lookups.

**Existing primitives that cover this:**

| AgentGuard Feature | Existing Primitive | Coverage |
|---|---|---|
| Path-based filesystem ACL | **Landlock** (hierarchy-based, irrevocable, unprivileged) | 90% — lacks glob patterns but hierarchy-based rules cover most cases |
| Exec allowlisting | **Landlock** `EXECUTE` per directory + **seccomp-BPF** | 95% |
| TCP port restrictions | **Landlock** ABI v4 `CONNECT_TCP` / `BIND_TCP` | 100% for TCP; no UDP coverage |
| Quantitative limits (exec count) | **BPF LSM** on `bprm_check_security` with per-cgroup counter | 100% |
| Quantitative limits (file count) | **XFS project quotas** ihard limit | 100% |
| Quantitative limits (byte count) | **XFS project quotas** bhard limit | 100% |
| Rate limiting | **BPF LSM** with token bucket in BPF map | 90% |
| Branch-aware policy | Not needed if policy is userspace-driven — puzzled configures per-branch Landlock/BPF | N/A |
| Dynamic policy updates | BPF map updates (hot-swappable) + Landlock stacking (up to 16 layers) | 80% |
| Signal scoping | **Landlock** ABI v6 `SCOPE_SIGNAL` | 100% (kernel 6.12+) |
| Abstract Unix socket scoping | **Landlock** ABI v6 `SCOPE_ABSTRACT_UNIX_SOCKET` | 100% (kernel 6.12+) |

**What AgentGuard adds over the existing stack:** Glob pattern matching (e.g., `/home/*/project/**/*.py`). Landlock uses hierarchy-based rules (`/home/user/project/` and everything underneath), not glob patterns. For most agent containment scenarios, hierarchy-based rules are sufficient (agents operate within a project directory). Glob patterns are a convenience feature, not a security requirement.

**Recommendation:** Do not build a new LSM. Use Landlock + BPF LSM + SELinux. If glob pattern matching is needed, implement it in the BPF LSM program (compile patterns to a trie in a BPF map, as the PRD already describes). This uses existing kernel infrastructure without new kernel modules.

**Upstream risk avoided:** A new LSM faces years of kernel community review, requires LSM stacking (which itself has been contentious), and must demonstrate that existing LSMs are insufficient. This is a very high bar.

### 4.2 Agent cgroup v2 Controller → Not Recommended for Kernel

The PRD proposes a new `agent` cgroup v2 controller with agent-specific knobs: `agent.branch_storage_max`, `agent.branch_lifetime_max_us`, `agent.exec_count`, `agent.network_egress_bytes`.

**Existing primitives that cover this:**

| Agent cgroup Feature | Existing Primitive | Coverage |
|---|---|---|
| Storage bytes limit | **XFS project quotas** bhard | 100% — VFS-level enforcement, `write()` returns ENOSPC |
| Inode count limit | **XFS project quotas** ihard | 100% |
| CPU / memory / IO limits | **cgroups v2** cpu, memory, io controllers | 100% |
| PID limit | **cgroups v2** pids controller | 100% |
| Branch lifetime | **systemd** `RuntimeMaxSec=` on agent scope unit | 100% — SIGTERM then SIGKILL on timeout |
| Exec count | **BPF LSM** on `bprm_check_security` | 100% |
| Network egress bytes | **nftables** byte counters or **eBPF** on `cgroup/sendmsg` | 95% |
| Branch-scoped OOM | **cgroups v2** memory controller + `memory.oom.group` | 90% — kills all processes in cgroup on OOM |

**What the agent cgroup controller adds:** A unified interface (`agent.*` files in the cgroup filesystem) instead of separate XFS quota commands, BPF map updates, and systemd unit settings. This is an **operational convenience**, not a capability gap.

**Recommendation:** Do not build a new cgroup controller. Use existing controllers + XFS quotas + BPF LSM. Provide a unified API through `puzzled`'s D-Bus interface and `puzzlectl` CLI that abstracts over the underlying mechanisms. The user experience is the same; the implementation avoids kernel changes.

**Upstream risk avoided:** New cgroup controllers require extensive discussion with the cgroup maintainer (Tejun Heo) and must demonstrate that the functionality cannot be achieved with existing controllers. Agent-specific knobs are unlikely to meet this bar.

### 4.3 Branch Context syscall → Not Recommended for Kernel

The PRD proposes `branch_context_create()`, a new system call that atomically creates PID ns + mount ns + net ns + cgroup + seccomp + Landlock + OverlayFS overlay, returning a single fd.

**Existing primitives that provide equivalent functionality:**

```
Userspace equivalent using clone3() + existing primitives:

1. puzzled calls clone3() with CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_PIDFD
   → Kernel atomically creates PID ns + mount ns + net ns
   → Returns pidfd for the new process

2. In the child process (before execve):
   a. Set up OverlayFS mount (mount -t overlay)
   b. Set up cgroup scope (mkdir + echo $$ > cgroup.procs)
   c. Apply Landlock ruleset (landlock_restrict_self)
   d. Apply seccomp-BPF filter (prctl + seccomp)
   e. Drop all capabilities
   f. PR_SET_NO_NEW_PRIVS
   g. execve the agent binary

3. puzzled holds the pidfd for lifecycle management:
   - poll(pidfd) → notification on agent exit
   - pidfd_send_signal(pidfd, SIGTERM) → graceful shutdown
   - Killing PID 1 of PID namespace → kernel kills all namespace members
```

**What `branch_context_create()` adds over `clone3()`:**

1. **Atomic unwinding on partial setup failure.** If step 2c fails in the userspace approach, steps 2a-2b must be manually unwound. With `branch_context_create()`, the kernel unwinds everything. However, the userspace approach is simple enough that manual unwinding is reliable — it's just `umount` + `rmdir`.

2. **Single-fd lifecycle.** `branch_context_create()` returns one fd that represents everything; `close(fd)` tears down everything. The userspace approach requires tracking pidfd + cgroup path + OverlayFS mount. However, puzzled maintains a `BranchState` struct per agent that tracks all of these — the code complexity is comparable.

3. **ioctl-based inspection.** `BRANCH_IOC_INSPECT` and `BRANCH_IOC_COMMIT` provide inspection and commit operations through the context fd. In the userspace approach, these are puzzled D-Bus methods or puzzlectl CLI commands — functionally equivalent.

**Recommendation:** Do not introduce a new system call. Use `clone3()` + pidfd + existing namespace/cgroup APIs. The operational complexity of managing multiple resources per agent is well-handled by container runtimes (crun already does this for every container it creates).

**Upstream risk avoided:** New system calls are among the hardest kernel changes to upstream. They must maintain backward compatibility forever, require exhaustive security review, and face the question "why can't you do this with existing calls?" — which, as shown above, you can.

### 4.4 AgentFS (Transactional Filesystem) → Narrow Kernel Enhancement May Be Justified

This is the one area where kernel work has merit — but the scope should be much narrower than the PRD proposes.

**What OverlayFS provides today:**
- CoW filesystem branching (agent writes go to upper layer) ✓
- Rollback by discarding upper layer ✓
- Isolation via mount namespace ✓
- Storage quotas via XFS project quotas ✓

**What OverlayFS lacks:**
- A kernel-maintained log of which files were **intentionally modified** (vs. copy-up artifacts)
- This is the genuine gap that userspace cannot fully bridge

**Proposed narrow kernel enhancement:**

Instead of a full AgentFS kernel module (the PRD describes thousands of lines of new kernel code), propose a focused **OverlayFS change log** feature:

```c
/*
 * Proposed OverlayFS enhancement: OVL_IOC_GET_CHANGES
 *
 * Returns a list of inodes in the upper layer that were modified by
 * userspace write operations (as distinct from kernel copy-up operations).
 *
 * This is implemented by setting an xattr (trusted.overlay.user_modified)
 * on files in the upper layer when they are first written to by a
 * userspace process after copy-up. The ioctl walks the upper layer
 * returning only files with this xattr set.
 *
 * This benefits all OverlayFS users (container image builders, atomic
 * updates, ostree) — not just agent containment.
 */
#define OVL_IOC_GET_CHANGES  _IOR('o', 1, struct ovl_changes)
```

**Why this narrow approach works:**

1. **General-purpose.** It benefits all OverlayFS users, not just agent containment. This dramatically improves upstream acceptance odds.
2. **Small patch.** Adding an xattr during write operations in the overlay VFS layer and an ioctl to query it is ~200-500 lines of code — reviewable in a single patch series.
3. **Non-breaking.** It adds a new ioctl to an existing filesystem; it does not change existing behavior.
4. **Independent of the rest of the product.** If the patch is rejected upstream, the userspace fallback (checksum-based diff) continues to work.

**Recommendation:** Propose this as an OverlayFS improvement to linux-unionfs@vger.kernel.org, framing it as a general-purpose feature for container image provenance and filesystem auditing. Do not frame it as an "agent containment" feature — the kernel community responds better to general-purpose infrastructure than to application-specific additions.

### 4.5 Network Side-Effect Gating → Userspace Proxy Preferred

The PRD proposes eBPF-based HTTP method inspection (allowing GET/HEAD, queuing POST/PUT/DELETE for commit-time replay).

**A userspace HTTP proxy is superior to eBPF for this purpose:**

| Concern | eBPF approach | Userspace proxy |
|---|---|---|
| TLS traffic | Cannot inspect (encrypted) | Can inspect via MITM with agent trust store |
| HTTP/2 | Very difficult to parse in BPF | Standard library support |
| Request queuing | Must serialize to disk from eBPF | Native application logic |
| Request replay | Requires separate replay daemon | Same proxy replays |
| Complexity | BPF verifier constraints, limited string ops | Standard Rust async code |
| Debugging | BPF debugging is difficult | Standard logging, tracing |

**Implementation:** Run a lightweight HTTP proxy (e.g., based on `hyper` in Rust) inside the agent's network namespace, configured as the HTTP_PROXY/HTTPS_PROXY environment variable. The proxy allows read operations (GET, HEAD, OPTIONS) immediately and queues write operations (POST, PUT, DELETE, PATCH) for commit-time replay by puzzled.

For non-HTTP traffic, use nftables rules in the network namespace to allow/deny at L3/L4.

**Recommendation:** Implement network side-effect gating as a userspace proxy. No kernel changes needed.

---

## 5. The Upstream Acceptance Reality

Even if kernel extensions were justified on technical merits, the upstream acceptance path must be realistic.

### 5.1 Upstream Acceptance by Component

| Component | Upstream Likelihood | Timeline | Rationale |
|---|---|---|---|
| New LSM (AgentGuard) | **Very Low** | 3-5 years | LSM stacking has been contentious for 15+ years. Adding a new LSM on top of that is an enormous political and technical lift. The kernel community would ask: "Why not Landlock + BPF LSM?" |
| New cgroup controller | **Low** | 2-3 years | Tejun Heo (cgroup maintainer) has consistently pushed back on new controllers unless existing controllers are demonstrably insufficient. XFS quotas + BPF LSM cover the use cases. |
| New syscall | **Low** | 2-3 years | New syscalls are permanent API. The bar is extremely high. "You can achieve this with clone3() + existing APIs" is a likely response. |
| OverlayFS change log | **Medium-High** | 6-12 months | Small, focused patch. Benefits all overlay users. Miklos Szeredi (OverlayFS maintainer) has been receptive to well-motivated enhancements. |
| eBPF programs (not modifications) | **N/A** (no changes needed) | Immediate | BPF LSM programs are loaded at runtime. No kernel code changes required. |

### 5.2 Risk of Out-of-Tree Maintenance

If patches are not accepted upstream, maintaining them out-of-tree has significant costs:

- **Rebase cost:** Every kernel version bump requires rebasing patches. For a full subsystem (AgentFS + AgentGuard + agent cgroup + Branch Context), this is estimated at 2-4 engineer-weeks per kernel release cycle.
- **Security burden:** Out-of-tree kernel code does not receive the same community review. Security vulnerabilities in custom kernel modules are our responsibility alone.
- **Customer friction:** Enterprises are reluctant to deploy custom kernels. RHEL's value proposition includes a supported, tested kernel. Custom modules undermine this.
- **DKMS fragility:** DKMS-based distribution of out-of-tree modules is fragile, especially across major kernel version boundaries.

### 5.3 The QM Precedent

The QM (Quality Management) partition for automotive workloads demonstrates that significant containment can be achieved without kernel modifications. QM uses:
- Podman with custom seccomp, SELinux, and cgroup profiles
- Separate network namespaces per partition
- systemd slice configuration for resource isolation
- blkio/io cgroup controls for I/O isolation

QM does not modify the kernel. It composes existing primitives. This is the same approach recommended here.

---

## 6. Recommended Architecture

### 6.1 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        USERSPACE                                │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   puzzled (Rust, runs as root)            │   │
│  │                                                          │   │
│  │  ┌──────────────┐ ┌──────────────┐ ┌─────────────────┐  │   │
│  │  │  Lifecycle    │ │  Governance  │ │   Telemetry     │  │   │
│  │  │  Manager     │ │  Engine      │ │   Collector     │  │   │
│  │  │              │ │  (OPA/Rego)  │ │   (eBPF +       │  │   │
│  │  │ - clone3()   │ │              │ │    fanotify +   │  │   │
│  │  │ - pidfd      │ │ - Commit     │ │    cgroup stats)│  │   │
│  │  │ - cgroup mgmt│ │   review    │ │                 │  │   │
│  │  │ - overlay    │ │ - Policy     │ │                 │  │   │
│  │  │   setup      │ │   profiles  │ │                 │  │   │
│  │  └──────────────┘ └──────────────┘ └─────────────────┘  │   │
│  │                                                          │   │
│  │  ┌──────────────┐ ┌──────────────┐ ┌─────────────────┐  │   │
│  │  │  HTTP Proxy  │ │  Diff Engine │ │   Audit/IMA     │  │   │
│  │  │  (per-agent  │ │  (upper layer│ │   (changeset    │  │   │
│  │  │   network ns)│ │   walk +     │ │    signing)     │  │   │
│  │  │              │ │   checksum   │ │                 │  │   │
│  │  │  GET: allow  │ │   filter)    │ │                 │  │   │
│  │  │  POST: queue │ │              │ │                 │  │   │
│  │  └──────────────┘ └──────────────┘ └─────────────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌────────────┐   │
│  │ Agent A   │  │ Agent B   │  │ Agent C   │  │ puzzlectl   │   │
│  │ (PID ns + │  │ (PID ns + │  │ (PID ns + │  │ (CLI)      │   │
│  │  mount ns │  │  mount ns │  │  mount ns │  │            │   │
│  │  + net ns │  │  + net ns │  │  + net ns │  │            │   │
│  │  + cgroup │  │  + cgroup │  │  + cgroup │  │            │   │
│  │  + seccomp│  │  + seccomp│  │  + seccomp│  │            │   │
│  │  + landl.)│  │  + landl.)│  │  + landl.)│  │            │   │
│  └───────────┘  └───────────┘  └───────────┘  └────────────┘   │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                    EXISTING KERNEL (unmodified)                  │
│                                                                 │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────────┐ ┌───────┐  │
│  │Namespaces│ │cgroups  │ │ seccomp │ │ Landlock  │ │SELinux│  │
│  │(PID,mnt, │ │  v2     │ │  BPF    │ │(ABI v4-v6)│ │      │  │
│  │ net,user)│ │         │ │         │ │           │ │      │  │
│  └─────────┘ └─────────┘ └─────────┘ └───────────┘ └───────┘  │
│                                                                 │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────────┐ ┌───────┐  │
│  │OverlayFS│ │  BPF    │ │ pidfd   │ │ nftables  │ │ XFS   │  │
│  │         │ │  LSM    │ │         │ │           │ │project│  │
│  │         │ │         │ │         │ │           │ │quotas │  │
│  └─────────┘ └─────────┘ └─────────┘ └───────────┘ └───────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Linux Audit + IMA + fanotify                 │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │           Base Filesystem (XFS / ext4 / Btrfs)            │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 What Stays in the Kernel

**Nothing new.** All kernel functionality uses existing, unmodified primitives:

| Kernel Primitive | Used For |
|---|---|
| PID namespace | Process containment, reliable termination |
| Mount namespace | OverlayFS isolation, path masking |
| Network namespace | Network isolation per agent |
| cgroups v2 (cpu, memory, io, pids) | Resource limits |
| OverlayFS | CoW filesystem branching |
| Seccomp-BPF | Syscall filtering |
| Landlock (ABI v4-v6) | Irrevocable filesystem + network ACL |
| SELinux | Label-based MAC |
| BPF LSM | Programmable access control hooks (exec counting, rate limiting) |
| XFS project quotas | Per-branch storage and inode limits |
| pidfd | Race-free process lifecycle management |
| nftables | L3/L4 network filtering per agent namespace |
| fanotify | Real-time file change monitoring |
| Linux Audit + IMA | Audit trail + cryptographic signing |

### 6.3 What Moves to Userspace

| PRD Component | Userspace Implementation |
|---|---|
| AgentFS transactional commit | Write-ahead journal in puzzled; OverlayFS upper layer merge with crash recovery |
| AgentFS change tracking | fanotify-based + upper-layer walk with checksum filtering |
| AgentFS conflict detection | puzzled maintains per-branch change sets; conflicts detected at commit time by comparing sets |
| AgentFS quota enforcement | XFS project quotas (byte + inode); systemd RuntimeMaxSec (lifetime) |
| AgentGuard access control | Landlock ruleset + BPF LSM programs + SELinux policy |
| Agent cgroup controller | Existing cgroup controllers + XFS quotas + BPF LSM |
| Branch Context lifecycle | clone3() + pidfd + puzzled struct tracking all per-agent resources |
| Network side-effect gating | Userspace HTTP proxy in agent's network namespace + nftables |
| Governance evaluation | OPA/Rego in puzzled (already userspace in the PRD) |

### 6.4 Optional Kernel Enhancement (Propose Upstream Separately)

**OverlayFS Change Log:** A small kernel patch (~200-500 LOC) that marks files in the upper layer that were modified by userspace (as distinct from copy-up). Proposed as a general-purpose OverlayFS improvement, not an agent-specific feature.

- **Framing:** "Enable OverlayFS users to efficiently identify which files in the upper layer were intentionally modified, supporting container image provenance, atomic update verification, and filesystem auditing."
- **Target:** linux-unionfs@vger.kernel.org, cc Miklos Szeredi
- **Timeline:** Propose after Phase 0 validates the gap with empirical data
- **Fallback:** If rejected, continue using checksum-based diff in userspace

---

## 7. What This Means for the PRD

If this architectural decision is adopted, the PRD should be revised:

| PRD Section | Change |
|---|---|
| Section 5 (Architecture) | Update diagram to show unmodified kernel; all new code in userspace |
| Section 6 (Branch Context) | Reframe as puzzled lifecycle management design using clone3() + pidfd; remove syscall proposal |
| Section 7 (AgentFS) | Reframe as puzzled transactional filesystem design using OverlayFS + WAL; kernel change log as optional enhancement |
| Section 8 (AgentGuard) | Reframe as agent containment profile design using Landlock + BPF LSM + SELinux |
| Section 9 (Agent cgroups) | Reframe as agent resource management using existing cgroup controllers + XFS quotas |
| Section 10 (Network Gating) | Reframe as userspace HTTP proxy + nftables |
| Section 20 (Phased Plan) | Phase 0 becomes the core product; Phase 1+ becomes optional kernel optimization |
| Section 22 (Language) | Kernel Rust no longer needed if no kernel modules; pure Rust userspace |

### 7.1 What This Does NOT Change

- The core **Fork, Explore, Commit** model — this is the product's differentiation
- The **governance gate** — OPA/Rego policy evaluation before commit
- The **audit trail** — IMA-signed changeset manifests
- The **defense-in-depth** security model — Landlock + BPF LSM + SELinux + seccomp + namespaces
- The **edge device** target — existing kernel primitives work on 4GB ARM64
- The **safety certification** path — existing kernel primitives have deterministic behavior

### 7.2 What This Improves

- **Time to market:** No kernel development, no upstream review, no DKMS packaging
- **Deployability:** Runs on stock RHEL 10 kernels. No kernel rebuild for customers
- **Maintainability:** No kernel module rebase on every kernel update
- **Security posture:** Using audited, upstream kernel primitives instead of custom kernel code
- **Credibility:** Demonstrates that we understand the kernel well enough to know when NOT to modify it

---

## 8. Risk Analysis

### 8.1 Risk: Userspace Approach Is Insufficient

**Mitigation:** Phase 0 (months 1-3) empirically validates the approach with real agent workloads. Specific gap tests measure diff performance, commit atomicity, and crash resilience. If the gaps are severe, narrow kernel enhancements are proposed with empirical evidence.

### 8.2 Risk: Competitor Ships Kernel-Level Solution First

**Mitigation:** There is no evidence of any competitor pursuing kernel-level agent containment. The AI agent sandboxing space (E2B, Daytona, Firecracker) focuses on VM-level or container-level isolation — both userspace approaches. If a competitor does propose kernel changes, they face the same upstream acceptance challenges.

### 8.3 Risk: "Just Podman With Extra Steps" Perception

**Mitigation:** The product differentiation is the **transactional execution model** (Fork, Explore, Commit) and the **governance gate** — not the containment mechanism. Podman provides containment; puzzled provides transactional semantics and governance. These are distinct value propositions that happen to use the same kernel primitives.

### 8.4 Risk: Safety Certification Requires Custom Kernel

**Mitigation:** Safety certification (IEC 61508, ISO 26262) certifies a **specific configuration** of a system, not specific custom code. A certified configuration using standard kernel primitives (namespaces, cgroups, seccomp) is actually easier to certify than one with custom kernel modules — because the kernel primitives have existing usage history, test coverage, and community review that certification bodies value.

---

## 9. Decision Framework

Use the following criteria to make the architectural decision:

| Criterion | Kernel Modification | Userspace Only |
|---|---|---|
| Deploys on stock RHEL 10 kernel | No | **Yes** |
| Upstream acceptance required | Yes (high risk, multi-year) | **No** |
| Time to first customer deployment | 12-18 months (kernel cycle) | **3-6 months** |
| Security depends on custom kernel code | Yes (increased attack surface) | **No** (uses audited upstream code) |
| Transactional FS: diff accuracy | Better (kernel change log) | Good (checksum filtering, ~5-15% false positives) |
| Transactional FS: commit atomicity | Marginally better (kernel journal) | Good (userspace WAL, same approach as databases) |
| Transactional FS: crash resilience | Stronger (kernel fd cleanup) | Good (systemd cleanup + startup scan) |
| Maintenance cost per kernel release | 2-4 engineer-weeks rebase | **None** |
| Safety certification complexity | Higher (certify custom modules) | **Lower** (certify configuration of standard kernel) |
| Product differentiation source | Kernel technology | **Governance model + transactional semantics** |

---

## 10. Conclusion

The strongest argument for kernel modifications is transactional filesystem efficiency — and even that gap is manageable in userspace. The strongest arguments against kernel modifications are upstream acceptance risk, maintenance cost, deployment friction, and the fact that the product's true differentiation (governance-gated transactional execution) is inherently a userspace concern.

**The kernel already provides comprehensive enforcement primitives. What is missing is not enforcement — it is the orchestration, governance, and transactional semantics that compose those primitives into an agent execution environment. That is a userspace problem.**

The recommended path is:

1. **Build puzzled as a userspace daemon** that composes existing kernel primitives into agent containment profiles with transactional filesystem semantics.
2. **Ship on stock RHEL 10 kernels** with zero kernel modifications.
3. **Propose a narrow OverlayFS change log enhancement** upstream after empirical validation, framed as a general-purpose feature.
4. **If the OverlayFS patch is accepted**, use it to improve diff accuracy. **If rejected**, continue with the checksum-based approach.

This is not a compromise. This is the correct architecture. The kernel is excellent at enforcement; it already provides the enforcement we need. Our innovation is in the governance and transactional model that sits on top of it.
