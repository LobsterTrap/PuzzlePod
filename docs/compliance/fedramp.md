# PuzzlePod -- FedRAMP / NIST 800-53 Control Mapping

This document maps NIST SP 800-53 Rev. 5 security controls to PuzzlePod features that implement or support each control. NIST 800-53 is the control framework underlying FedRAMP authorization. Controls are organized by family.

---

## Access Control (AC)

| Control | Title | PuzzlePod Implementation |
|---|---|---|
| AC-1 | Policy and Procedures | Agent profiles (YAML) define per-agent access policy. Profiles validated against JSON schema. Four-phase migration path provides procedural adoption framework. |
| AC-2 | Account Management | Agents are registered via D-Bus API with assigned profiles. `puzzlectl agent list` enumerates active agents. `puzzlectl agent kill` terminates agents. Agent lifecycle events logged to audit. |
| AC-3 | Access Enforcement | Landlock LSM enforces filesystem ACL (irrevocable, kernel-enforced). seccomp-BPF enforces syscall restrictions. SELinux type enforcement confines agents to `puzzlepod_agent_t` domain. All enforcement survives `puzzled` crash. |
| AC-4 | Information Flow Enforcement | Network namespace isolation prevents cross-agent network communication. PID namespace prevents cross-agent process signaling. OverlayFS branches provide per-agent filesystem isolation. HTTP proxy gates outbound data flow (POST/PUT/DELETE queued). |
| AC-5 | Separation of Duties | Agent profiles separate access scopes: restricted (no network, narrow FS), standard (gated network, project-scoped FS), privileged (monitored network, broad FS). Profile assignment is an administrative action. |
| AC-6 | Least Privilege | Agents run with no Linux capabilities. Landlock restricts filesystem access to minimum required paths. seccomp limits syscall surface. exec_allowlist restricts executable binaries. Resource limits (cgroups, XFS quotas) bound consumption. |
| AC-6(1) | Least Privilege: Authorize Access to Security Functions | `puzzled` is the only process with privileges to create namespaces, configure cgroups, and manage branches. Agents cannot access security functions. SELinux neverallow rules prevent agents from modifying policy. |
| AC-6(9) | Least Privilege: Log Use of Privileged Functions | All `puzzled` administrative actions (branch create, commit, rollback, policy reload) logged to Linux Audit. seccomp USER_NOTIF decisions (allow/deny execve, connect) logged per invocation. |
| AC-6(10) | Least Privilege: Prohibit Non-Privileged Users from Executing Privileged Functions | seccomp static deny blocks escape-vector syscalls (ptrace, mount, setns, kexec_load, init_module). Agents have no capabilities. SELinux neverallow prevents domain transition. |
| AC-17 | Remote Access | Network namespace isolation restricts agent network access. Three modes: Blocked (no network), Gated (proxy-mediated), Monitored (logged). Domain allowlists restrict endpoints. |
| AC-24 | Access Control Decisions | OPA/Rego governance policies evaluate changeset at commit time. Deterministic evaluation (no ML/heuristics). Policy violations include rule name, message, and severity. |

---

## Audit and Accountability (AU)

| Control | Title | PuzzlePod Implementation |
|---|---|---|
| AU-2 | Event Logging | Linux Audit subsystem records: branch creation, commit, rollback, agent kill, policy violation, behavioral trigger, seccomp notification, SELinux denial. |
| AU-3 | Content of Audit Records | Audit events include: timestamp, branch ID, agent ID, profile, action, result, changeset manifest (for commits), violation details (for rejections). |
| AU-3(1) | Content of Audit Records: Additional Audit Information | IMA-signed changeset manifests include file-level checksums, sizes, and modification types. fanotify event counters record per-branch file operation statistics. |
| AU-6 | Audit Record Review, Analysis, and Reporting | `puzzlectl audit list` queries audit events by time range, branch, or event type. `puzzlectl audit export --format json` produces machine-parseable output for SIEM integration. |
| AU-7 | Audit Record Reduction and Report Generation | `puzzlectl audit export` supports filtering by branch, time range, severity, and event type. JSON output enables integration with log aggregation and analytics platforms. |
| AU-8 | Time Stamps | Audit events use system clock. IMA manifests include signed timestamps. WAL entries include monotonic and wall-clock timestamps. |
| AU-9 | Protection of Audit Information | Audit trail stored via Linux Audit subsystem (protected by auditd). IMA-signed manifests provide tamper evidence. `puzzled` audit directory protected by SELinux type (`puzzlepod_branch_t`). |
| AU-10 | Non-Repudiation | IMA-signed changeset manifests provide cryptographic non-repudiation. Each commit is signed with the IMA key. `puzzlectl audit verify` validates manifest signatures. |
| AU-11 | Audit Record Retention | Audit retention follows system auditd configuration. IMA manifests stored in `/var/lib/puzzled/audit/` with configurable retention. |
| AU-12 | Audit Record Generation | Audit events generated automatically by `puzzled` for all security-relevant actions. No agent involvement in audit generation. Audit cannot be disabled by agents. |

---

## Configuration Management (CM)

| Control | Title | PuzzlePod Implementation |
|---|---|---|
| CM-2 | Baseline Configuration | Agent profiles define baseline access configuration. `puzzled.conf` defines system-level baseline. Default profiles (restricted, standard, privileged) provide tested baselines. |
| CM-3 | Configuration Change Control | Profile changes validated against JSON schema. Policy changes tested via `puzzlectl policy test`. Four-phase migration path (Monitor -> Audit -> Enforce -> Full) provides controlled rollout. |
| CM-5 | Access Restrictions for Change | Only root or `puzzled` group members can modify profiles and policies. SELinux restricts write access to configuration directories. Agent processes cannot modify their own profiles. |
| CM-6 | Configuration Settings | `puzzled.conf` documents all configuration fields. Profiles define per-agent settings. JSON schema enforces valid configuration. Default values follow least-privilege principle. |
| CM-7 | Least Functionality | seccomp-BPF limits agent syscall surface to required syscalls only. exec_allowlist restricts executable binaries. Network mode defaults to Blocked. Profiles can be narrowed for specific workloads. |
| CM-7(1) | Least Functionality: Periodic Review | `puzzlectl profile list` and `puzzlectl profile show` enable review of active profiles. Audit trail provides evidence of profile usage patterns. Behavioral monitoring identifies unused or over-broad permissions. |

---

## Identification and Authentication (IA)

| Control | Title | PuzzlePod Implementation |
|---|---|---|
| IA-2 | Identification and Authentication | Agents identified by agent_id assigned at branch creation. D-Bus authentication identifies the calling process. POSIX UID-based identity for multi-tenancy. |
| IA-4 | Identifier Management | Agent IDs are unique, system-generated UUIDs. Branch IDs are unique across the system. `puzzlectl agent list` enumerates all active identifiers. |
| IA-9 | Service Identification and Authentication | `puzzled` authenticates to D-Bus via system bus credentials. D-Bus policy restricts method access to authorized users (root, `puzzled` group). |

---

## Incident Response (IR)

| Control | Title | PuzzlePod Implementation |
|---|---|---|
| IR-4 | Incident Handling | Automatic rollback on governance failure (fail-closed). Agent termination via PID namespace kill. `puzzlectl agent kill` for manual intervention. Branch rollback removes all changes with zero residue. |
| IR-5 | Incident Monitoring | fanotify behavioral triggers detect anomalous patterns (mass deletion, credential access). Prometheus metrics enable threshold-based alerting. D-Bus signals notify subscribers of policy violations and behavioral triggers. |
| IR-6 | Incident Reporting | `puzzlectl audit export` produces structured incident data. IMA-signed manifests provide forensic evidence. Audit events include full changeset details for committed branches. |

---

## System and Communications Protection (SC)

| Control | Title | PuzzlePod Implementation |
|---|---|---|
| SC-2 | Separation of Application Functionality and Security Management | Kernel enforces security (Landlock, seccomp, namespaces, cgroups, SELinux). Userspace decides policy (OPA/Rego, profiles). Agent processes cannot modify their own security configuration. |
| SC-3 | Security Function Isolation | `puzzled` runs in its own SELinux domain (`puzzlepod_t`). Agent processes run in `puzzlepod_agent_t` domain. Neverallow rules prevent cross-domain access. `puzzled` is seccomp-filtered with 57 blocked escape-vector syscalls + 4 USER_NOTIF-gated syscalls (58 on x86_64). |
| SC-4 | Information in Shared System Resources | OverlayFS branches provide per-agent filesystem isolation. PID namespaces prevent cross-agent process visibility. Network namespaces prevent cross-agent network communication. cgroup isolation prevents cross-agent resource interference. |
| SC-7 | Boundary Protection | Network namespace provides network boundary per agent. nftables rules enforce boundary policy. HTTP proxy mediates external communication. Domain allowlists restrict reachable endpoints. |
| SC-7(5) | Boundary Protection: Deny by Default | Network mode defaults to Blocked (no external access). Landlock denies all filesystem access not explicitly allowed. seccomp denies escape-vector syscalls. Fail-closed governance denies commits on any policy failure. |
| SC-8 | Transmission Confidentiality and Integrity | IMA-signed changeset manifests ensure integrity of committed data. HTTP proxy can enforce TLS for outbound connections. Network gating prevents unauthorized data transmission. |
| SC-13 | Cryptographic Protection | IMA manifest signing uses kernel keyring cryptographic keys. SHA-256 checksums on all changeset files. WAL entries include checksums for crash recovery verification. |
| SC-28 | Protection of Information at Rest | OverlayFS upper layers stored on XFS with project quotas. Branch data protected by filesystem permissions and SELinux labeling (`puzzlepod_branch_t`). Rollback destroys upper layer data completely. |
| SC-39 | Process Isolation | PID namespace provides process isolation (kernel-enforced). Mount namespace provides filesystem view isolation. Network namespace provides network stack isolation. cgroup provides resource isolation. Each agent is isolated from all other agents and from the host. |

---

## System and Information Integrity (SI)

| Control | Title | PuzzlePod Implementation |
|---|---|---|
| SI-3 | Malicious Code Protection | Governance policies detect persistence mechanisms (cron jobs, systemd units), sensitive files in changesets, and executable permission changes. seccomp exec gating prevents execution of unauthorized binaries. |
| SI-4 | System Monitoring | fanotify monitors file access patterns. BPF LSM monitors exec calls and rate limits. cgroup monitoring detects resource pressure. Prometheus metrics provide real-time system-level monitoring. |
| SI-4(2) | System Monitoring: Automated Tools and Mechanisms for Real-Time Analysis | Behavioral triggers provide real-time anomaly detection (mass deletion, excessive reads, credential access). D-Bus signals enable real-time notification. Prometheus metrics enable real-time dashboard and alerting. |
| SI-5 | Security Alerts, Advisories, and Directives | D-Bus signals (`PolicyViolation`, `BehavioralTrigger`) provide real-time security alerts. `puzzlectl audit list` surfaces security events. Prometheus alerting integrates with existing notification infrastructure. |
| SI-7 | Software, Firmware, and Information Integrity | IMA integration verifies integrity of committed changesets. SHA-256 checksums on all files in changeset manifests. Governance policy detects unauthorized system file modifications (`/usr/bin/`, `/boot/`, `/lib/modules/`). |
| SI-10 | Information Input Validation | Profile validation against JSON schema. OPA/Rego policy input validated (changeset manifest format). D-Bus method parameters validated by `zbus` type system. |
| SI-16 | Memory Protection | seccomp-BPF restricts syscall surface. No capabilities granted to agent processes. SELinux `execmem` control restricts executable memory mapping. ASLR and other kernel memory protections apply to agent processes. |

---

## Planning (PL)

| Control | Title | PuzzlePod Implementation |
|---|---|---|
| PL-8 | Security and Privacy Architectures | Defense-in-depth architecture documented with eight independent kernel-enforced layers. Threat model with seven threat actors and risk assessment matrix. Residual risk analysis with explicit acknowledgment of unmitigated risks. |

---

## Risk Assessment (RA)

| Control | Title | PuzzlePod Implementation |
|---|---|---|
| RA-3 | Risk Assessment | Threat model (T1-T7) with risk assessment matrix covering likelihood, impact, and risk rating. Kill chain analysis for seven attack scenarios. Residual risk table with mitigation ceiling analysis. |
| RA-5 | Vulnerability Monitoring and Scanning | Security test suite (`tests/security/`) covers escape testing, privilege escalation, policy bypass, and namespace escape. Performance benchmarks measure enforcement overhead. |

---

## Summary

PuzzlePod provides strong technical controls for the following NIST 800-53 families:

- **AC (Access Control):** Kernel-enforced least privilege via Landlock, seccomp, namespaces, and cgroups
- **AU (Audit):** Comprehensive audit trail with IMA-signed manifests and non-repudiation
- **SC (System and Communications Protection):** Process isolation, boundary protection, and cryptographic integrity
- **SI (System and Information Integrity):** Real-time behavioral monitoring, governance-gated commits, and IMA integrity verification
- **CM (Configuration Management):** Declarative profiles, schema validation, and phased migration

Organizational controls (PL, RA, IR planning and procedures) remain the responsibility of the deploying organization. PuzzlePod provides the enforcement mechanisms and audit evidence that those controls depend upon.
