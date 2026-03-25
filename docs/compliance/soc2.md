# PuzzlePod -- SOC 2 Type II Control Mapping

This document maps SOC 2 Type II Trust Services Criteria to PuzzlePod features that implement or support each control. SOC 2 is organized around five Trust Services Categories: Security, Availability, Processing Integrity, Confidentiality, and Privacy.

---

## Security (Common Criteria)

| Control ID | Control Description | PuzzlePod Implementation |
|---|---|---|
| CC1.1 | The entity demonstrates a commitment to integrity and ethical values | Agent governance policies (OPA/Rego) enforce deterministic, auditable rules. No ML or heuristic decisions in the enforcement path. All policy changes are version-controlled and testable via `puzzlectl policy test`. |
| CC1.2 | The board of directors demonstrates independence from management and exercises oversight | Out of scope (organizational control). PuzzlePod provides the audit evidence (signed manifests, audit trail) needed for board-level reporting. |
| CC1.3 | Management establishes structures, reporting lines, and appropriate authorities | Agent profiles define per-agent authority boundaries (filesystem access, network access, resource limits). Profile assignment is an administrative action logged in the audit trail. |
| CC2.1 | The entity obtains or generates and uses relevant, quality information to support the functioning of internal control | fanotify behavioral monitoring, Prometheus metrics, and Linux Audit events provide continuous telemetry on agent behavior. `puzzlectl audit export` provides structured data for compliance reporting. |
| CC3.1 | The entity specifies objectives with sufficient clarity to enable the identification of risks | Threat model (T1-T7) with risk assessment matrix defines likelihood, impact, and risk rating for each threat actor. Kill chain analysis traces each attack scenario through defense layers. |
| CC3.2 | The entity identifies risks to the achievement of its objectives | Eight independent enforcement layers (Landlock, seccomp, PID NS, Mount NS, Net NS, cgroups, SELinux, BPF LSM) each address specific risk categories. Escape vector coverage table maps every known escape to at least two blocking mechanisms. |
| CC3.3 | The entity considers the potential for fraud | Prompt injection (T2), credential exfiltration (T4), and supply chain injection (T7) are explicitly modeled threat actors. Governance policies detect encoded credentials and sensitive file patterns. |
| CC5.1 | The entity selects and develops control activities that contribute to the mitigation of risks | Defense-in-depth architecture with kernel-enforced, agent-irrevocable controls. Landlock and seccomp are self-applied and cannot be removed by the agent process. |
| CC5.2 | The entity selects and develops general control activities over technology | `puzzled` is hardened: runs with minimal capabilities, confined by SELinux (`puzzlepod_t`), filtered by seccomp-BPF (57 blocked escape-vector syscalls + 4 USER_NOTIF-gated; 58 on x86_64), and has no external network access. |
| CC5.3 | The entity deploys control activities through policies and procedures | Agent profiles (YAML) and governance policies (Rego) are declarative, version-controlled, and validated against JSON schema before deployment. Four-phase migration path (Monitor -> Audit -> Enforce -> Full). |
| CC6.1 | The entity implements logical access security over protected information assets | Landlock filesystem ACL restricts agent read/write access to explicitly allowed paths. Denylist patterns block access to credential files regardless of allowlist entries. Per-agent PID namespace prevents cross-agent visibility. |
| CC6.2 | Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users | Agents are registered via D-Bus API (`CreateBranch`). Each agent is assigned a profile that defines its access scope. No agent can operate without a registered profile. |
| CC6.3 | The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets | Profile management (`puzzlectl profile`) controls access. Profile changes take effect on next branch creation. Rollback removes all agent changes from the base filesystem with zero residue. |
| CC6.6 | The entity implements logical access security measures to protect against threats from sources outside its system boundaries | Network namespace isolation with three modes (Blocked, Gated, Monitored). Domain allowlists restrict outbound connections. HTTP proxy queues write requests for commit-time review. nftables blocks raw socket bypass. |
| CC6.7 | The entity restricts the transmission of data to authorized external parties | Network gating: POST/PUT/DELETE requests are queued and replayed only after governance approval. DNS restricted to controlled resolvers. Data exfiltration via file content detected by governance policy (base64, credential patterns). |
| CC6.8 | The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software | seccomp USER_NOTIF gates `execve` calls against an explicit allowlist. BPF LSM enforces exec counting and rate limiting. Governance policy blocks persistence mechanisms (cron jobs, systemd units). |
| CC7.1 | To meet its objectives, the entity uses detection and monitoring procedures | fanotify behavioral monitoring detects mass deletion, excessive reads, and credential access in real time. Prometheus metrics expose branch count, commit rate, policy violations, and resource usage. Linux Audit logs all security-relevant events. |
| CC7.2 | The entity monitors system components for anomalies | Behavioral triggers fire when agent file access patterns exceed configured thresholds. Watchdog monitoring detects agent timeout or unresponsiveness. cgroup event notifications detect OOM and resource pressure. |
| CC7.3 | The entity evaluates security events to determine whether they could or have resulted in a failure | `puzzlectl audit list` provides queryable audit trail. IMA-signed manifests provide tamper-evident commit records. Policy violation events include rule name, message, and severity for root-cause analysis. |
| CC7.4 | The entity responds to identified security incidents | Automatic rollback on governance failure (fail-closed). Agent termination via PID namespace kill (all processes, guaranteed). `puzzlectl agent kill` for manual intervention. Branch rollback removes all changes with zero residue. |
| CC8.1 | The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure | Four-phase migration path: Monitor Only -> Audit Mode -> Enforce Mode -> Full Governance. Policy changes tested via `puzzlectl policy test` before deployment. Profile changes validated against JSON schema. |
| CC9.1 | The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions | WAL-based crash-safe commit ensures atomicity. `puzzled` auto-restarts via systemd and recovers orphaned branches. Configurable fail modes (FailClosed, FailSilent, FailOperational, FailSafeState) for different risk tolerance. |

---

## Availability

| Control ID | Control Description | PuzzlePod Implementation |
|---|---|---|
| A1.1 | The entity maintains, monitors, and evaluates current processing capacity and use | cgroups v2 enforce per-agent CPU, memory, I/O, and PID limits. XFS project quotas enforce per-branch storage limits. Prometheus metrics expose real-time resource usage per agent. |
| A1.2 | The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections | `puzzled` hardened with minimal capabilities, SELinux confinement, seccomp filtering. systemd watchdog detects daemon failure. Auto-restart with WAL recovery ensures continuity. |
| A1.3 | The entity tests recovery plan procedures | WAL-based crash recovery is testable: kill `puzzled` during commit, verify recovery on restart. Integration tests cover crash recovery scenarios. |

---

## Processing Integrity

| Control ID | Control Description | PuzzlePod Implementation |
|---|---|---|
| PI1.1 | The entity obtains or generates, uses, and communicates relevant, quality information regarding the objectives related to processing | OPA/Rego governance policies are deterministic: no ML, heuristics, or probabilistic decisions. Policy evaluation results include specific rule violations with messages and severity levels. |
| PI1.2 | The entity implements policies and procedures over system inputs | Agent profiles define explicit input boundaries: `read_allowlist`, `write_allowlist`, `denylist`, `exec_allowlist`. All inputs are validated by the kernel (Landlock) before the agent can access them. |
| PI1.3 | The entity implements policies and procedures over system processing | cgroup.freeze provides TOCTOU-free diff reading. WAL-based commit ensures atomicity. Checksum-based copy-up filtering ensures diff accuracy. |
| PI1.4 | The entity implements policies and procedures to make available or deliver output completely, accurately, and timely | Governance gate evaluates every changeset before commit. IMA-signed manifests attest to the integrity of committed changes. Audit trail records every commit with changeset details. |
| PI1.5 | The entity implements policies and procedures to store inputs, items in processing, and outputs completely, accurately, and timely | Branch storage on XFS with project quotas. WAL entries ensure crash-safe persistence. OverlayFS upper layers provide complete, checksummed record of all agent modifications. |

---

## Confidentiality

| Control ID | Control Description | PuzzlePod Implementation |
|---|---|---|
| C1.1 | The entity identifies and maintains confidential information | Landlock `denylist` explicitly blocks access to credential files (`/etc/shadow`, `.ssh/`, `.env`, `credentials.json`). Governance policy detects sensitive file patterns in changesets. |
| C1.2 | The entity disposes of confidential information | Branch rollback (`rm -rf` of upper layer) removes all agent-generated data with zero residue. PID namespace destruction terminates all agent processes. Network namespace destruction closes all sockets. |

---

## Privacy

| Control ID | Control Description | PuzzlePod Implementation |
|---|---|---|
| P6.1 | The entity obtains commitments from vendors and other third parties | Agent network access restricted by domain allowlist. HTTP proxy logs all external API calls. POST/PUT/DELETE requests queued for governance review before execution. |
| P6.5 | The entity obtains privacy commitments from vendors | Audit trail records all data access and transmission by agents. IMA-signed manifests provide cryptographic evidence of what data was committed. |

---

## Summary

PuzzlePod provides technical controls that support SOC 2 compliance across all five Trust Services Categories. The strongest coverage is in **Security** (CC6.x access controls, CC7.x monitoring) and **Processing Integrity** (PI1.x governance and atomicity). Organizational controls (CC1.x governance structure, CC1.2 board oversight) remain the responsibility of the deploying organization. PuzzlePod provides the audit evidence and enforcement mechanisms that those organizational controls rely upon.
