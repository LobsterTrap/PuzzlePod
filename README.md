# PuzzlePod

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-lightgrey.svg)]()

**Governance for AI agent containers on Linux.**

A userspace daemon (`puzzled`) and CLI (`puzzlectl`) that add automated governance to AI agent workloads running in Podman containers. Agents execute inside standard OCI containers; PuzzlePod adds the governance layer on top: OPA/Rego policy evaluation on changesets, automated commit/rollback decisions, and optional runtime mediation of specific syscalls. It composes with Podman and systemd — not reinvents them.

No kernel modifications. No custom container runtimes. Just governance.

---

## Why PuzzlePod?

The name comes from the intersection of three ideas:

**Edward Thorndike's Puzzle Box** (1898) was one of the first controlled experiments in behavioral science. Animals were placed inside a box with a latch mechanism — they could explore freely, but their actions were observed and only specific behaviors produced results. The **lobster trap** captures the same principle from a different angle: subjects enter freely, but cannot escape with the goods. **Podman** is the local container pod manager — the standard tool for running OCI containers on Linux.

**PuzzlePod** is the crossover: a governance layer where AI agents can explore freely inside containers, but their changes are observed, evaluated against policy, and only approved actions persist. Like Thorndike's puzzle box, the containment is real (kernel-enforced), the observation is continuous (fanotify, seccomp), and the outcome is deterministic (OPA/Rego policy, not heuristics).

The core insight: **the kernel enforces containment; userspace makes governance decisions.**

---

## The Problem

Containers provide strong isolation — namespaces, cgroups, seccomp, SELinux. But container security is **configured statically at start time**: you define a seccomp profile, mount paths, and resource limits, and they stay fixed.

AI agents are different. Their syscall sequence — which files they open, which binaries they execute, which network connections they initiate — is determined at runtime by an LLM, not by compiled program logic. A traditional container runs a known binary with a predictable call pattern. An agent might decide to run *any* binary on the system.

This creates a gap: **static container configuration doesn't make runtime governance decisions.** It can't evaluate "should these 500 file changes persist or be rolled back as a unit?" or "should this agent be allowed to execute `curl` with these specific arguments right now?"

PuzzlePod fills that gap — not by replacing container isolation, but by adding a governance layer on top of it.

## What PuzzlePod Adds

| What containers already do | What PuzzlePod adds |
|---|---|
| Namespaces, cgroups, seccomp, SELinux | OPA/Rego policy evaluation on agent changesets |
| Static seccomp allow/deny at start time | Runtime seccomp `USER_NOTIF` mediation — per-invocation allow/deny of execve/connect |
| Read-only mounts, bind mounts | OverlayFS branching with automated commit/rollback |
| Resource limits | Behavioral monitoring via fanotify — anomaly detection |
| Container image management | Changeset governance — deterministic policy decides what persists |

## Fork, Explore, Commit

Agents run inside containers with an OverlayFS branch. All writes go to an ephemeral upper layer. When the agent is done, `puzzled` evaluates the changeset against OPA/Rego policy and either commits or rolls back:

```
              Base Filesystem
         (container rootfs or bind mount)
                    |
         +----------+----------+
         |                     |
    OverlayFS Branch      OverlayFS Branch
         |                     |
    +-----------+         +-----------+
    |  Agent A  |         |  Agent B  |
    |  (writes  |         |  (writes  |
    |  to upper |         |  to upper |
    |  layer)   |         |  layer)   |
    +-----+-----+         +-----+-----+
          |                      |
    +-----v------+         +-----v-----+
    | Governance |         | Governance|
    | Gate       |         | Gate      |
    | - OPA/Rego |         | - OPA/Rego|
    +-----+------+         +-----+-----+
          |                      |
     commit()              rollback()
     (persist)             (discard)
```

**Nothing is permanent until explicitly committed.** If an agent crashes, hallucinates, times out, or produces a bad result, its branch is discarded. Zero cleanup. Zero residue.

---

## Quick Start

### Rootless Demo (No Root Required)

The fastest way to see PuzzlePod working:

```bash
# Build
cargo build --workspace

# Run the rootless demo
demo/run_demo_rootless.sh
```

This demonstrates the full Fork-Explore-Commit lifecycle using fuse-overlayfs and OPA/Rego governance — no root privileges needed.

### Linux (Native, Fedora 42+ / RHEL 10+)

```bash
# Install dependencies
sudo dnf install -y gcc gcc-c++ make cmake pkg-config \
  openssl-devel dbus-devel systemd-devel \
  clang llvm libseccomp-devel bpftool libbpf-devel \
  xfsprogs xfsprogs-devel nftables audit ima-evm-utils jq \
  rust cargo cargo-deny clippy rustfmt

# Build
make build

# Run tests
make test

# Start puzzled and run a governed command (single-step)
sudo systemctl start puzzled
puzzlectl run --profile=restricted -- python3 agent.py

# Or step-by-step for fine-grained control:
puzzlectl branch create --profile=restricted --base=/home/user/project
puzzlectl branch inspect <branch_id>
puzzlectl branch approve <branch_id>
```

### macOS (Lima VM)

```bash
./scripts/lima-dev.sh setup    # Create + start Fedora 42 VM
./scripts/lima-dev.sh shell    # Enter VM
./scripts/lima-dev.sh build    # Build in VM
./scripts/lima-dev.sh test     # Run tests
```

---

## Documentation

| Document | Description |
|---|---|
| [PRD](docs/PRD.md) | Product requirements: problem statement, use cases, functional requirements |
| [Technical Design](docs/technical-design.md) | Full technical architecture, kernel primitives, defense-in-depth, execution flows |
| [Admin Guide](docs/admin-guide.md) | Installation, configuration, operations |
| [Developer Guide](docs/developer-guide.md) | Contributing, code structure, building, testing |
| [Security Guide](docs/security-guide.md) | Security architecture, threat model, hardening |
| [Demo Guide](docs/demo-guide.md) | Walkthrough of all 5 demos |
| [Profile Authoring](docs/profile-authoring-guide.md) | Writing agent profiles |
| [Kernel vs Userspace](docs/Kernel_vs_userspace.md) | Architectural decision analysis |

### Compliance

| Framework | Document |
|---|---|
| FedRAMP | [docs/compliance/fedramp.md](docs/compliance/fedramp.md) |
| ISO 27001 | [docs/compliance/iso27001.md](docs/compliance/iso27001.md) |
| SOC 2 | [docs/compliance/soc2.md](docs/compliance/soc2.md) |

---

## Demos

PuzzlePod includes five demos that exercise real kernel primitives. See [docs/demo-guide.md](docs/demo-guide.md) for detailed walkthroughs.

| Demo | Script | Root? | What It Shows |
|---|---|---|---|
| **Sandbox Live** | `sudo demo/sandbox-live-demo.sh` | Yes | Real sandboxed process with 8 enforcement properties verified (~1 min) |
| **Phase 1: Core** | `sudo demo/run_demo_phase1.sh` | Yes | Fork-Explore-Commit, OPA/Rego policy, Landlock + seccomp + cgroups |
| **Phase 2: Hardening** | `sudo demo/run_demo_phase2.sh` | Yes | 23 profiles, network gating, seccomp USER_NOTIF, fanotify, BPF LSM |
| **Rootless** | `demo/run_demo_rootless.sh` | **No** | Full lifecycle without root, fuse-overlayfs, Podman rootless |
| **E2E Governance** | `sudo cargo test ...` | Yes | 3 agents (diligent/careless/malicious), OPA, trust scoring, attestation |

```bash
# Quick sandbox verification (~1 min)
sudo demo/sandbox-live-demo.sh

# Full demos
sudo demo/run_demo_phase1.sh    # Core lifecycle
demo/run_demo_rootless.sh       # Rootless (no root!)

# E2E governance lifecycle test
sudo cargo test -p puzzled --test e2e_governance_lifecycle \
  -- --include-ignored --nocapture --test-threads=1
```

---

## Architecture

| Component | Function |
|---|---|
| **puzzled** | Governance daemon — OverlayFS branch management, OPA/Rego policy engine, seccomp USER_NOTIF mediation, fanotify monitoring, WAL-based crash-safe commit, audit |
| **puzzlectl** | CLI — branch inspection, approval/rejection, profile management, agent simulation |
| **puzzle-podman** | Podman wrapper — `puzzle-podman run` adds branch governance to standard `podman run` |
| **puzzle-proxy** | HTTP proxy — credential injection, DLP scanning, network side-effect gating |
| **puzzle-init** | Container init shim — Landlock + nftables DNAT setup inside containers |
| **puzzle-hook** | OCI runtime hook — attaches governance to Podman-managed containers |

PuzzlePod uses standard kernel primitives — the same ones Podman/crun already use: OverlayFS, namespaces, cgroups, seccomp, Landlock, SELinux. No kernel modifications required.

### Key Design Decisions

- **Compose, don't reinvent.** Uses Podman for container lifecycle and systemd for service management. Adds governance — not another way to set up namespaces and cgroups.
- **Fail closed.** If governance cannot be determined, the default is rollback, not commit.
- **Changeset, not file-by-file.** Changes are evaluated as a complete set — dangerous combinations are caught at commit time.
- **Kernel enforces, userspace decides.** Landlock, seccomp, and namespaces are kernel-enforced and survive daemon crashes. OPA/Rego policy is evaluated in userspace.

---

## Advanced Governance

Beyond the core Fork-Explore-Commit workflow:

- **Cryptographic Attestation** — Ed25519 signatures, Merkle proofs (RFC 6962), SPIFFE JWT-SVID workload identity
- **Graduated Trust** — Agents earn/lose trust based on governance outcomes; trust tiers gate available actions
- **Provenance Chain** — Full causal chain from prompt to commit, stored as NDJSON
- **Compliance Evidence** — Automated mapping to FedRAMP, ISO 27001, SOC 2 controls
- **Data Loss Prevention** — Pattern matching, entropy detection, configurable actions on outbound data
- **Credential Isolation** — Phantom tokens, transparent proxy, 4 credential backends (encrypted local, Vault, Kubernetes, keyring)
- **Functional Safety** — Actuator gating, real-time profile, configurable fail modes for safety-critical deployments

---

## Repository Structure

```
puzzlepod/
├── crates/
│   ├── puzzled/              # Governance daemon
│   ├── puzzlectl/            # CLI tool
│   ├── puzzled-types/        # Shared types
│   ├── puzzle-proxy/         # HTTP proxy (credential injection, DLP)
│   ├── puzzle-init/          # Container init shim (Landlock, nftables)
│   └── puzzle-hook/          # OCI runtime hook
├── policies/
│   ├── profiles/             # 23 agent profiles (restricted -> privileged)
│   ├── rules/                # OPA/Rego governance rules
│   └── schemas/              # Profile validation schema
├── demo/                     # Demo scripts and sample data
├── podman/                   # Podman integration (wrapper, hooks, quadlets)
├── systemd/                  # Service units and slice configs
├── selinux/                  # SELinux policy module
├── docs/                     # Documentation
├── tests/                    # Security and performance tests
├── scripts/                  # Build and setup scripts
├── bpf/                      # eBPF programs (exec rate limiting)
├── packaging/                # RPM spec files
├── man/                      # Man pages
└── ansible/                  # Ansible collection
```

## Target Platforms

- **Architectures:** x86_64, aarch64
- **Kernel:** >= 6.7 (Landlock ABI v4)
- **Distributions:** RHEL 10+, Fedora 42+, CentOS Stream 10
- **Environments:** Data center servers, edge nodes (4GB+ RAM)

## Testing

```bash
make test           # Unit tests (no root)
make ci             # fmt + clippy + test + deny
sudo make test-all  # Full suite (root + Linux)
```

## Authors

Created by [Francis Chow](https://github.com/openchow) and [Adam Miller](https://github.com/maxamillion).

## License

Apache-2.0

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

[github.com/LobsterTrap/PuzzlePod](https://github.com/LobsterTrap/PuzzlePod)
