# Summit Demo — PuzzlePod

Side-by-side demonstration: same AI agent container image, different outcomes.

## Architecture

```
LAPTOP 1 (Fedora 42 / RHEL 10)          LAPTOP 2 (Ubuntu 22/24)
┌─────────────────────────┐             ┌─────────────────────────┐
│ puzzle-podman run        │             │ podman run              │
│   --profile=...   │             │   bad-agent             │
│   --native              │             │                         │
│   bad-agent             │             │ (no governance)         │
├─────────────────────────┤             ├─────────────────────────┤
│ puzzled (governance)     │             │                         │
│ ├─ OPA/Rego policy      │             │ No puzzled               │
│ ├─ HMAC attestation     │             │ No policy               │
│ └─ Evidence bundle      │             │ No attestation          │
├─────────────────────────┤             ├─────────────────────────┤
│ Kernel enforcement      │             │ Kernel (unused)         │
│ ├─ Landlock (filesystem)│             │ ├─ Landlock (not used)  │
│ ├─ seccomp (syscalls)   │             │ ├─ seccomp (default)    │
│ ├─ OverlayFS (COW)      │             │ └─ No OverlayFS branch │
│ └─ Namespaces           │             │                         │
└─────────────────────────┘             └─────────────────────────┘

Result: Bad behaviors BLOCKED          Result: ALL behaviors ALLOWED
        Zero residue on rollback                No audit trail
        HMAC-signed attestation chain           No governance proof
```

## The Bad Agent

`bad-agent.py` simulates an AI coding assistant that:

1. **Writes code** to workspace (legitimate — allowed on both)
2. **Reads /etc/shadow** (credential harvesting — blocked by Landlock on laptop 1)
3. **Installs cron job** (persistence — written to overlay, rejected by OPA on laptop 1)
4. **Installs systemd backdoor** (persistence — written to overlay, rejected by OPA on laptop 1)
5. **Exfiltrates data via curl** (data theft — blocked by Landlock on laptop 1)
6. **Attempts sandbox escape** (impossible — Landlock is irrevocable on laptop 1)

## Quick Start

### Laptop 1 (Fedora 42 / RHEL 10)

```bash
# One-time setup (installs puzzled, puzzlectl, hooks, builds image)
sudo ./setup-laptop1-fedora.sh

# Run the governed demo
sudo ./demo-governed.sh

# Show attestation verification (run immediately after governed demo)
sudo ./demo-attestation.sh
```

### Laptop 2 (Ubuntu)

```bash
# One-time setup (installs Podman, builds image)
sudo ./setup-laptop2-ubuntu.sh

# Run the ungoverned demo (sudo because setup built image as root)
sudo ./demo-ungoverned.sh
```

### Development (single machine)

Run both demos sequentially on the same Fedora machine:

```bash
# Governed (with PuzzlePod)
sudo ./demo-governed.sh

# Ungoverned (bypass governance — plain podman)
sudo podman run --rm -it bad-agent
```

## Files

| File | Purpose |
|---|---|
| `bad-agent.py` | The "AI agent" script (identical on both laptops) |
| `Containerfile.bad-agent` | Container image build (identical on both laptops) |
| `profiles/summit-demo.yaml` | PuzzlePod profile for the demo agent |
| `demo-governed.sh` | Laptop 1: run governed demo |
| `demo-ungoverned.sh` | Laptop 2: run ungoverned demo |
| `demo-attestation.sh` | Laptop 1: attestation verification (run after governed demo) |
| `setup-laptop1-fedora.sh` | One-time setup for Fedora/RHEL |
| `setup-laptop2-ubuntu.sh` | One-time setup for Ubuntu |

## Replacing with OpenClaw

To swap in OpenClaw:

1. Replace `bad-agent.py` with OpenClaw's agent entrypoint
2. Update `Containerfile.bad-agent` to install OpenClaw dependencies
3. Adjust `profiles/summit-demo.yaml` for OpenClaw's legitimate needs
4. The governance stack (puzzled, puzzle-podman, hooks, policies) stays the same
