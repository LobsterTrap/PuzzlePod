# Sandbox Live Demo Guide

This guide walks you through running a fully sandboxed agent process with puzzled and verifying that kernel-enforced containment is active. You'll see seccomp, Landlock, capabilities, namespaces, cgroups, and OverlayFS working together in a real Linux environment.

## Prerequisites

- **Linux with libvirt** or **macOS with Lima** (or a native Linux machine with Fedora 42+ / RHEL 10+)
- The PuzzlePod source code

## Step 1: Create the VM

### Option A: Fedora/RHEL Linux (libvirt)

```bash
# Install prerequisites (one-time)
sudo dnf install libvirt virt-install qemu-kvm genisoimage passt rsync
sudo systemctl enable --now libvirtd

# Create and provision the VM
./scripts/libvirt-dev.sh setup
```

### Option B: macOS (Lima)

```bash
# From the project root
limactl create --name=puzzled-dev puzzled-dev.yaml
limactl start puzzled-dev
```

Both options create a Fedora 42 VM with all required kernel primitives (Landlock, seccomp USER_NOTIF, BPF LSM, OverlayFS, namespaces, cgroups v2).

First-time provisioning takes 5-10 minutes (installs Rust, creates XFS test partition, configures D-Bus).

## Step 2: Enter the VM

### Option A: libvirt

```bash
./scripts/libvirt-dev.sh shell
# You are now in ~/puzzlepod inside the VM
```

### Option B: Lima

```bash
limactl shell puzzled-dev
cd ~/puzzlepod    # or wherever your project is mounted
```

## Step 3: Build the Workspace

```bash
# Create the sudocargo alias (preserves Rust toolchain paths)
alias sudocargo='sudo -E env PATH="$PATH" CARGO_HOME="$HOME/.cargo" RUSTUP_HOME="$HOME/.rustup" cargo'

# Build all crates in release mode
sudocargo build --workspace --release
```

This compiles `puzzled` (the governance daemon) and `puzzlectl` (the CLI tool).

## Step 4: Set Up the Development Environment

```bash
sudo scripts/dev-setup.sh setup
```

This creates:
- `/etc/puzzled/puzzled.conf` — daemon configuration
- `/etc/puzzled/profiles/` — agent profiles (restricted, standard, privileged)
- `/etc/puzzled/policies/` — OPA/Rego governance rules
- `/var/lib/puzzled/branches/` — OverlayFS branch storage
- `/run/puzzled/` — runtime state
- D-Bus policy for `org.lobstertrap.PuzzlePod1`

## Step 5: Start puzzled

Open **two terminal windows** into the VM.

**Window 1** (puzzled daemon — stays running):
```bash
# libvirt:
./scripts/libvirt-dev.sh shell
# Lima:
limactl shell puzzled-dev

cd ~/puzzlepod
sudo scripts/dev-setup.sh start
```

You'll see puzzled start with debug logging. Leave this running.

**Window 2** (your working terminal):
```bash
# libvirt:
./scripts/libvirt-dev.sh shell
# Lima:
limactl shell puzzled-dev

cd ~/puzzlepod
```

## Step 6: Run the Automated Demo

```bash
sudo ./demo/sandbox-live-demo.sh
```

This script:
1. Creates a sandboxed branch with the `restricted` profile
2. Verifies all kernel enforcement layers
3. Tests exec allowlist enforcement
4. Shows OverlayFS isolation
5. Verifies network blocking
6. Cleans up

## Step 7: Manual Exploration

### Create a branch manually

```bash
# Create a workspace directory
mkdir -p /tmp/test-workspace

# Create a sandboxed branch (cat blocks on stdin, stays alive)
sudo ./target/release/puzzlectl branch create \
    --profile=restricted \
    --base=/tmp/test-workspace \
    --command='["/usr/bin/cat"]'
```

The output shows the branch ID and agent PID.

### Inspect the sandboxed process

```bash
# Replace <PID> with the agent's PID from the output above

# Is it alive?
sudo cat /proc/<PID>/status | head -5
# Expected: Name=cat, State=S (sleeping)

# Seccomp filter active?
sudo grep Seccomp /proc/<PID>/status
# Expected: Seccomp: 2, Seccomp_filters: 1

# Capabilities dropped?
sudo grep Cap /proc/<PID>/status
# Expected: CapEff: 0000000000000000, CapPrm: 0000000000000000

# Running as non-root?
sudo grep Uid /proc/<PID>/status
# Expected: Uid: 65534 (nobody)

# In separate namespaces?
sudo ls -la /proc/<PID>/ns/
# pid, mnt, net should differ from /proc/self/ns/

# cgroup limits?
cat /proc/<PID>/cgroup
# Expected: puzzle.slice/user-65534.slice/agent-<branch-id>.scope
CGROUP=$(cat /proc/<PID>/cgroup | grep -o '/agent.*')
cat /sys/fs/cgroup${CGROUP}/memory.max   # 268435456 (256 MiB)
cat /sys/fs/cgroup${CGROUP}/pids.max     # 16
```

### Test exec allowlist enforcement

```bash
# This should FAIL — sleep is not in the restricted exec_allowlist
sudo ./target/release/puzzlectl branch create \
    --profile=restricted \
    --base=/tmp/test-workspace \
    --command='["/usr/bin/sleep", "3600"]'

# Check the puzzled log in window 1:
# "execve denied: not in allowlist pid=... path=/usr/bin/sleep"
```

### Test with the standard profile

```bash
# Standard profile allows more binaries and has Gated network mode
sudo ./target/release/puzzlectl branch create \
    --profile=standard \
    --base=/tmp/test-workspace \
    --command='["/usr/bin/python3", "-c", "import os; print(os.getpid(), os.getuid())"]'
```

### List and manage branches

```bash
# List all active branches
sudo ./target/release/puzzlectl branch list

# Kill an agent
sudo ./target/release/puzzlectl agent kill <BRANCH_ID>
```

### Inspect OverlayFS isolation

```bash
# Find the branch's upper directory from the create output
UPPER_DIR=/var/lib/puzzled/branches/<BRANCH_ID>/upper

# Any files the agent writes appear here (copy-on-write)
ls -la $UPPER_DIR

# The base workspace is untouched
ls -la /tmp/test-workspace

# On rollback, the upper directory is deleted — zero residue
```

## Step 8: Clean Up

```bash
# Stop puzzled (window 1: Ctrl+C, or from window 2:)
sudo scripts/dev-setup.sh stop

# Clean all runtime state
sudo scripts/dev-setup.sh clean

# Optionally stop the VM
exit  # leave the VM
limactl stop puzzled-dev
```

## What You Just Saw

| Layer | Mechanism | Verified By |
|-------|-----------|-------------|
| **Process isolation** | PID namespace via `clone3()` | Different `/proc/PID/ns/pid` |
| **Filesystem isolation** | Mount namespace + OverlayFS | Different `/proc/PID/ns/mnt`, writes in upper layer |
| **Filesystem ACL** | Landlock LSM | `execve` of non-allowed paths returns EPERM |
| **Syscall filtering** | seccomp-BPF + USER_NOTIF | `Seccomp: 2` in status, exec allowlist enforced |
| **Privilege restriction** | Capability dropping | `CapEff: 0000000000000000` |
| **Credential isolation** | `setuid`/`setgid` to nobody | `Uid: 65534` |
| **Network isolation** | Network namespace (empty) | Different `/proc/PID/ns/net`, no interfaces |
| **Resource limits** | cgroups v2 | `memory.max`, `pids.max` in agent cgroup scope |

All enforcement is **kernel-level and irrevocable**. Even if puzzled crashes, the restrictions on the agent process remain active until the process exits.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `The name is not activatable` | D-Bus policy not installed | Run `sudo scripts/dev-setup.sh setup` |
| Agent is a zombie (State: Z) | Sandbox setup failed | Check puzzled log for the specific error |
| `execve denied: not in allowlist` | Binary not in profile's `exec_allowlist` | Add to `policies/profiles/<profile>.yaml` and copy to `/etc/puzzled/profiles/` |
| `Permission denied` on execve | Binary directory not in Landlock `read_allowlist` | Add to `policies/profiles/<profile>.yaml` `filesystem.read_allowlist` |
| `XFS project ID assignment failed` | Not on XFS filesystem | Harmless warning (quotas advisory on ext4) |
| `fanotify_mark failed` | OverlayFS doesn't support fanotify FID | Harmless warning (behavioral monitoring degraded) |
| `BPF object file not found` | BPF LSM program not compiled | Harmless warning (exec rate limiting unavailable) |

## Further Reading

- `demo/run_demo_rootless.sh` — Rootless demo (no root required, uses fuse-overlayfs)
- `docs/demo-guide.md` — Full walkthrough of all demos
- `docs/debug/sandbox-child-process.md` — Detailed debugging session for sandbox setup issues
- `docs/security-guide.md` — Full security architecture
- `docs/profile-authoring-guide.md` — How to write agent profiles
- `CLAUDE.md` — Technical architecture overview
