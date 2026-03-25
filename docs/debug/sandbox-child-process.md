# Debugging: Sandbox Child Process Dies Immediately (Zombie)

This document captures the debugging journey of getting the puzzled sandbox to produce a fully-running child process. The child process was consistently dying immediately after `clone3()`, appearing as a zombie. Five distinct bugs were found and fixed across sensitive path masking, credential/capability ordering, UID handling, seccomp response semantics, and Landlock filesystem rules.

**Environment:** Lima VM (Fedora 42, aarch64), puzzled running as root, `puzzlectl` creating branches
**Kernel:** 6.14.0-63.fc42.aarch64
**Date:** 2026-03-09

---

## Table of Contents

1. [Symptoms](#symptoms)
2. [Bug 1: mask_sensitive_paths Fails on Directories (ENOTDIR)](#bug-1-mask_sensitive_paths-fails-on-directories-enotdir)
3. [Bug 2: setgroups Fails After Capabilities Dropped (EPERM)](#bug-2-setgroups-fails-after-capabilities-dropped-eperm)
4. [Bug 3: Root Caller UID Rejected by FailClosed Profile](#bug-3-root-caller-uid-rejected-by-failclosed-profile)
5. [Bug 4: Seccomp new_val(0) Fakes execve Success Without Executing](#bug-4-seccomp-new_val0-fakes-execve-success-without-executing)
6. [Bug 5: Landlock Blocks execve Because /usr/bin Not in read_allowlist](#bug-5-landlock-blocks-execve-because-usrbin-not-in-read_allowlist)
7. [Diagnostic Methodology](#diagnostic-methodology)
8. [Key Takeaways](#key-takeaways)

---

## Symptoms

After `puzzlectl branch create --profile=restricted`, the child process appeared as a zombie:

```
$ sudo cat /proc/<PID>/status | head -5
Name:    zbus::Connectio
State:    Z (zombie)
Tgid:    <PID>
```

Key observations:
- Process name was `zbus::Connectio` (inherited thread name from parent, never exec'd)
- cmdline was empty (no execve happened)
- puzzled reported the branch as "Active" with a valid PID

Each bug was found sequentially — fixing one revealed the next. The child process setup has a strict ordering of ~10 steps (SELinux, Landlock, seccomp, credentials, capabilities, execve), and a failure at any step kills the child in FailClosed mode.

---

## Bug 1: mask_sensitive_paths Fails on Directories (ENOTDIR)

### Error

```
ERROR puzzled::sandbox: failed to mask sensitive path /proc/acpi (fail-closed): Not a directory (os error 20)
```

### Root Cause

`mask_sensitive_paths()` bind-mounted `/dev/null` (a file) over every sensitive path. Some paths like `/proc/acpi` are **directories**. Bind-mounting a file over a directory fails with `ENOTDIR`. In FailClosed mode, this error was fatal — the child exited before applying seccomp, dropping capabilities, or executing the command.

### Fix

**File:** `crates/puzzled/src/sandbox/mod.rs`

Detect whether each sensitive path is a directory or file, then use the appropriate masking method:

- **Directories:** Mount an empty read-only tmpfs over them
- **Files:** Bind-mount `/dev/null` over them (original behavior)

```rust
let is_dir = std::path::Path::new(path_str).is_dir();

let ret = if is_dir {
    // Mount an empty tmpfs over the directory to hide its contents
    let tmpfs = std::ffi::CString::new("tmpfs").unwrap();
    unsafe {
        libc::mount(
            tmpfs.as_ptr(),
            target.as_ptr(),
            tmpfs.as_ptr(),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    }
} else {
    // Bind mount /dev/null over the file
    unsafe {
        libc::mount(
            dev_null.as_ptr(),
            target.as_ptr(),
            none.as_ptr(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    }
};
```

### Lesson

Bind mounts are type-sensitive. A file can only be bind-mounted over a file, and a directory over a directory. Container runtimes (runc, crun) handle this same distinction.

---

## Bug 2: setgroups Fails After Capabilities Dropped (EPERM)

### Error

```
ERROR puzzled::sandbox: failed to switch credentials in child error=sandbox setup error: setgroups(0) failed: Operation not permitted (os error 1)
```

### Root Cause

The child's setup sequence was:

1. SELinux context (needs CAP_MAC_ADMIN)
2. Landlock (irrevocable)
3. seccomp (irrevocable)
4. **Drop capabilities** (clears CAP_SETUID, CAP_SETGID, etc.)
5. **Switch credentials** (calls setgroups, setgid, setuid)

Step 5 requires `CAP_SETUID`/`CAP_SETGID`, which were already removed in step 4.

### Fix

**File:** `crates/puzzled/src/sandbox/mod.rs`

Swap steps 4 and 5 — switch credentials while capabilities are still held, then drop capabilities:

```
1. SELinux context (needs CAP_MAC_ADMIN)
2. Landlock (irrevocable)
3. seccomp (irrevocable)
4. Switch credentials (needs CAP_SETUID/CAP_SETGID)  ← moved up
5. Drop capabilities (last — removes all remaining caps)  ← moved down
```

### Lesson

Capability dropping and credential switching have a strict ordering dependency. The comment in the code said "must happen after capability dropping (which requires root)" which was backwards — it's the dropping that should come after.

---

## Bug 3: Root Caller UID Rejected by FailClosed Profile

### Error

```
ERROR puzzled::sandbox: failed to switch credentials in child error=sandbox setup error: refusing to run agent as root (FailClosed profile requires non-root UID)
```

### Root Cause

When `sudo puzzlectl branch create` is called:
1. D-Bus `get_caller_uid()` returns UID 0 (root)
2. UID 0 is passed to `SandboxBuilder::with_credentials(0, 0)`
3. In the child, `switch_credentials(0, 0, reject_root=true)` rejects UID 0 for FailClosed profiles

This is correct safety behavior — agents shouldn't run as root. But there was no way to specify a non-root UID from the CLI.

### Fix

**File:** `crates/puzzled/src/dbus.rs`

When root (UID 0) creates a branch, default the agent UID to `nobody` (65534):

```rust
let agent_uid = if uid == 0 { 65534 } else { uid };
```

Non-root callers still run the agent as themselves.

### Lesson

When an admin (root) creates a branch, the agent should run as an unprivileged user, not as root. This is analogous to how `podman` and `systemd` handle service user specification.

---

## Bug 4: Seccomp new_val(0) Fakes execve Success Without Executing

### Error

```
INFO puzzled::sandbox::seccomp::validate: execve allowed pid=<PID> path=/usr/bin/cat
ERROR puzzled::sandbox: execve failed command=["/usr/bin/cat"] error=Invalid argument (os error 22)
```

The seccomp handler approved the execve, but the child still failed.

### Root Cause

The seccomp notification response used:

```rust
ScmpNotifResp::new_val(req.id, 0, ScmpNotifRespFlags::empty())
```

This tells the kernel: "return value 0 from the syscall." For execve, this means the kernel returns 0 to userspace **without actually loading the binary**. The child's code after `libc::execve()` continues (execve only returns on error), logs `last_os_error()`, and exits.

### Fix

**File:** `crates/puzzled/src/sandbox/seccomp/notif.rs`

Use `new_continue` instead of `new_val(0)`:

```rust
let resp = if allow {
    ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty())
} else {
    ScmpNotifResp::new_error(req.id, libc::EPERM, ScmpNotifRespFlags::empty())
};
```

`new_continue` sets `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, telling the kernel to **actually execute the original syscall**.

Additionally, SECCOMP_ADDFD failures were changed from deny to allow-via-CONTINUE, since ADDFD is a TOCTOU mitigation and the path was already validated.

### Lesson

`SECCOMP_RET_USER_NOTIF` semantics require explicit `FLAG_CONTINUE` to let the original syscall proceed. Without it, the response is interpreted as "replace the syscall return value" — which for execve means a silent no-op. This is the most subtle bug in the entire sequence.

---

## Bug 5: Landlock Blocks execve Because /usr/bin Not in read_allowlist

### Error

```
ERROR puzzled::sandbox: execve failed command=["/usr/bin/cat"] error=Permission denied (os error 13)
```

### Root Cause

The `restricted.yaml` profile had:

```yaml
exec_allowlist:
  - /usr/bin/cat

filesystem:
  read_allowlist:
    - /usr/share
    - /usr/lib
    - /usr/lib64
    # /usr/bin was MISSING
```

Landlock and seccomp are **independent enforcement layers**:
- seccomp USER_NOTIF approved the execve (path in exec_allowlist)
- Landlock denied the file read (path not in read_allowlist)

`execve` requires reading the binary, which Landlock blocks if the directory isn't readable.

### Fix

**File:** `policies/profiles/restricted.yaml`

Added `/usr/bin` to the read_allowlist:

```yaml
filesystem:
  read_allowlist:
    - /usr/bin      # Required for exec_allowlist entries
    - /usr/share
    - /usr/lib
    - /usr/lib64
```

### Lesson

Defense-in-depth means every layer enforces independently. The exec_allowlist (seccomp) and Landlock's read_allowlist must be **consistent** — you can't exec a binary you can't read. Profile authors must ensure Landlock read access covers all directories referenced by the exec_allowlist.

---

## Diagnostic Methodology

### Key Diagnostic Commands

```bash
# Check process state (zombie = Z, sleeping = S)
sudo cat /proc/<PID>/status | head -5

# Check if execve happened (empty = no exec)
sudo cat /proc/<PID>/cmdline | tr '\0' ' '

# Check seccomp enforcement
sudo grep Seccomp /proc/<PID>/status

# Check capability enforcement
sudo grep Cap /proc/<PID>/status

# Check kernel denials
sudo dmesg | tail -20

# puzzled logs (most useful)
# Window 1 foreground output, or:
tail -f /var/log/puzzled.log
```

### Diagnosis Sequence

For each attempt:
1. **Check puzzled log** — the error message tells you which setup step failed
2. **Check /proc/PID/status** — zombie means child died, sleeping means alive
3. **Check /proc/PID/cmdline** — empty means execve never happened
4. **Check dmesg** — kernel security denials (SELinux, Landlock, seccomp)

### Error-to-Bug Mapping

| puzzled Log Error | Root Cause |
|---|---|
| `failed to mask sensitive path ... Not a directory` | Bug 1: bind-mounting file over directory |
| `setgroups(0) failed: Operation not permitted` | Bug 2: capabilities dropped before credential switch |
| `refusing to run agent as root (FailClosed)` | Bug 3: root caller UID passed to child |
| `execve failed ... Invalid argument` | Bug 4: seccomp new_val(0) instead of new_continue |
| `execve failed ... Permission denied` | Bug 5: Landlock read_allowlist missing /usr/bin |
| `SECCOMP_ADDFD inject failed ... Bad file descriptor` | Non-fatal: ADDFD ioctl issue, fallback to CONTINUE |

---

## Key Takeaways

1. **FailClosed mode is merciless.** Any setup step failure kills the child immediately. This is the correct production behavior but makes debugging harder — you only see the first error.

2. **Ordering is everything.** The child setup has ~10 steps with strict ordering dependencies. The correct order is: mount namespace setup → OverlayFS → SELinux context → Landlock → sensitive path masking → seccomp → wait for parent ACK → switch credentials → drop capabilities → execve.

3. **Independent enforcement layers can conflict.** Landlock and seccomp are independent — an execve can be approved by seccomp but denied by Landlock. Profile authors must ensure consistency across all layers.

4. **seccomp USER_NOTIF requires FLAG_CONTINUE for pass-through.** This is a critical semantic difference from seccomp-BPF `SECCOMP_RET_ALLOW`. USER_NOTIF defaults to "replace the return value" unless `FLAG_CONTINUE` is set.

5. **Test with real processes, not just unit tests.** These bugs only manifest when running real processes through the full sandbox setup chain. Unit tests that mock individual components can't catch ordering issues or cross-layer conflicts.
