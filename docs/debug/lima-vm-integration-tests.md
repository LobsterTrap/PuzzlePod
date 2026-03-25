# Debugging: Lima VM Integration Tests (`branch_lifecycle`)

This document captures the full debugging journey of getting the `branch_lifecycle` integration tests passing on a Lima VM (aarch64 Linux on Apple Silicon macOS). It covers five distinct bugs across kernel namespace management, process creation, state management, async runtime assumptions, and policy evaluation — each revealing important architectural lessons.

**Tests:** `crates/puzzled/tests/branch_lifecycle.rs` (5 tests, all require `sudo` on Linux)
**Command:** `sudo ~/.cargo/bin/cargo test -p puzzled --test branch_lifecycle -- --include-ignored`

---

## Table of Contents

1. [Environment](#environment)
2. [Bug 1: Network Namespace Visibility](#bug-1-network-namespace-visibility)
3. [Bug 2: clone3 Custom Stack SIGSEGV](#bug-2-clone3-custom-stack-sigsegv)
4. [Bug 3: BranchInfo State Not Updated After Transition](#bug-3-branchinfo-state-not-updated-after-transition)
5. [Bug 4: Tokio Runtime Panic in Synchronous Tests](#bug-4-tokio-runtime-panic-in-synchronous-tests)
6. [Bug 5: Rego Policy Path Matching (Relative vs Absolute)](#bug-5-rego-policy-path-matching-relative-vs-absolute)
7. [Bug 6: Test Assertions After Rollback](#bug-6-test-assertions-after-rollback)
8. [Key Takeaways](#key-takeaways)

---

## Environment

- **Host:** macOS on Apple Silicon (aarch64)
- **VM:** Lima VM running Fedora/RHEL-compatible Linux (aarch64 native, not QEMU emulation)
- **Kernel features used:** `clone3()`, PID/mount/network/UTS/IPC/cgroup namespaces, `setns()`, named network namespaces, OverlayFS, cgroups v2, seccomp-BPF, Landlock

---

## Bug 1: Network Namespace Visibility

### Symptom
The parent process could not reference the child's network namespace to configure veth pairs and nftables rules. Various `ip link set ... netns ...` commands failed with "Invalid netns value" or "No such file or directory".

### Root Cause
The parent needs to reference the child's network namespace by name (for `ip link set <veth> netns <name>`) or by path (e.g., `/proc/<pid>/ns/net`). Three approaches were tried and failed on Lima:

### Failed Approach 1: `/proc/<pid>/ns/net`
```
ip link set va_xxx netns <child_pid>
→ Error: No such file or directory
```
On Lima, `/proc/<pid>/ns/net` was not visible from the parent for the child PID. This appears to be a Lima-specific issue with how the `/proc` filesystem is mounted or how PID namespace translation works.

### Failed Approach 2: `setns(pidfd, CLONE_NEWNET)`
```rust
// Parent tries to enter child's netns via pidfd
let ret = unsafe { libc::setns(pidfd, libc::CLONE_NEWNET) };
// Returns 0 (success!) but doesn't actually switch namespace
```
The `setns()` call returned success but the parent remained in its own network namespace. Subsequent veth configuration saw the host's routes, causing "RTNETLINK answers: File exists" errors when adding default routes.

### Failed Approach 3: Child Bind-Mount with Mount Propagation
```rust
// Child (in new mount namespace via CLONE_NEWNS):
libc::mount("/proc/self/ns/net", "/var/run/netns/<name>", MS_BIND);
// Parent: ip link set <veth> netns <name>
// → "Invalid netns value" — parent can't see the bind-mount
```
The child created a named netns by bind-mounting `/proc/self/ns/net` to `/var/run/netns/<name>`. But because clone3 included `CLONE_NEWNS`, the child has its own mount namespace. The bind-mount is invisible to the parent, even with systemd's default "shared" mount propagation — `CLONE_NEWNS` copies the mount table at clone time, but subsequent mounts in the child don't propagate back.

### Solution: Parent Creates Named Netns Before clone3
```
Timeline:
1. Parent: ip netns add agentns_<crc32>     ← creates /var/run/netns/<name>
2. Parent: clone3(CLONE_NEWPID | CLONE_NEWNS | ...)  ← NO CLONE_NEWNET
3. Child:  setns(open("/var/run/netns/<name>"), CLONE_NEWNET)
4. Child:  write(socket, ready_byte)
5. Parent: ip link set <veth> netns agentns_<crc32>  ← works!
```

**Key insight:** The parent creates and owns the named netns file. Since it's created before `clone3(CLONE_NEWNS)`, it exists in the parent's mount namespace. The child can still access it because `CLONE_NEWNS` copies the mount table at clone time (the file existed before the copy). The child's `setns()` into the named netns works because it uses a file path, not a pidfd.

### Files Changed
- `crates/puzzled/src/sandbox/namespace.rs` — Removed `CLONE_NEWNET` from clone3 flags
- `crates/puzzled/src/sandbox/network.rs` — Replaced `create_named_netns_from_pidfd()` with `create_named_netns()` using `ip netns add`
- `crates/puzzled/src/sandbox/mod.rs` — Parent creates netns before clone3; child joins via `setns()`

---

## Bug 2: clone3 Custom Stack SIGSEGV

### Symptom
After fixing the network namespace issue, all tests crashed with signal 11 (SIGSEGV). The child process died before executing its very first instruction — even a raw `write(2, "hello", 5)` at the top of the child closure produced no output.

### Root Cause
The `clone3()` call used a custom stack (`stack` and `stack_size` fields in `clone_args`). This changes the child's stack pointer (SP) to point to the custom stack. However, the compiler generates SP-relative addressing for local variables in the `create_isolated_process()` function. After clone3 changes SP, those SP-relative offsets point into uninitialized memory on the custom stack instead of the actual local variables (which live on the original stack, now COW-duplicated).

```
Before clone3:
  SP → [original stack: child_fn, pidfd, args, ret, ...]

After clone3 (in child):
  SP → [custom stack: uninitialized garbage]
       [original stack: child_fn, pidfd, args, ret, ...]  ← still accessible via COW
                                                            but NOT via SP-relative addressing
```

On aarch64, the `svc #0` syscall instruction doesn't use the stack for return addresses (uses LR register), so the child successfully returns from the syscall wrapper. But when it then tries to access `child_fn` or `ret` via `SP + offset`, it reads garbage and segfaults.

**Why it worked before:** The previous code changes happened to produce compiler output that used frame-pointer-relative (x29) addressing for the critical variables. After code changes, the compiler generated different register allocation using SP-relative addressing, exposing the latent bug.

### Solution
Set `stack: 0, stack_size: 0` in `clone_args`. Without `CLONE_VM`, clone3 acts exactly like `fork()` — the child gets a full COW copy of the parent's address space including the stack. No custom stack is needed.

```rust
let mut args = CloneArgs {
    // ...
    stack: 0,      // child uses COW copy of parent's stack
    stack_size: 0,
    // ...
};
```

### Lesson
**Never use a custom stack with clone3 when also using inline return-value checking** (the `if ret == 0 { /* child */ }` pattern). The custom stack feature is designed for `clone()`-style usage where a separate function pointer is provided. For fork-like semantics where parent and child diverge after checking the return value, the child must run on the same stack as the parent.

### Files Changed
- `crates/puzzled/src/sandbox/namespace.rs` — Set `stack: 0, stack_size: 0`; removed `allocate_child_stack()` call
- `crates/puzzled/src/sandbox/mod.rs` — Removed `child_stack` field from `SandboxHandle` and `SandboxCleanup`

---

## Bug 3: BranchInfo State Not Updated After Transition

### Symptom
```
assertion `left == right` failed
  left: Creating
 right: Active
```

### Root Cause
In `create_with_gid()`, a `BranchInfo` is created with `state: BranchState::Creating`, cloned into the DashMap, then the DashMap entry is transitioned to `Active`. But the local `info` variable (returned to the caller) still has `Creating`:

```rust
let info = BranchInfo { state: BranchState::Creating, ... };
self.branches.insert(branch_id.clone(), info.clone());  // clone into map
self.transition(&branch_id, BranchState::Active)?;       // updates MAP entry
Ok(info)  // returns ORIGINAL with Creating state
```

### Solution
```rust
self.transition(&branch_id, BranchState::Active)?;
info.state = BranchState::Active;  // sync local copy
```

### Lesson
When using concurrent maps (DashMap), remember that `insert(key, value.clone())` creates a separate copy. Mutations to the map entry don't affect the original. Always sync the local copy if it's returned to callers.

---

## Bug 4: Tokio Runtime Panic in Synchronous Tests

### Symptom
```
panicked at crates/puzzled/src/branch.rs:1005:
there is no reactor running, must be called from the context of a Tokio 1.x runtime
```

### Root Cause
`replay_network_journal()` used `tokio::spawn()` to asynchronously replay network journal entries. The integration tests run synchronously (plain `#[test]`, not `#[tokio::test]`), so there's no Tokio runtime available.

### Solution
Guard the spawn with a runtime check:
```rust
if let Ok(handle) = tokio::runtime::Handle::try_current() {
    handle.spawn(async move { /* ... */ });
} else {
    tracing::debug!("skipping network journal replay (no Tokio runtime)");
}
```

### Lesson
Any code path that may be called from both async and sync contexts should guard `tokio::spawn()` with `Handle::try_current()`. This is especially important for "best-effort" background tasks that shouldn't fail the main operation.

---

## Bug 5: Rego Policy Path Matching (Relative vs Absolute)

### Symptom
```
panicked at 'commit with /usr/bin file should have been rejected'
```
The policy approved a commit containing `usr/bin/evil_binary` when it should have been rejected by the `no_system_modifications` rule.

### Root Cause
The diff engine produces **relative** paths (e.g., `usr/bin/evil_binary`) by stripping the upper directory prefix. But the Rego policy checked for **absolute** paths:

```rego
system_prefixes := ["/usr/bin/", "/usr/sbin/", ...]
startswith(change.path, prefix)  # "usr/bin/..." does NOT start with "/usr/bin/"
```

Note: The paths must stay relative because the commit executor uses `base_path.join(&change.path)` — if the path were absolute, `Path::join()` would discard the base.

### Solution
Normalize paths in the Rego rules using `trim_left`:
```rego
system_prefixes := ["usr/bin/", "usr/sbin/", ...]

violations[v] if {
    some change in input.changes
    some prefix in system_prefixes
    path := trim_left(change.path, "/")  # handles both relative and absolute
    startswith(path, prefix)
    # ...
}
```

### Lesson
When a pipeline has multiple stages (diff engine → policy evaluation → commit executor), path conventions must be consistent. Document whether paths are relative or absolute, and make consumers handle both defensively.

---

## Bug 6: Test Assertions After Rollback

### Symptom
```
called `Option::unwrap()` on a `None` value
```
at `manager.inspect(&info.id).unwrap()` after rollback.

### Root Cause
The `rollback_internal()` method removes the branch from the DashMap after transitioning to `RolledBack`:
```rust
self.transition(id, BranchState::RolledBack)?;
self.branches.remove(id);  // C4: free the slot
```
The test expected to inspect the branch after rollback, but it no longer exists.

### Solution
Update test assertions to match actual behavior:
```rust
assert!(
    manager.inspect(&info.id).is_none(),
    "rolled-back branch should be removed from branch map"
);
```

---

## Key Takeaways

1. **VM environments differ from bare metal.** Lima VMs have quirks with `/proc` visibility, `setns()` behavior, and mount propagation. Design for the lowest common denominator or test on your target environment early.

2. **clone3's custom stack is dangerous with Rust.** The compiler's register allocation is not stable across code changes. A custom stack that works today may SIGSEGV tomorrow after an unrelated code change. Use `stack=0` for fork-like semantics.

3. **Raw `write(2, msg, len)` is the ultimate debugger for clone3 children.** Standard I/O (`eprintln!`, `tracing::error!`) may not work in clone3 children. Raw syscalls to fd 2 bypass all Rust machinery and always work — if even those don't appear, the child never started executing.

4. **DashMap mutations don't propagate to clones.** After `insert(key, value.clone())`, the map entry and the original are independent. If you return the original, sync it manually.

5. **Guard `tokio::spawn` with `Handle::try_current()`** when code may be called from sync contexts.

6. **Path conventions must be documented and tested.** The diff engine, policy engine, and commit executor each assume different path formats. A single `trim_left(path, "/")` in the Rego policy fixed the mismatch.

7. **Diagnostic methodology matters.** The debugging progressed through layers:
   - Compilation errors → fixed with targeted code changes
   - Network namespace errors → tried 3 approaches before finding one that works
   - SIGSEGV with no output → added raw `write(2, ...)` probes to narrow down
   - State/assertion errors → read the source to understand actual behavior
