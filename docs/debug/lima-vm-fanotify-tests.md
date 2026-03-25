# Debugging: Lima VM Fanotify Monitoring Tests

This document captures the debugging journey of getting the `fanotify_monitoring` integration tests passing on a Lima VM (aarch64 Linux on Apple Silicon macOS). It covers three distinct bugs across fanotify constant values, kernel FID mode semantics, and test lifecycle management.

**Tests:** `crates/puzzled/tests/fanotify_monitoring.rs` (5 tests, 3 require `sudo` on Linux)
**Command:** `sudo ~/.cargo/bin/cargo test -p puzzled --test fanotify_monitoring -- --include-ignored`
**Kernel:** 6.14.0-63.fc42.aarch64

---

## Table of Contents

1. [Environment](#environment)
2. [Bug 1: Wrong fanotify Event Constants](#bug-1-wrong-fanotify-event-constants)
3. [Bug 2: FAN_REPORT_FID Makes All Event fds Invalid](#bug-2-fan_report_fid-makes-all-event-fds-invalid)
4. [Bug 3: spawn_blocking Poll Thread Prevents Test Exit](#bug-3-spawn_blocking-poll-thread-prevents-test-exit)
5. [Diagnostic Methodology](#diagnostic-methodology)
6. [Key Takeaways](#key-takeaways)

---

## Environment

- **Host:** macOS on Apple Silicon (aarch64)
- **VM:** Lima VM running Fedora 42 Linux (aarch64 native)
- **Kernel:** 6.14.0-63.fc42.aarch64
- **Kernel features used:** `fanotify_init()`, `fanotify_mark()`, `epoll`, `FAN_REPORT_FID`, `FAN_REPORT_DIR_FID`

---

## Bug 1: Wrong fanotify Event Constants

### Symptom
```
fanotify_mark failed on /tmp/.tmpXXX/merged: Invalid argument (os error 22)
```
All three kernel-dependent tests (`test_mass_deletion_trigger`, `test_reads_below_threshold_no_trigger`, `test_credential_access_trigger`) failed at `FanotifyMonitor::init()` with EINVAL from `fanotify_mark`.

### Investigation

Initial hypothesis: `FAN_REPORT_FID` + `FAN_MARK_MOUNT` + directory events (`FAN_DELETE`, `FAN_CREATE`) are incompatible on some kernels.

Added a fallback from `FAN_MARK_MOUNT` to `FAN_MARK_FILESYSTEM` on EINVAL. Still failed.

Added `FAN_REPORT_DIR_FID` to the init flags (required for directory events on kernel 5.9+). Still failed.

**Breakthrough: Wrote a diagnostic probe** (`fanotify_probe.rs`) that tested every combination of init flags, mark types, and event masks. The probe revealed that `FAN_DELETE` and `FAN_CREATE` failed with EINVAL regardless of ANY init or mark flags — even with no FID flags at all (`NOTIF_ONLY`). This meant the constants themselves were wrong.

### Root Cause

The event mask constants were shifted 16 bits too far:

| Constant | Wrong Value | Correct Value | What It Actually Was |
|---|---|---|---|
| `FAN_DELETE` | `0x0200_0000` | `0x0000_0200` | Invalid bit (no kernel meaning) |
| `FAN_CREATE` | `0x0100_0000` | `0x0000_0100` | Invalid bit (no kernel meaning) |
| `FAN_CLOSE_WRITE` | `0x0000_0010` | `0x0000_0008` | Actually `FAN_CLOSE_NOWRITE` |

The `0x0200_0000` and `0x0100_0000` values don't correspond to any valid fanotify event bit, so the kernel unconditionally rejects them. The probe was invaluable because it proved the problem was orthogonal to init flags and mark types — narrowing the root cause to the mask values.

### Solution
Fixed constants in both the init mask and `classify_event()` to match `include/uapi/linux/fanotify.h`:
```rust
const FAN_OPEN: u64 = 0x0000_0020;
const FAN_CLOSE_WRITE: u64 = 0x0000_0008;  // was 0x0000_0010 (FAN_CLOSE_NOWRITE)
const FAN_DELETE: u64 = 0x0000_0200;        // was 0x0200_0000
const FAN_CREATE: u64 = 0x0000_0100;        // was 0x0100_0000
```

### Lesson
**Always verify kernel constants against the actual kernel headers** (`include/uapi/linux/fanotify.h`). Constants with similar hex patterns (e.g., `0x0200` vs `0x0200_0000`) are easy to confuse, and the kernel provides no helpful error message — just EINVAL. A systematic probe of all flag combinations is the fastest way to isolate constant-value bugs.

### Files Changed
- `crates/puzzled/src/sandbox/fanotify.rs` — Fixed `FAN_DELETE`, `FAN_CREATE`, and `FAN_CLOSE_WRITE` constants in both `init()` and `classify_event()`

---

## Bug 2: FAN_REPORT_FID Makes All Event fds Invalid

### Symptom
After fixing the constants, `test_mass_deletion_trigger` and `test_reads_below_threshold_no_trigger` passed, but `test_credential_access_trigger` failed:
```
credential access counter should be > 0 after reading id_rsa
```
The reads counter incremented (confirming `FAN_OPEN` events were received), but credential detection never triggered.

### Investigation

Added diagnostic output to the test:
```
[diag] cred_file readlink: /tmp/.tmpL5DrCy/merged/.ssh/id_rsa
[diag] reads before cred read: 3
[diag] reads after cred poll: 4
[diag] credential_accesses: 0
```

This proved:
1. Path resolution works from the test process (readlink returns the correct path)
2. The `FAN_OPEN` event for the credential file was received (reads 3→4)
3. But `credential_accesses` stayed at 0

Added diagnostic `eprintln` inside `classify_event()` in the path-resolution branch:
```rust
if event.fd >= 0 {
    // ... diagnostic prints ...
}
```
**No output appeared.** This meant `event.fd < 0` for ALL events — even `FAN_OPEN` events that don't require FID.

### Root Cause

Any FID flag (`FAN_REPORT_FID` or `FAN_REPORT_DIR_FID`) on the `fanotify_init` call causes **all** events in that fanotify group to have `fd = FAN_NOFD (-1)`, regardless of the event type. This is a kernel-wide behavior, not per-event-type:

```
fanotify_init flags              FAN_OPEN fd    FAN_DELETE fd
────────────────────────────────────────────────────────────
No FID flags                     valid fd       N/A (EINVAL)
FAN_REPORT_FID                   -1 (FAN_NOFD)  N/A (EINVAL)
FAN_REPORT_DIR_FID               -1 (FAN_NOFD)  -1 (FAN_NOFD)
FAN_REPORT_FID|FAN_REPORT_DIR_FID -1 (FAN_NOFD) -1 (FAN_NOFD)
```

The credential detection code resolves file paths via `readlink(/proc/self/fd/<fd>)` — which requires a valid fd. With `fd = -1`, path resolution returns `None` and credential pattern matching is skipped entirely.

But `FAN_DELETE`/`FAN_CREATE` events require `FAN_REPORT_DIR_FID` in the init flags. So we can't have both fd-based path resolution AND directory event monitoring in a single fanotify group.

### Failed Approach: FAN_REPORT_DIR_FID Without FAN_REPORT_FID

Hypothesis: using `FAN_REPORT_DIR_FID` without `FAN_REPORT_FID` would give PATH events (with valid fd) for `FAN_OPEN` and NAME events (with `fd=-1`) for `FAN_DELETE`.

Kernel source analysis suggested this should work:
```c
// In fanotify_alloc_event():
if (name_event && (fid_mode & FAN_REPORT_DIR_FID)) {
    event = fanotify_alloc_name_event();  // FAN_DELETE → fd=-1
} else if (fid_mode & FAN_REPORT_FID) {
    event = fanotify_alloc_fid_event();   // FAN_OPEN → fd=-1
} else {
    event = fanotify_alloc_path_event();  // FAN_OPEN → fd=valid
}
```

**Reality on kernel 6.14:** Even with `FAN_REPORT_DIR_FID` alone (no `FAN_REPORT_FID`), all events had `fd = -1`. The source analysis was incorrect for this kernel version — the actual behavior makes all events FID-mode when any FID flag is set.

### Solution: Two Fanotify Groups

Create two separate fanotify instances, each optimized for its purpose:

```
Group 1 (FID group):  fanotify_init(FAN_REPORT_DIR_FID | FAN_NONBLOCK)
                      fanotify_mark(FAN_DELETE | FAN_CREATE | FAN_ONDIR)
                      → Events have fd=-1, used for deletion/creation COUNTING only

Group 2 (Path group): fanotify_init(FAN_NONBLOCK)  // NO FID flags
                      fanotify_mark(FAN_OPEN | FAN_CLOSE_WRITE)
                      → Events have valid fd, used for path resolution,
                        credential detection, and touched-file tracking
```

Both fds are added to a single epoll instance. The `classify_event()` function works unchanged — it already handles both `fd >= 0` (path resolution) and `fd < 0` (mask-only counting).

### Files Changed
- `crates/puzzled/src/sandbox/fanotify.rs`:
  - Struct: `fanotify_fd` → `fid_fd` + `path_fd`
  - `init()`: Creates two fanotify groups with separate masks
  - `poll_loop()`: Adds both fds to epoll, reads from whichever triggers
  - `Drop`: Closes both fds

---

## Bug 3: spawn_blocking Poll Thread Prevents Test Exit

### Symptom
After fixing bugs 1 and 2, tests that passed would cause the test process to hang indefinitely instead of exiting. Tests that failed also hung (masking the error message until the process was killed).

### Root Cause
The `start()` method spawns the poll loop via `tokio::task::spawn_blocking()`. This creates a thread in tokio's blocking thread pool. The poll loop runs until the `shutdown` flag is set.

The tests never set the shutdown flag:
```rust
let (mut rx, counters, _touched, _needs_full_diff, _shutdown) = monitor.start();
// ... test logic ...
// shutdown flag never set → poll thread runs forever
```

When the test function returns (or panics), the `#[tokio::test]` runtime is dropped. But `spawn_blocking` threads are not cancelled on runtime shutdown — they continue running. The test binary's process can't exit because live non-daemon threads exist.

This was particularly insidious for failing tests: the assertion panic occurred, but `shutdown.store(true, ...)` was placed after the assertions and thus never executed, so the poll thread ran forever and the process hung without printing the failure message.

### Solution
Added a `ShutdownGuard` that sets the shutdown flag on drop — including during panic unwind:
```rust
struct ShutdownGuard(Arc<AtomicBool>);
impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

// In each test:
let (mut rx, counters, _touched, _needs_full_diff, shutdown) = monitor.start();
let _guard = ShutdownGuard(shutdown.clone());
// Guard is dropped when test exits (normally or via panic)
```

### Lesson
**Always use RAII guards for thread lifecycle management in tests.** Placing cleanup code after assertions doesn't work because panics skip subsequent statements. A `Drop`-based guard ensures cleanup runs on both success and failure paths. This applies to any test that spawns background threads or tasks.

### Files Changed
- `crates/puzzled/tests/fanotify_monitoring.rs` — Added `ShutdownGuard` struct; all three kernel tests use it

---

## Diagnostic Methodology

### The Probe Technique (Bug 1)

When `fanotify_mark` returned EINVAL, the error was opaque — the kernel provides no detail about which flag or mask bit is invalid. The breakthrough was writing a **systematic probe** (`fanotify_probe.rs`) that tested every combination:

- 4 init flag sets × 3 mark types × 8 event masks = 96 combinations
- Printed a matrix showing OK/FAIL for each

This immediately revealed the pattern: `FAN_DELETE` and `FAN_CREATE` failed in ALL combinations, proving the constants themselves were wrong (rather than any flag incompatibility).

### The Absent Diagnostic Technique (Bug 2)

Adding a diagnostic `eprintln` inside a code path and observing that it **never prints** is as informative as seeing its output. When the diagnostic inside `if event.fd >= 0 { ... }` never printed, it proved `event.fd < 0` for all events — ruling out path resolution bugs and narrowing the issue to the FID mode behavior.

### The Counter Delta Technique (Bug 2)

Adding counter snapshots before and after an operation:
```
reads before: 3
reads after:  4  (delta = 1 → event was received)
credential_accesses: 0 (never incremented → path didn't match)
```
This separated "event not received" from "event received but not classified correctly" — two very different root causes.

---

## Key Takeaways

1. **Verify kernel constants against headers, not memory.** `FAN_DELETE = 0x0200` vs `0x0200_0000` is a 16-bit shift that produces completely valid-looking hex but is categorically wrong. The kernel gives no diagnostic — just EINVAL.

2. **FID mode in fanotify is all-or-nothing.** Any FID flag (`FAN_REPORT_FID`, `FAN_REPORT_DIR_FID`) causes ALL events in the group to have `fd = FAN_NOFD (-1)`. You cannot mix fd-based and FID-based events in a single fanotify group. Use two groups if you need both.

3. **Kernel source analysis can be wrong for specific versions.** The kernel source suggested `FAN_REPORT_DIR_FID` without `FAN_REPORT_FID` would give PATH events with valid fds. On kernel 6.14, this wasn't true. Always verify with actual runtime behavior, not source reading.

4. **Use RAII guards for test cleanup, not post-assertion code.** `Drop`-based guards run during panic unwind. Post-assertion cleanup does not. This is critical for tests that spawn background threads — an orphaned thread prevents the test process from exiting, masking the actual failure.

5. **Systematic probing beats hypothesis testing for opaque errors.** When the kernel only says EINVAL, testing 96 combinations in a matrix takes seconds and gives definitive answers. Four rounds of hypothesis-driven changes would have taken much longer.

6. **Two-group fanotify is the correct architecture** for behavioral monitoring that needs both directory event counting (requires FID) and file path resolution (requires fd). This is a stable pattern, not a workaround.
