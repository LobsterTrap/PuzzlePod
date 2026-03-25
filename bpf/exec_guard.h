/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * exec_guard.h — Shared types for the exec_guard BPF LSM program.
 *
 * Used by both the BPF program (exec_guard.bpf.c) and the userspace
 * loader (crates/puzzled/src/sandbox/bpf_lsm.rs).
 */

#ifndef __EXEC_GUARD_H
#define __EXEC_GUARD_H

/* Maximum number of tracked cgroups (agent branches). */
#define MAX_CGROUPS 256

/* Maximum exec rate window in nanoseconds (1 second). */
#define RATE_WINDOW_NS 1000000000ULL

/*
 * Per-cgroup exec counter — tracks total execs and rate limiting.
 *
 * Stored in BPF_MAP_TYPE_HASH keyed by cgroup ID (u64).
 */
struct exec_counter {
    /* Total number of execve() calls in this cgroup. */
    __u64 total;

    /* Timestamp (ktime_get_ns) of the start of the current rate window. */
    __u64 window_start_ns;

    /* Number of execs within the current rate window. */
    __u32 window_count;

    /* Padding for alignment. */
    __u32 _pad;
};

/*
 * Per-cgroup rate limit configuration.
 *
 * Stored in BPF_MAP_TYPE_HASH keyed by cgroup ID (u64).
 * Written by userspace (puzzled) when creating a branch.
 */
struct rate_limit_config {
    /* Maximum number of exec() calls per second. 0 = unlimited. */
    __u32 max_execs_per_second;

    /* Maximum total exec() calls for this branch. 0 = unlimited. */
    __u32 max_total_execs;

    /* If nonzero, all execs in this cgroup are denied. */
    __u32 kill_switch;

    /* Padding for alignment. */
    __u32 _pad;
};

#endif /* __EXEC_GUARD_H */
