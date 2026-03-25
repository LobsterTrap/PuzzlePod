// SPDX-License-Identifier: GPL-2.0
/*
 * exec_guard.bpf.c — BPF LSM program for per-cgroup exec rate limiting.
 *
 * Attaches to the bprm_check_security LSM hook. For each execve():
 *   1. Looks up the cgroup ID of the calling process.
 *   2. Checks the rate_limit_config map for this cgroup.
 *   3. If a config exists, enforces:
 *      - Kill switch (deny all execs).
 *      - Total exec limit.
 *      - Per-second rate limit.
 *   4. Updates the exec_counter map.
 *   5. Returns 0 (allow) or -EPERM (deny).
 *
 * If no config exists for the cgroup, the exec is allowed (passthrough).
 *
 * Build:
 *   clang -O2 -target bpf -g -c exec_guard.bpf.c -o exec_guard.bpf.o
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "exec_guard.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * Map: cgroup_id (u64) -> exec_counter
 *
 * Tracks exec counts and rate window state per cgroup.
 * Entries are created on first exec within a configured cgroup.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CGROUPS);
    __type(key, __u64);
    __type(value, struct exec_counter);
} exec_counters SEC(".maps");

/*
 * Map: cgroup_id (u64) -> rate_limit_config
 *
 * Configuration written by userspace (puzzled) when a branch is created.
 * Read-only from the BPF program's perspective.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CGROUPS);
    __type(key, __u64);
    __type(value, struct rate_limit_config);
} rate_limits SEC(".maps");

/*
 * LSM hook: bprm_check_security
 *
 * Called during execve() before the new program is loaded.
 * Returning non-zero denies the exec.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(exec_guard, struct linux_binprm *bprm, int ret)
{
    /* If a previous LSM already denied, propagate. */
    if (ret != 0)
        return ret;

    /* Get the cgroup ID of the current task. */
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    /* Look up rate limit config for this cgroup. */
    struct rate_limit_config *config = bpf_map_lookup_elem(&rate_limits, &cgroup_id);
    if (!config) {
        /* No config for this cgroup — allow (passthrough). */
        return 0;
    }

    /* Check kill switch. */
    if (config->kill_switch) {
        return -EPERM;
    }

    /* Get or create the exec counter for this cgroup. */
    struct exec_counter *counter = bpf_map_lookup_elem(&exec_counters, &cgroup_id);
    struct exec_counter new_counter = {};

    if (!counter) {
        /* First exec in this cgroup — initialize counter. */
        new_counter.total = 0;
        new_counter.window_start_ns = bpf_ktime_get_ns();
        new_counter.window_count = 0;
        bpf_map_update_elem(&exec_counters, &cgroup_id, &new_counter, BPF_ANY);
        counter = bpf_map_lookup_elem(&exec_counters, &cgroup_id);
        if (!counter)
            return -EPERM; /* Should not happen; fail closed. */
    }

    /* Check total exec limit. */
    if (config->max_total_execs > 0 && counter->total >= config->max_total_execs) {
        return -EPERM;
    }

    /* Check per-second rate limit. */
    if (config->max_execs_per_second > 0) {
        __u64 now = bpf_ktime_get_ns();
        __u64 elapsed = now - counter->window_start_ns;

        if (elapsed >= RATE_WINDOW_NS) {
            /* New window — reset. */
            counter->window_start_ns = now;
            counter->window_count = 0;
        }

        if (counter->window_count >= config->max_execs_per_second) {
            return -EPERM;
        }

        counter->window_count += 1;
    }

    /* Update total count. */
    counter->total += 1;

    return 0;
}
