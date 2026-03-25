#!/bin/bash
# run_all_tests.sh — Comprehensive test runner for PuzzlePod
#
# Runs all test suites in sequence and prints a summary at the end.
# Designed to be run inside a Lima VM (or any Linux with root).
#
# Usage:
#   sudo scripts/run_all_tests.sh          # Run all test suites
#   sudo scripts/run_all_tests.sh --quick  # Skip slow suites (rogue agent, security shell tests)
#
# Prerequisites:
#   - Linux (Lima VM, Fedora 42+, RHEL 10+)
#   - Run as root (sudo)
#   - puzzled built: CARGO_TARGET_DIR=/var/tmp/puzzlepod-target cargo build --workspace
#   - For Suite 3 (live D-Bus): puzzled must be running in another terminal
#   - For Suite 2 (rogue agent): puzzle-sandbox-demo must be built and test files in /tmp/security-tests/

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/var/tmp/puzzlepod-target}"
export CARGO_TARGET_DIR

# Limit parallel compilation to avoid OOM on memory-constrained VMs (8GB).
# puzzled test binaries are very large and multiple parallel rustc instances
# will exhaust memory and thrash swap.
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

QUICK_MODE=false
[ "${1:-}" = "--quick" ] && QUICK_MODE=true

# ─── Colors ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ─── State ───────────────────────────────────────────────────────────────────

SUITE_NAMES=()
SUITE_RESULTS=()    # PASS / FAIL / SKIP
SUITE_DETAILS=()    # One-line detail (e.g. "647 tests, 0 failures")
SUITE_DURATIONS=()
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
START_TIME=$(date +%s)

# ─── Helpers ─────────────────────────────────────────────────────────────────

record_result() {
    local name="$1" result="$2" detail="$3" duration="$4"
    SUITE_NAMES+=("$name")
    SUITE_RESULTS+=("$result")
    SUITE_DETAILS+=("$detail")
    SUITE_DURATIONS+=("${duration}s")
    case "$result" in
        PASS) TOTAL_PASS=$((TOTAL_PASS + 1)) ;;
        FAIL) TOTAL_FAIL=$((TOTAL_FAIL + 1)) ;;
        SKIP) TOTAL_SKIP=$((TOTAL_SKIP + 1)) ;;
    esac
}

print_header() {
    echo ""
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_suite() {
    local num="$1" name="$2" desc="$3"
    echo -e "${BOLD}[$num] $name${NC}"
    echo -e "${DIM}    $desc${NC}"
    echo ""
}

# ─── Checks ──────────────────────────────────────────────────────────────────

if [ "$(uname -s)" != "Linux" ]; then
    echo -e "${RED}ERROR: Must run on Linux (use Lima VM on macOS)${NC}"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}ERROR: Must run as root (sudo)${NC}"
    exit 1
fi

cd "$REPO_DIR"

# ─── Banner ──────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}======================================================================${NC}"
echo -e "${BOLD}  PuzzlePod — Comprehensive Test Suite${NC}"
echo -e "${BOLD}======================================================================${NC}"
echo ""
echo -e "  ${DIM}System :${NC} $(uname -r) ($(uname -m))"
echo -e "  ${DIM}Date   :${NC} $(date -Iseconds)"
echo -e "  ${DIM}Kernel :${NC} $(uname -v | cut -c1-60)"
echo -e "  ${DIM}Target :${NC} $CARGO_TARGET_DIR"
echo -e "  ${DIM}Mode   :${NC} $([ "$QUICK_MODE" = true ] && echo 'Quick (skipping slow suites)' || echo 'Full')"
echo ""
echo -e "  ${DIM}Test suites:${NC}"
echo -e "    ${DIM}1. Security shell tests     — Escape vectors, privilege escalation, bypass attempts${NC}"
echo -e "    ${DIM}2. Rogue agent (sandboxed)   — 50 attack scenarios inside puzzle-sandbox-demo${NC}"
echo -e "    ${DIM}3. Live D-Bus integration    — 36 tests against running puzzled daemon${NC}"
echo -e "    ${DIM}4. Cargo unit + integration  — 1858+ tests across all crates${NC}"
echo -e "    ${DIM}5. Cargo integration tests   — 196+ integration tests (root + Linux required)${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# Suite 1: Security Shell Tests
# ══════════════════════════════════════════════════════════════════════════════

print_header "Suite 1: Security Shell Tests"
print_suite 1 "tests/security/run_all.sh" \
    "10 shell-based test suites covering escape vectors, privilege escalation,
    seccomp bypass, Landlock bypass, cgroup escape, BPF bypass, fanotify bypass,
    network escape, policy bypass, and sandbox escape. Requires root + Linux.
    (test_rogue_agent is skipped here — it runs separately in Suite 2.)"

suite_start=$(date +%s)
set +e
bash tests/security/run_all.sh 2>&1
ret=$?
set -e
suite_duration=$(( $(date +%s) - suite_start ))

if [ $ret -eq 0 ]; then
    record_result "Security shell tests" "PASS" "10 test scripts" "$suite_duration"
    echo -e "\n  ${GREEN}PASS${NC}"
elif [ $ret -eq 77 ]; then
    record_result "Security shell tests" "SKIP" "Prerequisites not met" "$suite_duration"
    echo -e "\n  ${YELLOW}SKIP${NC}"
else
    record_result "Security shell tests" "FAIL" "Exit code $ret" "$suite_duration"
    echo -e "\n  ${RED}FAIL${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# Suite 2: Rogue Agent (Sandboxed via puzzle-sandbox-demo)
# ══════════════════════════════════════════════════════════════════════════════

print_header "Suite 2: Rogue Agent (Sandboxed)"
print_suite 2 "test_rogue_agent.sh via puzzle-sandbox-demo exec" \
    "50 attack scenarios executed INSIDE a puzzle-sandbox-demo container with full
    Landlock, seccomp, namespace, and cgroup enforcement. Tests include:
    filesystem escape, sensitive file access, /proc info leaks, network
    attempts, SUID escalation, symlink attacks, and resource exhaustion.
    Requires puzzle-sandbox-demo binary and test files copied to /tmp/security-tests/."

if [ "$QUICK_MODE" = true ]; then
    record_result "Rogue agent (sandboxed)" "SKIP" "Skipped in quick mode" "0"
    echo -e "  ${YELLOW}SKIP${NC}: Skipped in quick mode"
elif [ ! -x "$CARGO_TARGET_DIR/debug/puzzle-sandbox-demo" ]; then
    record_result "Rogue agent (sandboxed)" "SKIP" "puzzle-sandbox-demo not built" "0"
    echo -e "  ${YELLOW}SKIP${NC}: puzzle-sandbox-demo not built at $CARGO_TARGET_DIR/debug/puzzle-sandbox-demo"
else
    # N7: Use unpredictable temp directory to prevent symlink/race attacks on /tmp
    SECURITY_TEST_DIR=$(mktemp -d /tmp/security-tests.XXXXXX)
    cp "$REPO_DIR/tests/security/test_rogue_agent.sh" "$REPO_DIR/tests/security/helpers.sh" "$SECURITY_TEST_DIR/"
    suite_start=$(date +%s)
    set +e
    "$CARGO_TARGET_DIR/debug/puzzle-sandbox-demo" exec \
        --allow-read "$SECURITY_TEST_DIR" \
        -- bash "$SECURITY_TEST_DIR/test_rogue_agent.sh" 2>&1
    ret=$?
    set -e
    suite_duration=$(( $(date +%s) - suite_start ))

    if [ $ret -eq 0 ]; then
        record_result "Rogue agent (sandboxed)" "PASS" "50 attack scenarios" "$suite_duration"
        echo -e "\n  ${GREEN}PASS${NC}"
    else
        record_result "Rogue agent (sandboxed)" "FAIL" "Exit code $ret" "$suite_duration"
        echo -e "\n  ${RED}FAIL${NC}"
    fi
    rm -rf "$SECURITY_TEST_DIR" # R5: Clean up temp dir after test completes
fi

# ══════════════════════════════════════════════════════════════════════════════
# Suite 3: Live D-Bus Integration Tests
# ══════════════════════════════════════════════════════════════════════════════

print_header "Suite 3: Live D-Bus Integration Tests"
print_suite 3 "cargo test -p puzzled --test live_dbus_integration" \
    "36 tests against a RUNNING puzzled daemon over D-Bus. Tests cover:
    branch create/list/inspect/approve/reject/rollback, profile listing,
    input validation, rate limiting, concurrent access, full lifecycle,
    graduated trust (get/reset score, set override, list history),
    provenance chain (report/get records), and agent workload identity
    (get token, SPIFFE ID, JWKS endpoint).
    This suite automatically starts puzzled in the background, runs the tests,
    and stops puzzled when done. If puzzled is already running, it uses that instead.
    test_60 (full lifecycle rollback) takes ~2 min due to rate limit cooldown."

# Find puzzled binary — try CARGO_TARGET_DIR first, then release, then debug
PUZZLED_BIN=""
for candidate in \
    "$CARGO_TARGET_DIR/debug/puzzled" \
    "$CARGO_TARGET_DIR/release/puzzled" \
    "$REPO_DIR/target/release/puzzled" \
    "$REPO_DIR/target/debug/puzzled"; do
    if [ -x "$candidate" ]; then
        PUZZLED_BIN="$candidate"
        break
    fi
done

PUZZLED_STARTED_BY_US=false
PUZZLED_PID=""

# Check if puzzled is already running
if busctl --system list 2>/dev/null | grep -q "org.lobstertrap.PuzzlePod1"; then
    echo -e "  ${DIM}puzzled already running on system bus — using existing instance${NC}"
    echo ""
elif [ -z "$PUZZLED_BIN" ]; then
    record_result "Live D-Bus integration" "SKIP" "puzzled binary not found" "0"
    echo -e "  ${YELLOW}SKIP${NC}: puzzled binary not found. Build first:"
    echo -e "  ${DIM}    cargo build -p puzzled${NC}"
else
    # Ensure setup prerequisites exist
    if [ ! -d /etc/puzzled/profiles ] || [ -z "$(ls /etc/puzzled/profiles/*.yaml 2>/dev/null)" ]; then
        echo -e "  ${DIM}Running dev-setup.sh setup to install profiles/policies...${NC}"
        bash "$REPO_DIR/scripts/dev-setup.sh" setup >/dev/null 2>&1 || true
    fi

    # Clean stale branches to avoid Degraded state on startup
    rm -rf /var/lib/puzzled/branches/*/  2>/dev/null || true
    mkdir -p /var/lib/puzzled/branches/wal /run/puzzled

    echo -e "  ${DIM}Starting puzzled in background ($PUZZLED_BIN)...${NC}"
    RUST_LOG=puzzled=warn "$PUZZLED_BIN" &
    PUZZLED_PID=$!
    PUZZLED_STARTED_BY_US=true

    # Wait for D-Bus registration (up to 10 seconds)
    for i in $(seq 1 20); do
        if busctl --system list 2>/dev/null | grep -q "org.lobstertrap.PuzzlePod1"; then
            echo -e "  ${DIM}puzzled registered on D-Bus (PID $PUZZLED_PID)${NC}"
            echo ""
            break
        fi
        sleep 0.5
    done

    if ! busctl --system list 2>/dev/null | grep -q "org.lobstertrap.PuzzlePod1"; then
        echo -e "  ${RED}puzzled failed to register on D-Bus within 10s${NC}"
        kill "$PUZZLED_PID" 2>/dev/null || true
        wait "$PUZZLED_PID" 2>/dev/null || true
        PUZZLED_STARTED_BY_US=false
        record_result "Live D-Bus integration" "SKIP" "puzzled failed to start" "0"
    fi
fi

# Run the tests if puzzled is available
if busctl --system list 2>/dev/null | grep -q "org.lobstertrap.PuzzlePod1"; then
    suite_start=$(date +%s)
    set +e
    cargo test -p puzzled --test live_dbus_integration -- --test-threads=1 2>&1
    ret=$?
    set -e
    suite_duration=$(( $(date +%s) - suite_start ))

    if [ $ret -eq 0 ]; then
        record_result "Live D-Bus integration" "PASS" "36 tests" "$suite_duration"
        echo -e "\n  ${GREEN}PASS${NC}"
    else
        record_result "Live D-Bus integration" "FAIL" "Exit code $ret" "$suite_duration"
        echo -e "\n  ${RED}FAIL${NC}"
    fi
fi

# Stop puzzled if we started it
if [ "$PUZZLED_STARTED_BY_US" = true ] && [ -n "$PUZZLED_PID" ]; then
    echo -e "  ${DIM}Stopping puzzled (PID $PUZZLED_PID)...${NC}"
    kill "$PUZZLED_PID" 2>/dev/null || true
    wait "$PUZZLED_PID" 2>/dev/null || true
    echo -e "  ${DIM}puzzled stopped${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# Suite 4: Cargo Unit Tests (all crates)
# ══════════════════════════════════════════════════════════════════════════════

print_header "Suite 4: Cargo Unit Tests"
print_suite 4 "cargo test --workspace (excluding live_dbus_integration)" \
    "1858+ unit + integration tests across all crates (puzzled, puzzlectl, puzzled-types,
    puzzle-proxy, puzzle-hook, puzzle-init).
    Covers: config parsing, profile validation, policy evaluation, diff engine,
    WAL recovery, seccomp validation, audit store (incl. attestation chain,
    HMAC key corruption detection, NDJSON recovery, NDJSON/Merkle reconciliation
    on crash), Merkle tree (inclusion/consistency proofs with verification,
    persistence, domain separation, crash recovery with partial write truncation),
    metrics, D-Bus input validation, commit logic, conflict detection, budget
    tracking, IMA signing, graduated trust
    (5-tier scoring, behavioral baselines, MetricWindow anomaly detection,
    max_increase_per_day enforcement, admin overrides with expiry, history
    persistence, tier transitions), provenance chain (NDJSON storage, file
    tracing, causal chain grouping, record_file_changes/record_governance
    helpers, serialization roundtrips), agent workload identity (SPIFFE IDs,
    JWT-SVID issuance/verification with Ed25519, JWKS format, GovernanceClaims
    with DelegationMetadata, token expiration, wrong-key rejection),
    cross-module integration (14 tests: trust+provenance on commit/reject,
    full provenance chain with SDK-mode batch writes, behavioral anomaly→trust
    scoring, containment violation severity, trust tier transition with daily
    cap, admin overrides, history persistence across reload, provenance cleanup
    on rollback, baseline anomaly→scoring event mapping, full 3-module
    composition: trust+provenance+identity with JWT-SVID claim verification),
    Podman-native pivot (seccomp profile generation with NOTIFY/DENY/ALLOW
    tiers, Landlock rules generation with denylist filtering, OCI hook
    annotation contract, seccomp-Landlock cross-compatibility, full artifact
    generation flow, puzzle-hook OCI state parsing, puzzle-init Landlock
    rules parsing),
    compliance evidence generation (4 regulatory frameworks — EU AI Act,
    SOC 2, ISO 27001, NIST AI RMF — 28 control-to-event mappings, 3-state
    evaluation with diversity thresholds, gap analysis, per-profile branch
    stats, violation resolution tracking, Ed25519 package signing, NDJSON
    audit loading with parse diagnostics, RFC 3339 timestamp parsing with
    non-ASCII safety, executive summary generation, report package structure),
    security audit hardening (S1-S29: fail-closed canonicalize in Landlock,
    silent error logging in branch cleanup/cgroup/OverlayFS/BPF/XFS/IMA,
    H-23 timeout enforcement in all seccomp USER_NOTIF handlers, commit
    symlink read failure, mutex poison recovery logging, IMA clock skew
    detection, non-Linux stub fail-closed for fanotify/network/seccomp_ack,
    explicit seccomp_mode in all 23 profiles, DENY_SYSCALLS completeness
    vs Docker defaults, SENSITIVE_PATHS completeness, commit.rego cloud
    credential and shell history patterns, D-Bus approve/reject branch
    validate_and_authorize consistency;
    R1-R27: attestation D-Bus auth, credential query param warnings,
    netns path traversal validation, policy load error propagation,
    HMAC chain recovery logging, ensure_branch UID ownership + rate
    limiting, cgroup kill error logging, diff checksum logging, fanotify
    mutex poison data recovery, symlink parent traversal in Rego, TLS
    BasicConstraints depth, IMA sign method + key rotation O_EXCL,
    credential file mode 0o600 at creation, conflict detector bounds;
    S30-S49: user systemd/dbus/udev/modules-load persistence paths,
    shell rc and keytab/secring credential patterns in Rego, cgroup
    remove_scope kill logging, audit store truncate error propagation,
    ip_forward write logging, HMAC constant-time comparison, socketpair
    bounded allocation, AtomicU32 saturating counters, budget float-to-int
    .max(1), public key read logging, hex decode logging, metrics encode
    logging, cmsg_len validation, lgetxattr safe cast, trust score
    saturating arithmetic, entry_count safe 32-bit cast;
    F1-F28: dead Rego rule fix (change_type→kind), workspace boundary
    bypass prevention, additional persistence paths (ld.so.preload,
    pam.d, xdg/autostart, profile.d, environment.d, NetworkManager,
    anacron), privileged/standard profile denylist expansion, branch
    metadata serialization fallback, budget counter saturating_add,
    Merkle tree leaves cap, lifetime_minutes safe cast, budget agents
    HashMap cap, fallback transition logging, D-Bus signal emission
    logging, metrics socket/response logging, policy evaluation
    concurrency bound, nlmsg_len bounds check, fanotify timer handle
    storage, TLS MITM error response logging, QueueOverflow trigger
    logging, readlink trace logging, Content-Length parse logging,
    journal discard logging, puzzle-init Landlock skipped rule counting
    with strict mode, manifest hash serialization logging, SystemTime
    expect messages, directory entry error counting, trust score
    debug_assert;
    G1-G31: Merkle tree rotation-safe capping (no leaf clear), Merkle
    size u32 safe cast, audit timestamp datetime comparison, CSV formula
    injection prevention, fanotify fd double-close fix, unbounded TLS
    header buffer cap, credential auth_header Zeroizing, case-insensitive
    sensitive file detection in Rego, symlink workspace prefix-slash fix,
    missing change.size field rejection, puzzle-podman input validation
    (profile regex, base path, PODMAN env), puzzle-hook branch ID
    validation, privileged exec_denylist, policy watcher thread cap,
    audit recovery filter_map vs map_while, QueryParameter URL-encoding,
    Bearer case-insensitive stripping, proxy_ip pattern validation,
    fanotify event_len OOB check, credential exfil GET coverage, request
    body size limit, lgetxattr retry on size change, export file size
    cap, netlink fd=-1 on close, credential temp file create_new,
    audit log read size check, BranchId::From validation, profile name
    path traversal, Landlock env var debug-only gate;
    H1-H97: attestation subtree_hash/root_hash Result propagation
    (no assert!/expect panic), subtree_hash safe usize cast with
    bounds check, timeout_secs safe i64 cast, len/count safe u32 cast,
    metrics label cardinality cap (MAX_PROFILE_LABEL_LEN=64), pidfd
    close safe i32 cast, metrics HTTP slowloris timeout, apply_tier_limits
    returns Result (fail-closed cgroup writes), diff total_bytes
    saturating_add, approve_branch re-verifies cgroup freeze,
    fanotify touched_files bounded (MAX_TOUCHED_FILES=100K),
    to_string_lossy→to_str() for mount/chown/chdir paths (3 sites),
    child_pid safe i32 cast, nfds safe usize cast, proxy_url_len
    safe usize cast, fanotify_init safe i32 cast, overlay post-creation
    symlink verification (TOCTOU), credential path component-aware
    matching, nft short_id hex validation in setup_monitored, netns
    ready write() checked, send_fd() failure fatal in child, sentinel
    byte write checked, audit event uid injection for non-root
    visibility, count_existing_events single-fd TOCTOU fix, to_value
    unwrap→unwrap_or(Null), BTreeMap serialization expect→unwrap_or_else,
    hex parsing odd-length guard, trigger_governance audit logging,
    credential file error path redaction, audit query MAX_QUERY_LIMIT
    =10K, next_seq mutex invariant documented, ensure_branch audit
    logging, signing key file permissions check, nlmsghdr alignment-safe
    byte writes, command_json logged as length only, HMAC expect safety
    documented, forward_request fallback body size limit, TLS intercept
    case-insensitive Bearer/Basic, puzzlectl credential Zeroizing,
    inject_resolved_credential fail-closed on header error, TLS domain
    CR/LF validation, TLS path/method CR/LF validation, credential
    expiry parse fail-closed, parse_period_secs min length check,
    chrono_now pre-epoch fallback, stale BranchId test→should_panic,
    puzzle-podman command -v skip for remote, mkdir -m 0700, Rego
    credential patterns file-extension-specific, Rego persistence/
    system paths case-insensitive (lower()), hook stdin bounded read
    (1MiB), privileged/security-scanner/infrastructure-auditor denylist
    expansion, web-scraper *.org/*.gov/*.edu removed, ResourceLimits
    memory_bytes/storage_quota_mb validation, puzzle-podman approve
    fail-closed (no || true), hook D-Bus session bus debug-only gate,
    puzzle-podman branch ID format validation, container-builder/
    ci-runner exec_denylist + docker removal, ResourceLimits validate()
    caller obligation documented;
    J1-J88: budget float-to-u32 saturating helper, BPF map_fd/prog_fd
    safe u32 cast, BPF insn_cnt safe u32 cast, netns remove_file error
    logging, clone3 child_pid safe u32 cast, fanotify epoll fd safe
    i32 round-trip, attestation query unbounded for internal callers
    (None=unlimited vs Some=capped at 10K), activate_branch command_json
    length-only logging, attestation timestamp parsed datetime comparison,
    branch_chains HashMap bounded + remove_branch_chain(), audit seq
    checked_add overflow detection, bytes_read compile-time size assert,
    HMAC error no hash value disclosure, TLS intercept QueryParameter
    param_name URL-encoding, QueryParameter URI parse fail-closed,
    puzzlectl credential stdin bounded read (64KB), D-C2 phantom token
    case-insensitive prefix strip, parse_rfc3339_approx year range
    validation, copy_dir_files error propagation, Rego persistence
    exact files case-insensitive, Rego path traversal (..) rejection,
    privileged exec_denylist extended (18 binaries), puzzle-podman
    PUZZLECTL binary validation, puzzle-podman stderr not suppressed for
    governance artifacts, infrastructure-auditor/security-scanner
    denylist expansion (keytab, opasswd, ldap.conf), Rego symlink
    empty/missing target rejection, ResourceLimits memory_bytes/
    storage_quota_mb upper bounds, all profiles exec_denylist added,
    Landlock rules generation read_denylist/write_denylist filtering,
    profile_storage_quota integration test, deny_outside_workspace +
    max_file_count integration tests, safety-critical profile property
    tests, exec_denylist coverage test for networked profiles, baseline
    anomaly test unconditional assertion, rollback/create production
    code include_str! verification, audit sanitize_audit_field
    production pattern verification;
    K1-K87: Landlock rules path canonicalization, BPF syscall return
    safe i32 cast, seccomp inotify bounds clamp, D-Bus reason parameter
    sanitization, trust history query limit (10K), provenance record size
    limit (64KB), audit export OOM prevention, ensure_branch trust
    registration, trigger_governance policy decision audit, credential
    file symlink bypass via canonicalization, proxy error response
    information disclosure prevention (5 fixes), DNS rebinding check
    in Unrestricted/Monitored modes, base64 intermediate Zeroizing
    wrap, HKDF expect safety documentation, getrandom Result propagation,
    FileChange target field for symlink Rego validation (CRITICAL),
    puzzle-podman MERGED_DIR path validation, Rego null-byte-in-path
    rejection, Rego var/spool/at persistence path, puzzle-podman stderr
    suppression removal, puzzle-podman SECCOMP/LANDLOCK path validation,
    privileged profile write_denylist, zero signing key replaced with
    random ephemeral (HIGH), signing key length validation (>=32 bytes),
    SVID lifetime upper bound validation, provenance write lock bounded
    HashMap (10K), DLP/credential init fatal on enabled failure, config
    validation for svid_lifetime/initial_score/anomaly_threshold/
    phantom_entropy, trust score delta safe i32 clamp;
    L1-L61: compliance parse_period_secs checked_mul overflow,
    compliance parse_rfc3339_approx checked arithmetic chain,
    IMA key rotation saturating_mul for max_age_days, JWT expiry
    checked_add + i64::try_from (HIGH), sendmsg isize return no
    i32 truncation, replay start_index usize::try_from, proxy
    credential scan body size limit (HIGH), DLP error path body
    bounded, DLP entropy matcher MAX_ENTROPY_MATCHES=1000 cap,
    TLS error response write failures logged (10+ instances),
    WAL cleanup remove_file failure logged, WAL fsync failure
    logged, replay journal discard failure logged, WAL orphan
    cleanup read errors logged, puzzle-podman readlink -f symlink
    resolution for MERGED_DIR/SECCOMP_PATH/LANDLOCK_PATH,
    scenario executor shell injection removed (sh -c → direct exec)),
    HTTP proxy (handler, DLP inspection, credential store, phantom tokens,
    GeoIP, TLS MITM with Bearer prefix stripping, InjectionMethod dispatch
    (Bearer/Basic/Custom/QueryParameter/AwsSigV4), Blocked mode enforcement,
    non-phantom auth header stripping, dual phantom token stripping, journal
    credential redaction, credential zeroize, Content-Length response parsing,
    session timeout, credential body exfiltration check, credential backends
    with key derivation parity, VaultAuth variants, branch-scoped token
    revocation, chunked Transfer-Encoding decoding, duplicate Content-Length
    rejection (RFC 9112), HTTP header name/value validation (RFC 9110),
    StoredCredential Debug redaction);
    M1-M9: getrandom panic-free exit on failure, seccomp path
    normalize_path_components for logical '..' resolution,
    commit TOCTOU removal (always attempt renameat2 first),
    dead code removal (test_helpers::create_temp_branch_dir),
    compliance DEFAULT_ATTESTATION_DIR constant, report_version
    from CARGO_PKG_VERSION, seccomp EPOLL_TIMEOUT_MS named constant,
    diff max_depth_seen tracking with warn on MAX_DEPTH hit,
    branch audit outcome includes error message detail);
    N-series (5-pass production audit): signal handler graceful fallback,
    trust window_secs i64 overflow protection, trust history 10MB rotation,
    hardcoded proxy port replaced with config, config load() calls validate(),
    IMA build_canonical error propagation, SPIFFE URI branch_id validation,
    inject_fd denylist defense-in-depth, procmem null terminator rejection,
    validate_execve denylist raw_path check, socketpair u32 overflow check,
    CString post-fork error handling, DNS rebinding/SSRF/timeout error
    scrubbing, TLS credential zeroize documentation, QueryParameter URI
    redaction in journal, StoredCredential serde(skip), custom header
    journal redaction, Vault path traversal sanitization, scenario path
    traversal prevention, worker timeout, unbounded attestation file read,
    Rego deny_hardlinks/deny_device_files/configurable max_files,
    privileged profile exec_denylist+Gated mode, all profiles
    read_denylist/write_denylist defense-in-depth, hook fail-closed,
    systemd hardening directives, SELinux path consistency,
    cargo-deny advisory enforcement, CI credential stdin), and more.
    Excludes live_dbus_integration (already run in Suite 3).
    Runs on any platform (no root required, Linux-specific tests auto-skip)."

suite_start=$(date +%s)
set +e
# Run each crate individually to exclude the live_dbus_integration test binary.
# --skip only filters test function names, not binary names, so we use
# cargo test -p <crate> to avoid running the live_dbus_integration binary
# (which hangs if puzzled was just stopped).
cargo test -p puzzled --lib 2>&1 \
    && cargo test -p puzzled --test dbus_validation --test diff_engine --test crash_recovery \
       --test ima_integration --test phase2_features --test policy_evaluation \
       --test profile_validation --test seccomp_validation --test security_hardening \
       --test wal_recovery_execution --test wal_recovery --test wal_safety \
       --test podman_native_integration --test cross_module_integration 2>&1 \
    && cargo test -p puzzle-proxy 2>&1 \
    && cargo test -p puzzlectl 2>&1 \
    && cargo test -p puzzled-types 2>&1 \
    && cargo test -p puzzle-hook 2>&1 \
    && cargo test -p puzzle-init 2>&1
ret=$?
set -e
suite_duration=$(( $(date +%s) - suite_start ))

if [ $ret -eq 0 ]; then
    record_result "Cargo unit tests" "PASS" "1858+ tests across 6 crates" "$suite_duration"
    echo -e "\n  ${GREEN}PASS${NC}"
else
    record_result "Cargo unit tests" "FAIL" "Exit code $ret" "$suite_duration"
    echo -e "\n  ${RED}FAIL${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# Suite 5: Cargo Integration Tests (root + Linux, --include-ignored)
# ══════════════════════════════════════════════════════════════════════════════

print_header "Suite 5: Cargo Integration Tests (root + Linux)"
print_suite 5 "cargo test --workspace -- --include-ignored --test-threads=1" \
    "196+ integration tests that require root + Linux. Includes:
    - Branch lifecycle (create/activate/commit/rollback with real OverlayFS)
    - Sandbox containment (namespace isolation, Landlock enforcement, cgroup limits)
    - E2E adversarial (fork bombs, symlink attacks, clock manipulation, signal escape)
    - E2E scenarios (multi-step agent workflows with governance)
    - Concurrent branches (parallel branch operations, conflict detection)
    - Crash recovery (WAL replay after simulated crashes)
    - Fanotify monitoring (real fanotify fd-based file event tracking)
    - BPF LSM hooks (exec rate limiting via eBPF)
    - Rogue agent (cargo-based attack scenarios)
    - Seccomp notification handler (USER_NOTIF mediated syscalls)
    - Graduated trust (scoring persistence, tier transitions, behavioral baselines)
    - Provenance chain (NDJSON append/read, file tracing, chain grouping)
    - Agent workload identity (JWT-SVID issuance/verification, SPIFFE IDs, JWKS)
    - Cross-module integration (trust+provenance+identity wiring, 14 tests)
    - E2E governance lifecycle (3-act scenario: clean commit, secret leak, persistence
      attack — exercises trust trajectory, provenance chain, attestation, identity)
    - Podman-native pivot (seccomp/Landlock artifact generation, cross-compatibility)
    - Attestation: Merkle tree proofs (inclusion + consistency verification),
      Ed25519 signing, audit chain integrity, NDJSON/Merkle crash reconciliation
    - Agent proxy: DLP, credential backends, GeoIP, phantom tokens, TLS intercept
    - Landlock: credential store deny paths (/var/lib + /etc/puzzled/credentials)
    - puzzle-hook: OCI state parsing, annotation matching, stage determination
    - puzzle-init: Landlock rules parsing, ABI version handling
    These run with --test-threads=1 to avoid resource contention."

suite_start=$(date +%s)
set +e
# Run ignored integration tests per-binary to exclude live_dbus_integration.
# These tests require root + Linux (namespaces, cgroups, Landlock, OverlayFS).
cargo test -p puzzled --lib -- --include-ignored --test-threads=1 2>&1 \
    && cargo test -p puzzled \
       --test branch_lifecycle --test concurrent_branches --test sandbox_containment \
       --test e2e_adversarial --test e2e_scenarios --test crash_recovery \
       --test fanotify_monitoring --test bpf_lsm_hooks --test rogue_agent \
       --test seccomp_notif_handler \
       --test dbus_validation --test diff_engine --test ima_integration \
       --test phase2_features --test policy_evaluation --test profile_validation \
       --test seccomp_validation --test security_hardening \
       --test wal_recovery_execution --test wal_recovery --test wal_safety \
       --test podman_native_integration --test cross_module_integration \
       --test e2e_governance_lifecycle \
       -- --include-ignored --test-threads=1 2>&1 \
    && cargo test -p puzzle-proxy -- --include-ignored --test-threads=1 2>&1 \
    && cargo test -p puzzlectl -- --include-ignored --test-threads=1 2>&1 \
    && cargo test -p puzzled-types -- --include-ignored --test-threads=1 2>&1 \
    && cargo test -p puzzle-hook -- --include-ignored --test-threads=1 2>&1 \
    && cargo test -p puzzle-init -- --include-ignored --test-threads=1 2>&1
ret=$?
set -e
suite_duration=$(( $(date +%s) - suite_start ))

if [ $ret -eq 0 ]; then
    record_result "Cargo integration tests" "PASS" "196+ tests (root + Linux)" "$suite_duration"
    echo -e "\n  ${GREEN}PASS${NC}"
else
    record_result "Cargo integration tests" "FAIL" "Exit code $ret" "$suite_duration"
    echo -e "\n  ${RED}FAIL${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════

TOTAL_DURATION=$(( $(date +%s) - START_TIME ))
TOTAL_MINS=$((TOTAL_DURATION / 60))
TOTAL_SECS=$((TOTAL_DURATION % 60))

echo ""
echo -e "${BOLD}======================================================================${NC}"
echo -e "${BOLD}  Test Results Summary${NC}"
echo -e "${BOLD}======================================================================${NC}"
echo ""

# Column headers
printf "  ${BOLD}%-4s  %-30s  %-6s  %-8s  %s${NC}\n" "#" "Suite" "Result" "Time" "Details"
printf "  ${DIM}%-4s  %-30s  %-6s  %-8s  %s${NC}\n" "----" "------------------------------" "------" "--------" "-------"

for i in "${!SUITE_NAMES[@]}"; do
    result="${SUITE_RESULTS[$i]}"
    case "$result" in
        PASS) color="$GREEN" ;;
        FAIL) color="$RED" ;;
        SKIP) color="$YELLOW" ;;
        *)    color="$NC" ;;
    esac
    printf "  %-4s  %-30s  ${color}%-6s${NC}  %-8s  %s\n" \
        "$((i+1))" "${SUITE_NAMES[$i]}" "$result" "${SUITE_DURATIONS[$i]}" "${SUITE_DETAILS[$i]}"
done

echo ""
echo -e "  ${GREEN}Passed${NC} : $TOTAL_PASS"
echo -e "  ${RED}Failed${NC} : $TOTAL_FAIL"
echo -e "  ${YELLOW}Skipped${NC}: $TOTAL_SKIP"
echo -e "  ${DIM}Total time: ${TOTAL_MINS}m ${TOTAL_SECS}s${NC}"
echo ""

if [ $TOTAL_FAIL -gt 0 ]; then
    echo -e "${RED}${BOLD}  OVERALL: FAILED ($TOTAL_FAIL suite(s) failed)${NC}"
    echo ""
    exit 1
else
    echo -e "${GREEN}${BOLD}  OVERALL: PASSED ($TOTAL_PASS passed, $TOTAL_SKIP skipped)${NC}"
    echo ""
    exit 0
fi
