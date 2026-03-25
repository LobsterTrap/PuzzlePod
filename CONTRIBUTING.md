# Contributing to PuzzlePod

## Before You Push

Please run the full test suite locally before pushing changes:

```bash
sudo make test-all
```

This runs all 5 test suites (~920 tests total) and prints a summary at the end. If you're short on time, at minimum run the unit tests:

```bash
make test
```

Or run the same checks that CI runs (formatting, linting, tests, dependency audit):

```bash
make ci
```

### Test Suite Overview

| # | Suite | Make target | Standalone command | Requires |
|---|-------|-------------|---------------------|----------|
| 1 | Security shell tests | `sudo make test-security` | `sudo tests/security/run_all.sh` | Root + Linux |
| 2 | Rogue agent (sandboxed) | — | `sudo puzzle-sandbox-demo exec -- bash test_rogue_agent.sh` | Root + Linux + puzzle-sandbox-demo built |
| 3 | Live D-Bus integration | `make test-dbus` | `cargo test -p puzzled --test live_dbus_integration -- --test-threads=1` | Running puzzled (script handles this automatically) |
| 4 | Cargo unit tests | `make test` | `cargo test --workspace` | Any platform |
| 5 | Cargo integration tests | `sudo make test-integration` | `sudo cargo test --workspace -- --include-ignored --test-threads=1` | Root + Linux |

Use `--quick` to skip slow suites:

```bash
sudo scripts/run_all_tests.sh --quick
```

### Available Make Targets

Run `make help` for a full list of available targets. Key targets:

| Target | Description |
|--------|-------------|
| `make` | Build everything (Rust + BPF + SELinux) |
| `make build` | Build Rust workspace (debug) |
| `make release` | Build edge-optimized release |
| `make check` | Run fmt --check + clippy |
| `make fmt` | Format all Rust code |
| `make test` | Run unit tests |
| `make ci` | Run CI checks (fmt + clippy + test + deny) |
| `make container` | Build container image |
| `make install` | Install binaries, configs, man pages, units, policies |
| `make clean` | Remove build artifacts |
| `make check-deps` | Verify build dependencies are installed |

## Development Setup

### macOS (Lima VM)

The project requires Linux kernel primitives (namespaces, cgroups, Landlock, OverlayFS). On macOS, use the included Lima VM:

```bash
./scripts/lima-dev.sh setup    # Create + start VM (~10 min first time)
./scripts/lima-dev.sh shell    # Enter VM at project directory
```

### Linux (Native)

```bash
# Check what's installed
make check-deps

# Install build dependencies
sudo dnf install -y gcc gcc-c++ make cmake pkg-config \
  openssl-devel dbus-devel systemd-devel \
  clang llvm libseccomp-devel bpftool libbpf-devel \
  xfsprogs xfsprogs-devel nftables audit ima-evm-utils jq

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
make build
```

### Running puzzled for Development

```bash
sudo make dev-setup    # Create dirs, install config/profiles/policies
sudo make dev-start    # Start puzzled in foreground (Ctrl+C to stop)

# In another terminal:
mkdir -p /tmp/test
sudo target/release/puzzlectl branch create --profile=restricted --base=/tmp/test --command='["/bin/sleep","300"]'
sudo target/release/puzzlectl branch list
```

## Code Guidelines

- **Rust** for all userspace components. Build via Cargo workspace (`make build`).
- Run `make fmt` before committing.
- Run `make clippy` — CI enforces zero warnings.
- Clippy on macOS skips `#[cfg(target_os = "linux")]` files — CI catches lint errors locally missed. Check CI results.
- All D-Bus methods must be idempotent.
- `puzzlectl` output must be machine-parseable (JSON with `--output=json`).

### Code Comment Conventions

Source comments use prefixed tags to categorize design decisions:

| Prefix | Meaning | Example |
|--------|---------|---------|
| H | Hardening measure | H8: Policy evaluation timeout |
| M | Mitigation (for specific threat) | M10: Rate limiting branch creation |
| SC | Seccomp-specific design | SC1: TOCTOU-safe execve via ADDFD |
| DC | Design choice (trade-off) | DC2: Idempotency cache for D-Bus |

See `CLAUDE.md` for the full list.

## Adding Tests

- **Unit tests** go in the source file or in `crates/<crate>/tests/<module>.rs`.
- **Integration tests** that require root should be `#[ignore]` with a comment (e.g., `#[ignore] // Requires root on Linux`).
- **Security shell tests** go in `tests/security/test_<name>.sh` — they're auto-discovered by `run_all.sh`.
- When adding a new integration test file to `crates/puzzled/tests/`, update `scripts/run_all_tests.sh` and `.github/workflows/ci.yml` to include it in the explicit `--test` lists (the `live_dbus_integration` binary is excluded from general cargo test runs to avoid hangs).

## CI Pipeline

CI runs on GitHub Actions. See `.github/workflows/ci.yml`.

| Job | Stage | Trigger | What |
|-----|-------|---------|------|
| `ci` | ci | Every push | fmt + clippy + 647 unit tests + cargo-deny |
| `integration` | integration | Every push | Starts D-Bus + puzzled, runs 26 live D-Bus tests |
| `security-test` | integration | Manual/scheduled | 196 integration tests + shell security + rogue agent (privileged runner) |
| `release` | release | Manual (main only) | Release build + RPM spec validation |

## Commit Messages

- Use conventional commit style: `Fix:`, `Add:`, `Update:`, `Refactor:`, etc.
- Keep the first line under 72 characters.
- Reference issue numbers where applicable.
