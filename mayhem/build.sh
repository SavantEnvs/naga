#!/usr/bin/env bash
#
# mayhem/build.sh — build naga's cargo-fuzz targets as sanitized libFuzzer binaries
# (OSS-Fuzz Rust path: cargo-fuzz + ASan via RUSTFLAGS), plus the functional oracle that
# mayhem/test.sh runs (mayhem/oracle, a libFuzzer binary built exactly like the fuzz targets — see below).
#
# Runs inside the commit image (RUST mayhem/Dockerfile) as `mayhem` in /mayhem.
# The Rust toolchain + cargo registry live at $CARGO_HOME=/opt/toolchains/rust/cargo
# (pinned by the Dockerfile ENV — absolute, $HOME-independent).
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE.
#   - This FIRST build (in CI, online) populates the cargo registry under $CARGO_HOME.
#   - The PATCH re-run resolves crates from that cache. The rlenv runtime exports
#     CARGO_NET_OFFLINE=true for the re-run so cargo won't try to refresh the
#     crates.io index over the (absent) network — so do NOT hard-code `--offline`
#     here (it would break this first, online build).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${MAYHEM_JOBS:=$(nproc)}"
# cargo-fuzz has no --jobs flag; cargo reads parallelism from CARGO_BUILD_JOBS.
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"

cd "$SRC"

# --- sanitizer + debug-info contract (SPEC §6.1 / §6.2 items 9-10) -----------------
# SANITIZER_FLAGS is the org-wide knob (clang-form default from the base image); for the
# Rust/cargo-fuzz path we translate "does it ask for ASan?" into the rustc sanitizer flag.
# cargo-fuzz turns on -Zsanitizer=address itself, but we pin it explicitly so the fuzzed
# PROJECT code (not just the harness) is instrumented. `--build-arg SANITIZER_FLAGS=` (empty)
# builds a natural-crash (no-sanitizer) binary.
: "${SANITIZER_FLAGS:=-fsanitize=address}"
RUST_SAN=""
case "$SANITIZER_FLAGS" in
  *address*) RUST_SAN="-Zsanitizer=address" ;;
esac

# RUST_DEBUG_FLAGS (SPEC §6.2 item 10): DWARF < 4 so Mayhem triage/gdb resolve source lines
# (Mayhem's tool can't read DWARF >= 4; rustc's default with modern LLVM is DWARF-5).
: "${RUST_DEBUG_FLAGS:=-Cdebuginfo=2 -Zdwarf-version=3 -Clinker=/opt/mayhem-dwarf3-anchor/cc-wrapper.sh}"

# --cfg fuzzing matches libfuzzer-sys; force-frame-pointers aids ASan backtraces.
export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing ${RUST_SAN} -Cforce-frame-pointers ${RUST_DEBUG_FLAGS}"

# naga ships its own cargo-fuzz crate (fuzz/) with all four targets; it builds cleanly on
# the pinned nightly, so we use it directly (leaves upstream untouched — nothing to add).
FUZZ_DIR="fuzz"
TRIPLE="x86_64-unknown-linux-gnu"

# Discover every target from the crate's fuzz_targets/ dir (one binary per target).
FUZZ_TARGETS=()
for f in "$FUZZ_DIR"/fuzz_targets/*.rs; do
  FUZZ_TARGETS+=("$(basename "${f%.*}")")
done
[ "${#FUZZ_TARGETS[@]}" -gt 0 ] || { echo "ERROR: no fuzz targets under $FUZZ_DIR/fuzz_targets/" >&2; exit 1; }

# --- functional oracle (for mayhem/test.sh), part 1 ------------------------------------
# test.sh must exercise the SAME program the graded fuzz binaries contain (#1460; fast_rsync #1122 is
# the reference pattern). A check compiled any other way than the fuzz targets is a different program:
# a patch gated on cfg(fuzzing), cfg(sanitize = "address"), debug_assertions, option_env!(..) or a naga
# feature could neuter naga inside the graded binaries while the checks still passed; a check run by
# libtest (named test threads, Rust runtime `main`, no fuzzer entry points) can be told apart at run
# time. So the oracle (mayhem/oracle: ALL checks, suites wgsl-errors, glsl-defines, glsl-golden and
# ir-decode) is itself a cargo-fuzz crate: ONE libFuzzer binary, `naga_oracle`, built with
# `cargo fuzz build` exactly like the targets (same flags, same environment, from a copy of the fuzz
# crate's Cargo.lock), twice:
#   - GRADED: the fuzz crate's EXACT naga feature set (the oracle's `default`), into the fuzz crate's own
#     target dir, after the fuzz targets. The build ASSERTS cargo reused the fuzz targets' naga rlib
#     ("Fresh"), so these checks link the very naga the fuzz binaries link (any drift of flags,
#     profile, lock or features would recompile naga and fail the build).
#   - REFERENCE: that set + `span` + `wgsl-out` (rendered diagnostics need spans, golden's WGSL
#     comparison needs the writer). naga is necessarily a second compile (two extra features), so it
#     runs in the BACKGROUND, into its own target dir, while the fuzz targets build. `span` cannot go
#     into the graded build: it adds a field to naga's Arbitrary-derived Arena, i.e. it would change
#     how every ir-target input decodes.
#   mayhem/test.sh runs every check in both builds (the graded build skips only the 17 wgsl-errors
#   checks whose snapshots need spans; ir-decode, which pins how the ir target decodes its input
#   bytes, runs in the graded build only) and counts a check as passed only if it passes in each build
#   that runs it.
# Air-gapped: naga is a path dependency; the one extra crate (`diff`) is resolved into the lock and the
# registry cache by the first (online) build. The oracle's lock is seeded from fuzz/Cargo.lock whenever
# it is absent (first build; a clean removes both locks), so the shared crates resolve to the versions
# the fuzz binaries are built from; an existing one is reused, so a re-run needs no network (a lock that
# drifted from the fuzz crate's would make naga non-fresh below and fail the build).
ORACLE_DIR="$SRC/mayhem/oracle"
ORACLE_BIN="$SRC/target/mayhem-oracle"             # <build>/naga_oracle links (what test.sh runs)
ORACLE_SPAN_TARGET="$SRC/target/mayhem-oracle-span" # target dir of the reference (span, wgsl-out) build
FUZZ_TARGET_DIR="$SRC/$FUZZ_DIR/target"

# oracle_build <label> <target-dir> [cargo fuzz build args...] — build naga_oracle the cargo-fuzz way
# (verbose cargo output in $ORACLE_BIN/<label>.log) and link it as $ORACLE_BIN/<label>/naga_oracle.
oracle_build() {
  local label="$1" target_dir="$2"; shift 2
  local exe="$target_dir/$TRIPLE/release/naga_oracle"
  echo "--- oracle build [$label]: cargo fuzz build --fuzz-dir mayhem/oracle -O --debug-assertions -v $* ---"
  cargo fuzz build --fuzz-dir "$ORACLE_DIR" -O --debug-assertions -v --target-dir "$target_dir" "$@" naga_oracle \
    > "$ORACLE_BIN/$label.log" 2>&1 || { tail -40 "$ORACLE_BIN/$label.log" >&2; return 1; }
  [ -x "$exe" ] || { echo "ERROR: oracle executable not found at $exe" >&2; return 1; }
  mkdir -p "$ORACLE_BIN/$label"
  ln -sfn "$exe" "$ORACLE_BIN/$label/naga_oracle"
  echo "oracle [$label] -> $exe"
}

# Resolve fuzz/Cargo.lock now (a no-op when it exists; `cargo fuzz build` would create the same one)
# and pin the oracle to it, so the background build can start before the fuzz targets are built. The
# oracle's lock is completed (+ `diff`) here, synchronously, so neither oracle build rewrites it.
cargo metadata --manifest-path "$FUZZ_DIR/Cargo.toml" --format-version 1 > /dev/null
if [ ! -f "$ORACLE_DIR/Cargo.lock" ]; then
  cp "$SRC/$FUZZ_DIR/Cargo.lock" "$ORACLE_DIR/Cargo.lock"
fi
cargo metadata --manifest-path "$ORACLE_DIR/Cargo.toml" --format-version 1 > /dev/null
rm -rf "$ORACLE_BIN"
mkdir -p "$ORACLE_BIN"
echo "=== oracle build [span-wgsl-out] started in the background (log: $ORACLE_BIN/span-wgsl-out.log) ==="
oracle_build span-wgsl-out "$ORACLE_SPAN_TARGET" --features span,wgsl-out > "$ORACLE_BIN/span-wgsl-out.out" 2>&1 &
ORACLE_SPAN_PID=$!
trap 'kill "$ORACLE_SPAN_PID" 2>/dev/null || true' EXIT

echo "=== cargo fuzz build (image nightly, ASan via RUSTFLAGS) ==="
echo "RUSTFLAGS=$RUSTFLAGS"
echo "targets: ${FUZZ_TARGETS[*]}"

# Use the image's DEFAULT toolchain (the Dockerfile pinned it). A `+toolchain`
# override would make rustup try to install another channel into the locked /opt/rust.
for t in "${FUZZ_TARGETS[@]}"; do
  echo "--- building fuzz target: $t ---"
  cargo fuzz build --fuzz-dir "$FUZZ_DIR" -O --debug-assertions "$t"
  bin="$SRC/$FUZZ_DIR/target/$TRIPLE/release/$t"
  [ -x "$bin" ] || { echo "ERROR: expected fuzz binary not found at $bin" >&2; exit 1; }
  cp "$bin" "/mayhem/$t"
  echo "built /mayhem/$t"
done

# --- functional oracle (for mayhem/test.sh), part 2 ------------------------------------
echo "=== oracle (mayhem/oracle): built exactly like the fuzz targets ==="
oracle_build fuzz-features "$FUZZ_TARGET_DIR"
# The graded-feature build must have REUSED the fuzz binaries' naga rlib, not compiled another one.
if grep -qE '^ *(Compiling|Dirty) naga v' "$ORACLE_BIN/fuzz-features.log" \
   || ! grep -qE "^ *Fresh naga v[^ ]+ \($SRC\)\$" "$ORACLE_BIN/fuzz-features.log"; then
  echo "ERROR: the oracle's graded-feature build did not reuse the fuzz targets' naga artifact — its flags," \
       "profile, features or Cargo.lock no longer match the fuzz crate's (fuzz/Cargo.toml changed?)" >&2
  grep -E '^ *(Fresh|Dirty|Compiling) naga v' "$ORACLE_BIN/fuzz-features.log" >&2 || true
  exit 1
fi
echo "oracle [fuzz-features] links the fuzz binaries' own naga build (Fresh)"
span_rc=0
wait "$ORACLE_SPAN_PID" || span_rc=$?
trap - EXIT
cat "$ORACLE_BIN/span-wgsl-out.out"
[ "$span_rc" -eq 0 ] || { echo "ERROR: oracle build [span-wgsl-out] failed (rc=$span_rc)" >&2; exit 1; }
for b in fuzz-features span-wgsl-out; do
  [ -x "$ORACLE_BIN/$b/naga_oracle" ] || { echo "ERROR: oracle executable '$b/naga_oracle' was not built" >&2; exit 1; }
done

echo "build.sh complete"
