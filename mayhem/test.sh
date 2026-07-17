#!/usr/bin/env bash
#
# mayhem/test.sh — RUN naga's functional oracle (already compiled by mayhem/build.sh) and report ONE
# CTRF summary over all suites. exit 0 iff no check failed.
#
# The oracle (mayhem/oracle) is ONE libFuzzer binary, naga_oracle, that build.sh built with
# `cargo fuzz build` exactly like the graded fuzz targets; every check runs the way libFuzzer runs a
# reproducer (one input file, one process, on the main thread under libFuzzer's own `main`), i.e. in the
# same kind of process as the graded code. This script compiles nothing.
#
# Suites (every check asserts BEHAVIOR/OUTPUT, not "the binary ran"):
#   1. wgsl-errors (upstream tests/wgsl-errors.rs; mayhem/oracle/build.rs makes its 68 #[test] functions
#      callable): parses invalid WGSL and asserts the EXACT rendered diagnostic against inline golden
#      snapshots, and validates WGSL modules (ValidationFlags::all(), Capabilities::default() — the ir
#      target's configuration) against expected results — covers the WGSL frontend and the validator
#      (the wgsl-parser and ir targets).
#   2. glsl-defines (mayhem/oracle/src/defines.rs): known-answer tests for front::glsl::Options::defines.
#      Each passes a non-empty map of VALID defines through Frontend::parse — i.e. it executes the
#      lexer's define-registration path, where the fuzzed glsl-parser defect lives — and asserts the
#      effect on the Module (branch taken, workgroup size, array length, literal). A patch that drops or
#      rejects defines fails them. None asserts what an INVALID define must do (that would fail on the
#      unpatched tree and dictate the fix).
#   3. glsl-golden (mayhem/oracle/src/golden.rs): one check per upstream tests/in/glsl shader (36),
#      against upstream's committed tests/out/wgsl/<name>.wgsl snapshot (nothing is written to the
#      tree): parse + validate + WGSL output byte-for-byte in the reference build; parse + validate
#      (as the ir target does) + module shape in the graded build (see golden.rs).
#   4. ir-decode (mayhem/oracle/src/ir_decode.rs; graded build only): pins how the ir target DECODES its
#      input. ir.rs is `fuzz_target!(|module: naga::Module| ..)`, so libfuzzer-sys turns the bytes into a
#      Module with naga's own (agent-editable) Arbitrary implementation, which no other suite exercises:
#      a patch that changed that decoding (field order, #[arbitrary(default)]/with attributes,
#      UniqueArena::arbitrary, a size_hint) would make the ir PoVs decode to other modules, or skip them,
#      and pass suites 1-3. Each check feeds a fixed input through exactly what fuzz_target! expands to
#      (the size_hint(0) early exit, then arbitrary_take_rest) and compares a digest of the resulting
#      Module (per field: length + hash of its Debug form) with the record pinned in
#      mayhem/oracle/ir-decode/expected.txt, generated from the UNPATCHED tree: the gate (size_hint), 30
#      checks of 64 pseudo-random inputs each (lengths 10..32768) and one check per NON-crashing input of
#      the ir testsuite (34; mayhem/oracle/ir-decode/testsuite/), each with 63 fixed mutants of it.
#      Nothing here validates, so a validator/typifier fix (where the ir defects are) cannot change a
#      digest.
# Suites 2-4 use naga's PUBLIC API only. Upstream's in-crate GLSL unit tests (cargo test --lib, incl.
# src/front/glsl/parser_tests.rs) are deliberately NOT used: they import crate internals from a file
# the agent never sees, so an honest patch that reshapes those internals would break the build with a
# cause it cannot inspect.
#
# Two builds of the oracle (both with cargo-fuzz's --cfg fuzzing, ASan, sancov, profile, target, lock):
#   - fuzz-features: the fuzz crate's exact naga features; links the fuzz binaries' OWN naga rlib.
#     It has no `span` feature, so the 17 wgsl-errors checks whose snapshots carry span labels
#     (SPAN_ONLY below) are skipped here, by exact name — and only here.
#   - span-wgsl-out: those features + `span` + `wgsl-out` (spans; the WGSL writer golden needs).
# Suites 1-3 run in both; ir-decode runs in fuzz-features only (the one build that decodes exactly as
# the ir binary does: `span` adds a field to naga's Arbitrary-derived Arena). A check counts as PASSED
# only if it passed in EVERY build that runs it; if either build fails it (panic, crash, sanitizer
# report, nonzero exit, missing executable, no PASS line) it counts as FAILED, once. So a change that
# only takes effect in the graded fuzz binaries (their features, their build flags, their libFuzzer
# process) fails the same checks it would fail if it were unconditional.
# Total: 68 + 11 + 36 + 65 = 180 checks.
#
# Protocol (mayhem/oracle/src/main.rs): input `@list <nonce>` lists the checks; input
# `<suite>/<name> <nonce>` runs one and prints `ORACLE-PASS <suite>/<name> <nonce>` iff it passed. The
# nonce is random per run, so only the oracle's own completed run can produce the PASS line.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

SUITES=(wgsl-errors glsl-defines glsl-golden ir-decode)
BUILDS=(span-wgsl-out fuzz-features)
# Checks each suite has; a check the oracle does not list (it crashed, is missing, ...) counts as failed.
declare -A EXPECTED=([wgsl-errors]=68 [glsl-defines]=11 [glsl-golden]=36 [ir-decode]=65)
# The upstream wgsl-errors tests whose rendered snapshots contain span labels naga records only with its
# `span` feature; without it they fail on the unpatched tree. Skipped in the fuzz-features build only.
SPAN_ONLY=(
  assign_to_expr assign_to_let bad_texture bad_type_cast constructor_parameter_type_mismatch
  function_param_redefinition_as_local function_param_redefinition_as_param invalid_arrays
  postfix_pointers struct_member_align_too_low struct_member_non_po2_align struct_member_size_too_low
  swizzle_assignment switch_signed_unsigned_mismatch unexpected_constructor_parameters unknown_ident
  unknown_identifier
)

ORACLE_BIN="$SRC/target/mayhem-oracle"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
NONCE="$(od -An -N8 -tx8 /dev/urandom | tr -d ' \n')"
mkdir -p "$WORK/in" "$WORK/out" "$WORK/artifacts"

# run_oracle <build> <input> — run <build>'s naga_oracle on ONE input file "<input> <nonce>", invoked as
# the graded binaries are (`<exe> <input file>`; libFuzzer writes a crash artifact into the working
# directory, $WORK/artifacts); output + "(exit N)" in $WORK/out/<build>.<input>.log.
run_oracle() {
  local build="$1" input="$2" f
  f="$build.${input//\//.}"
  printf '%s %s\n' "$input" "$NONCE" > "$WORK/in/$f"
  (cd "$WORK/artifacts" && "$ORACLE_BIN/$build/naga_oracle" "$WORK/in/$f") > "$WORK/out/$f.log" 2>&1 < /dev/null
  echo "(exit $?)" >> "$WORK/out/$f.log"
}
export -f run_oracle
export ORACLE_BIN WORK NONCE

# passed <build> <check> — did <build> run <check> to completion (PASS line with this run's nonce, exit 0)?
passed() {
  local log="$WORK/out/$1.${2//\//.}.log"
  [ -f "$log" ] && grep -qxF "ORACLE-PASS $2 $NONCE" "$log" && [ "$(tail -n1 "$log")" = "(exit 0)" ]
}

# 1. The checks: the union of what the builds list (a build's list counts only if it completed).
: > "$WORK/checks"
for b in "${BUILDS[@]}"; do
  echo "=== naga_oracle [$b]: $(readlink -f "$ORACLE_BIN/$b/naga_oracle" 2>/dev/null || echo MISSING)"
  run_oracle "$b" @list
  if grep -qxF "ORACLE-LIST-END $NONCE" "$WORK/out/$b.@list.log"; then
    sed -nE 's/^ORACLE-CASE ([^ ]+)$/\1/p' "$WORK/out/$b.@list.log" >> "$WORK/checks"
  else
    echo "ERROR: naga_oracle [$b] did not list its checks:" >&2
    tail -n 5 "$WORK/out/$b.@list.log" >&2
  fi
done
sort -u -o "$WORK/checks" "$WORK/checks"

# 2. Run every check in every build that runs it, in parallel.
# runs_in <build> <check> — every build runs every check, except: fuzz-features skips the SPAN_ONLY
# wgsl-errors checks, and only fuzz-features runs ir-decode.
runs_in() {
  case "$2" in
    wgsl-errors/*) [ "$1" != fuzz-features ] || ! printf '%s\n' "${SPAN_ONLY[@]}" | grep -qxF -- "${2#wgsl-errors/}" ;;
    ir-decode/*) [ "$1" = fuzz-features ] ;;
    *) true ;;
  esac
}
: > "$WORK/jobs"
while IFS= read -r c; do
  for b in "${BUILDS[@]}"; do
    runs_in "$b" "$c" || continue
    printf '%s %s\n' "$b" "$c" >> "$WORK/jobs"
  done
done < "$WORK/checks"
echo "=== running $(wc -l < "$WORK/checks") checks: $(wc -l < "$WORK/jobs") oracle runs, $MAYHEM_JOBS at a time"
xargs -P "$MAYHEM_JOBS" -L 1 bash -c 'run_oracle "$0" "$1"' < "$WORK/jobs"

# 3. Merge: a check PASSES iff every build that ran it passed it.
PASSED=0 FAILED=0
for s in "${SUITES[@]}"; do
  p=0 f=0 n=0
  while IFS= read -r c; do
    [ "${c%%/*}" = "$s" ] || continue
    n=$(( n + 1 )) state=ok failed_in=""
    for b in "${BUILDS[@]}"; do
      runs_in "$b" "$c" || continue
      if ! passed "$b" "$c"; then
        state=FAILED
        failed_in="$failed_in $b"
        why="$(grep -m1 -E "panicked at|ERROR: AddressSanitizer|ERROR: LeakSanitizer|deadly signal|no oracle check" \
                 "$WORK/out/$b.${c//\//.}.log" 2>/dev/null | cut -c1-160)"
        failed_in="$failed_in(${why:-$(tail -n1 "$WORK/out/$b.${c//\//.}.log" 2>/dev/null || echo 'no run')})"
      fi
    done
    if [ "$state" = ok ]; then p=$(( p + 1 )); else f=$(( f + 1 )); echo "    FAILED $c in:$failed_in"; fi
  done < "$WORK/checks"
  if [ "$n" -lt "${EXPECTED[$s]}" ]; then
    echo "ERROR: suite '$s' lists $n checks, expected ${EXPECTED[$s]} — the $(( ${EXPECTED[$s]} - n )) unlisted ones count as failed" >&2
    f=$(( f + ${EXPECTED[$s]} - n ))
  fi
  builds="${BUILDS[*]}"; [ "$s" = ir-decode ] && builds=fuzz-features
  echo "=== suite $s: $p passed, $f failed (builds: $builds)"
  PASSED=$(( PASSED + p )); FAILED=$(( FAILED + f ))
done

emit_ctrf "naga-oracle:wgsl-errors+glsl-defines+glsl-golden+ir-decode" "$PASSED" "$FAILED"
