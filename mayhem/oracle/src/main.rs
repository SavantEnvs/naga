//! naga's functional oracle (mayhem layer, not upstream): every check mayhem/test.sh runs, in ONE
//! libFuzzer binary that mayhem/build.sh builds with `cargo fuzz build` — the same command, flags,
//! profile, target, Cargo.lock and (for the graded build) naga features and target dir that build the
//! graded fuzz targets, so the graded build links the very naga rlib the fuzz binaries link.
//!
//! Why a fuzz target and not libtest: a check must run in the same kind of process as the graded
//! code. Here, as in the fuzz binaries, libFuzzer's `main` drives `LLVMFuzzerTestOneInput`
//! (libfuzzer-sys) on the process's main thread, without the Rust runtime's `main` and without
//! libtest's named test threads. So code that looks for the fuzzer at run time (its entry points, the
//! libFuzzer runtime, the thread it runs on) finds it in the checks too, not only in the graded
//! binaries.
//!
//! Protocol (mayhem/test.sh): run the binary on ONE input file, as libFuzzer runs a reproducer.
//!   `@list <nonce>`         -> print `ORACLE-CASE <suite>/<name>` per check, then `ORACLE-LIST-END <nonce>`
//!   `<suite>/<name> <nonce>` -> run that check; print `ORACLE-PASS <suite>/<name> <nonce>` iff it
//!                               returned. A failed assertion panics, which libfuzzer-sys turns into
//!                               an abort (a crash), so the PASS line is never printed.
//!   `@ir-decode-records <nonce>` -> print `IR-DECODE-RECORD <name> <record>` per `ir-decode` check,
//!                               then `IR-DECODE-END <nonce>` (regenerates ir-decode/expected.txt;
//!                               test.sh never uses it)
//! The nonce is test.sh's per-run random token, so a PASS line is only ever this binary's own output.
//!
//! Suite `ir-decode` (ir_decode.rs) exists in the graded build only: it pins how the `ir` target
//! decodes bytes into a `naga::Module`, and the reference build's `span` feature adds a field to
//! naga's Arbitrary-derived `Arena`, i.e. decodes every input differently by design.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// `checks! { f, g, .. }` — this module's check table: `pub(crate) const CASES: &[(name, fn)]`.
macro_rules! checks {
    ($($check:ident),* $(,)?) => {
        /// This suite's checks, in order: (name, check). A check passes iff it returns.
        pub(crate) const CASES: &[(&str, fn())] = &[$((stringify!($check), $check)),*];
    };
}

mod common;
/// Suite `glsl-defines`.
mod defines;
/// Suite `glsl-golden`.
mod golden;
/// Suite `ir-decode` (graded build only; see above).
#[cfg(not(feature = "span"))]
mod ir_decode;
// Suite `wgsl-errors`: upstream's tests/wgsl-errors.rs, made callable outside libtest by build.rs.
include!(concat!(env!("OUT_DIR"), "/wgsl_errors_mod.rs"));

/// Every suite: (name, checks); a suite may span several entries (`ir-decode`: gate + pseudo-random
/// inputs, then the testsuite inputs).
#[cfg(not(feature = "span"))]
const SUITES: &[(&str, &[(&str, fn())])] = &[
    ("wgsl-errors", wgsl_errors::CASES),
    ("glsl-defines", defines::CASES),
    ("glsl-golden", golden::CASES),
    ("ir-decode", ir_decode::CASES),
    ("ir-decode", ir_decode::TESTSUITE_CASES),
];
#[cfg(feature = "span")]
const SUITES: &[(&str, &[(&str, fn())])] = &[
    ("wgsl-errors", wgsl_errors::CASES),
    ("glsl-defines", defines::CASES),
    ("glsl-golden", golden::CASES),
];

fuzz_target!(|data: &[u8]| {
    let input = std::str::from_utf8(data).expect("oracle input is not UTF-8");
    let (id, nonce) = input.trim_end().split_once(' ').expect("oracle input is not `<check> <nonce>`");
    if id == "@list" {
        for (suite, cases) in SUITES {
            for (name, _) in cases.iter() {
                println!("ORACLE-CASE {suite}/{name}");
            }
        }
        println!("ORACLE-LIST-END {nonce}");
        return;
    }
    #[cfg(not(feature = "span"))]
    if id == "@ir-decode-records" {
        for (name, record) in ir_decode::records() {
            println!("IR-DECODE-RECORD {name} {record}");
        }
        println!("IR-DECODE-END {nonce}");
        return;
    }
    let (suite, name) = id.split_once('/').expect("oracle check id is not `<suite>/<name>`");
    let check = SUITES
        .iter()
        .filter(|(s, _)| *s == suite)
        .flat_map(|(_, cases)| cases.iter())
        .find(|(n, _)| *n == name)
        .map(|(_, check)| *check)
        .unwrap_or_else(|| panic!("no oracle check {id:?}"));
    check();
    println!("ORACLE-PASS {id} {nonce}");
});
