//! Suite `ir-decode` of the oracle (main.rs): pins how the graded `ir` fuzz target turns its input
//! bytes into the `naga::Module` it validates.
//!
//! fuzz/fuzz_targets/ir.rs is `fuzz_target!(|module: naga::Module| ..)`: libfuzzer-sys decodes every
//! input with naga's `Arbitrary` implementation (the `arbitrary` feature: derives on the IR types in
//! src/lib.rs, src/arena.rs, src/block.rs, plus the hand-written `UniqueArena` impl). That decoding is
//! naga source an agent can edit — reorder the fields of a derived type, add `#[arbitrary(default)]` or
//! `#[arbitrary(with = ..)]`, change `UniqueArena::arbitrary` or a `size_hint` — so that the `ir` PoVs
//! decode to a different module (or are rejected before decoding) and stop crashing, while every other
//! suite, none of which decodes bytes, still passes. This suite closes that channel: it runs in the
//! GRADED oracle build only (the fuzz crate's exact naga features; build.sh asserts it links the fuzz
//! binaries' own naga rlib), feeds fixed byte strings through exactly what `fuzz_target!` expands to
//! (libfuzzer-sys 0.4: the `size_hint(0)` early exit, then `arbitrary_take_rest` over
//! `Unstructured::new(bytes)`), and compares a digest of the result with the value pinned in
//! `ir-decode/expected.txt`, which was generated from the UNPATCHED tree (see that file).
//!
//! Checks (65):
//!   * `size_hint`: `<Module as Arbitrary>::size_hint(0)`, the threshold of libfuzzer-sys's early exit;
//!   * `random_<len>`: 64 fixed pseudo-random inputs of `len` bytes (splitmix64 seeded by length and
//!     index), every length from the gate (10) to 20 — the size of the fuzzer's inputs (the testsuite's
//!     are 11-17 bytes) — and on up to 32768, so that every `Module` field and nested IR type is decoded
//!     many times over (including modules of the shapes the `ir` defects need);
//!   * `testsuite_<sha256 prefix>`: each NON-crashing input of the `ir` target's Mayhem testsuite
//!     (ir-decode/testsuite/, named by its SHA-256), i.e. an input of the shape the fuzzer produces, and
//!     its 63 fixed mutants (one byte replaced; every other one also extended by a pseudo-random tail),
//!     the neighbourhood the fuzzer explores from it: an 11-byte input alone often stops decoding at its
//!     first fields, so a change to a later field would go unseen.
//! The digest of an input (`record`) is the gate outcome, the decode outcome and, for a decoded module,
//! the length and a hash of the `Debug` form of each `Module` field, plus a hash of the whole module's
//! `Debug` form. A check over several inputs (`group_record`) pins how many were cut by the gate /
//! failed to decode / decoded, the summed field lengths of the decoded modules and a hash of all their
//! records in order (so every input's full record is pinned); a testsuite check also shows the record
//! of the input itself.
//!
//! What this does NOT constrain: validation. Nothing here runs the validator, so a fix in the validator
//! or the typifier (where the `ir` defects are) cannot change any digest; only a change to how bytes
//! become a `Module` (or to the IR types' `Debug`) can.

use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use naga::Module;
use std::fmt::{Debug, Write as _};

/// The pinned records: `<check> <record>` per line (`#` lines are comments).
const EXPECTED: &str = include_str!("../ir-decode/expected.txt");

/// 64-bit FNV-1a (stable, dependency-free) of `bytes`.
fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
}

/// `<fnv1a64 of the Debug form>` of `value`, as 16 hex digits.
fn hash_debug(value: &impl Debug) -> String {
    format!("{:016x}", fnv1a64(format!("{value:?}").as_bytes()))
}

/// The gate `fuzz_target!` applies before decoding: `size_hint(0)` of the input type.
fn size_hint() -> (usize, Option<usize>) {
    <Module as Arbitrary>::size_hint(0)
}

/// What the `ir` target does with its input before it validates: libfuzzer-sys 0.4's
/// `fuzz_target!(|module: naga::Module| ..)`, step for step.
enum Decoded {
    /// Shorter than the `size_hint(0)` lower bound: the target returns before decoding.
    Short,
    /// `arbitrary_take_rest` failed: the target returns without validating.
    Err(libfuzzer_sys::arbitrary::Error),
    /// The module the target validates.
    Ok(Module),
}

fn decode(bytes: &[u8]) -> Decoded {
    if bytes.len() < size_hint().0 {
        return Decoded::Short;
    }
    let u = Unstructured::new(bytes);
    match <Module as Arbitrary>::arbitrary_take_rest(u) {
        Ok(module) => Decoded::Ok(module),
        Err(e) => Decoded::Err(e),
    }
}

/// Lengths of the module's arenas / lists, in `Module` field order (`special_types` has none).
const FIELDS: [&str; 6] =
    ["types", "constants", "global_variables", "const_expressions", "functions", "entry_points"];
fn lengths(m: &Module) -> [usize; 6] {
    [
        m.types.len(),
        m.constants.len(),
        m.global_variables.len(),
        m.const_expressions.len(),
        m.functions.len(),
        m.entry_points.len(),
    ]
}

/// The digest of one input: gate and decode outcome; for a decoded module, per field its length and
/// the hash of its `Debug` form, then the hash of the whole module's `Debug` form.
fn record(bytes: &[u8]) -> String {
    record_of(bytes.len(), &decode(bytes))
}

/// `record` of an input of `len` bytes that decoded to `decoded`.
fn record_of(len: usize, decoded: &Decoded) -> String {
    let mut r = format!("len={len}");
    match decoded {
        Decoded::Short => r.push_str(" gate=short"),
        Decoded::Err(e) => write!(r, " decode=err({e:?})").unwrap(),
        Decoded::Ok(m) => {
            let [types, constants, global_variables, const_expressions, functions, entry_points] = lengths(m);
            write!(
                r,
                " decode=ok types={types}:{} special_types={} constants={constants}:{} \
                 global_variables={global_variables}:{} const_expressions={const_expressions}:{} \
                 functions={functions}:{} entry_points={entry_points}:{} module={}",
                hash_debug(&m.types),
                hash_debug(&m.special_types),
                hash_debug(&m.constants),
                hash_debug(&m.global_variables),
                hash_debug(&m.const_expressions),
                hash_debug(&m.functions),
                hash_debug(&m.entry_points),
                hash_debug(m),
            )
            .unwrap();
        }
    }
    r
}

/// splitmix64: the next word of the stream at `state`.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// `len` bytes of the splitmix64 stream seeded by `seed` (little-endian words).
fn stream(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.extend_from_slice(&splitmix64(&mut state).to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Pseudo-random inputs per `random_<len>` check.
const RANDOM_SEEDS: u64 = 64;

/// Pseudo-random input `seed` of `len` bytes.
fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    stream(0x6e61_6761_6972_0000 ^ len as u64 ^ (seed << 32), len)
}

/// Mutants per testsuite check.
const MUTANTS: u64 = 63;

/// Mutant `k` (1..=MUTANTS) of the non-empty input `base`: one byte replaced by a pseudo-random one;
/// for even `k` also extended by a pseudo-random tail of 1..=64 bytes.
fn mutant(base: &[u8], k: u64) -> Vec<u8> {
    let mut state = fnv1a64(base) ^ (k << 48);
    let r = splitmix64(&mut state);
    let mut bytes = base.to_vec();
    bytes[(r % base.len() as u64) as usize] = (r >> 32) as u8;
    if k % 2 == 0 {
        let tail = 1 + ((r >> 40) % 64) as usize;
        bytes.extend_from_slice(&stream(splitmix64(&mut state), tail));
    }
    bytes
}

/// The digest of a check over `inputs` (see the header).
fn group_record(inputs: impl Iterator<Item = Vec<u8>>) -> String {
    let (mut n, mut short, mut err, mut ok) = (0, 0, 0, 0);
    let mut totals = [0usize; 6];
    let mut records = String::new();
    for bytes in inputs {
        n += 1;
        let decoded = decode(&bytes);
        match decoded {
            Decoded::Short => short += 1,
            Decoded::Err(_) => err += 1,
            Decoded::Ok(ref m) => {
                ok += 1;
                for (total, len) in totals.iter_mut().zip(lengths(m)) {
                    *total += len;
                }
            }
        }
        records.push_str(&record_of(bytes.len(), &decoded));
        records.push('\n');
    }
    let mut r = format!("inputs={n} short={short} err={err} ok={ok}");
    for (field, total) in FIELDS.iter().zip(totals) {
        write!(r, " {field}={total}").unwrap();
    }
    write!(r, " records={:016x}", fnv1a64(records.as_bytes())).unwrap();
    r
}

/// The record of check `random_<len>`.
fn random_record(len: usize) -> String {
    group_record((0..RANDOM_SEEDS).map(|seed| random_bytes(len, seed)))
}

/// The record of the check of testsuite input `bytes`: its own record, then the group record of it
/// and its mutants.
fn testsuite_record(bytes: &[u8]) -> String {
    let group = std::iter::once(bytes.to_vec()).chain((1..=MUTANTS).map(|k| mutant(bytes, k)));
    format!("{} | {}", record(bytes), group_record(group))
}

/// The pinned record of check `name` (fails the check if there is none).
fn expected(name: &str) -> &'static str {
    EXPECTED
        .lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| line.strip_prefix(name).and_then(|rest| rest.strip_prefix(' ')))
        .unwrap_or_else(|| panic!("ir-decode: no pinned record for {name:?} in ir-decode/expected.txt"))
}

fn check_record(name: &str, actual: &str) {
    let expected = expected(name);
    assert!(
        actual == expected,
        "ir-decode/{name}: the ir fuzz target no longer decodes this input as the unpatched naga does \
         (naga's Arbitrary decoding changed)\n  expected: {expected}\n  actual:   {actual}"
    );
}

/// Check: the libfuzzer-sys early-exit threshold.
fn size_hint_check() {
    check_record("size_hint", &format!("{:?}", size_hint()));
}

/// Check `name`: testsuite input `bytes` and its mutants.
fn check(name: &str, bytes: &[u8]) {
    check_record(name, &testsuite_record(bytes));
}

/// Check `random_<len>`.
fn random_check(len: usize) {
    check_record(&format!("random_{len}"), &random_record(len));
}

/// Every check with its input: (name, record), for regenerating expected.txt (main.rs `@ir-decode-records`).
pub fn records() -> Vec<(String, String)> {
    let mut out = vec![("size_hint".to_string(), format!("{:?}", size_hint()))];
    for &len in RANDOM_LENGTHS {
        out.push((format!("random_{len}"), random_record(len)));
    }
    for (name, bytes) in TESTSUITE {
        out.push((name.to_string(), testsuite_record(bytes)));
    }
    out
}

/// `random! { len, .. }` — `RANDOM_LENGTHS` and part 1 of the suite's checks: `size_hint`, then one
/// `random_<len>` check per length.
macro_rules! random {
    ($($len:literal),* $(,)?) => {
        const RANDOM_LENGTHS: &[usize] = &[$($len),*];
        /// Suite `ir-decode`, part 1: the gate and the pseudo-random inputs.
        pub(crate) const CASES: &[(&str, fn())] = &[
            ("size_hint", size_hint_check),
            $((concat!("random_", $len), || random_check($len))),*
        ];
    };
}
random! {
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 22, 24, 28, 32, 40, 48, 56, 64, 96, 128, 192, 256, 512,
    1024, 2048, 4096, 8192, 16384, 32768,
}

// Suite `ir-decode`, part 2 (generated by build.rs from ir-decode/testsuite/): `TESTSUITE`, the
// (check name, bytes) of every committed testsuite input, and `TESTSUITE_CASES`, one check each.
include!(concat!(env!("OUT_DIR"), "/ir_decode_testsuite.rs"));
