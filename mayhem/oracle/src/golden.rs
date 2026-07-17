//! GLSL golden tests over upstream's own corpus (suite `glsl-golden` of the oracle, main.rs): one
//! check per shader in `tests/in/glsl/`, each against upstream's committed snapshot
//! `tests/out/wgsl/<name>.wgsl`.
//!
//! mayhem/build.sh builds the oracle TWICE and mayhem/test.sh counts a check as passed only if it
//! passes in BOTH builds:
//!
//! * with naga's `wgsl-out` (the `span,wgsl-out` build): parse with the GLSL frontend, validate (all
//!   flags, all capabilities), write WGSL and compare it byte-for-byte with the snapshot — the same
//!   pipeline upstream's `convert_glsl_folder` snapshot test runs with `glsl-in,wgsl-out`, except
//!   that it compares in memory and writes nothing into the tree;
//! * with the graded fuzz crate's exact naga features (no `wgsl-out`: this build links the very naga
//!   rlib the fuzz binaries link, so it has no WGSL writer): parse, validate the way the `ir` fuzz
//!   target does (`ValidationFlags::all()`, `Capabilities::default()`, plus only the capabilities the
//!   shader itself needs), and check the parsed module's SHAPE against the same snapshot — the entry
//!   points (stage, name, workgroup size) and the number of functions, global variables, named
//!   constants and structs the WGSL writer emitted from it. So naga as the fuzz binaries contain it
//!   must accept every shader AND produce the module the reference build produces, not merely
//!   return `Ok`.
//!
//! Nothing here is an extra constraint on a correct fix: the shape is read off upstream's snapshot,
//! which the first build already requires byte-for-byte.

use naga::valid::Capabilities;
use naga::ShaderStage;
use crate::common::parse;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// (stage, GLSL source, path of the WGSL snapshot, snapshot text) of the corpus shader `file`.
fn load(file: &str) -> (ShaderStage, String, PathBuf, String) {
    let input = repo_root().join("tests/in/glsl").join(file);
    let golden = repo_root().join("tests/out/wgsl").join(format!("{file}.wgsl"));
    let stage = match file.rsplit('.').next() {
        Some("vert") => ShaderStage::Vertex,
        Some("frag") => ShaderStage::Fragment,
        Some("comp") => ShaderStage::Compute,
        _ => panic!("unknown GLSL shader extension: {file}"),
    };
    let source = read(&input);
    let expected = read(&golden);
    (stage, source, golden, expected)
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Reference build: full GLSL -> WGSL round trip, compared with the snapshot byte-for-byte.
#[cfg(feature = "wgsl-out")]
fn check(file: &str, _capabilities: Capabilities) {
    use naga::back::wgsl::{write_string, WriterFlags};

    let (stage, source, golden, expected) = load(file);
    let module = parse(stage, &[], &source);
    let info = crate::common::validate(&module);
    let actual = write_string(&module, &info, WriterFlags::empty())
        .unwrap_or_else(|e| panic!("WGSL write failed for {file}: {e:?}"));

    if actual != expected {
        let line = actual
            .lines()
            .zip(expected.lines())
            .position(|(a, e)| a != e)
            .unwrap_or_else(|| actual.lines().count().min(expected.lines().count()));
        panic!(
            "WGSL for {file} differs from {} at line {}:\n  got:      {:?}\n  expected: {:?}\n({} vs {} lines)",
            golden.display(),
            line + 1,
            actual.lines().nth(line),
            expected.lines().nth(line),
            actual.lines().count(),
            expected.lines().count(),
        );
    }
}

/// Graded build (naga exactly as the fuzz binaries link it): parse, validate like the `ir` target,
/// and compare the module's shape with the shape of the snapshot.
#[cfg(not(feature = "wgsl-out"))]
fn check(file: &str, capabilities: Capabilities) {
    let (stage, source, golden, expected) = load(file);
    let module = parse(stage, &[], &source);
    crate::common::validate_with(&module, capabilities);
    let actual = Shape::of_module(&module);
    let snapshot = Shape::of_wgsl(&expected);
    assert!(
        snapshot.entry_points.len() == 1,
        "{}: expected exactly one entry point in the snapshot, got {:?}",
        golden.display(),
        snapshot.entry_points
    );
    assert_eq!(
        actual,
        snapshot,
        "the module parsed from {file} does not have the shape of {}",
        golden.display()
    );
}

/// What the WGSL writer's module-level output reveals about a module: every entry point (stage,
/// name, workgroup size of a compute stage) in order, and how many regular functions, global
/// variables, named constants and (non-predeclared) structs it contains.
#[cfg(not(feature = "wgsl-out"))]
#[derive(Debug, PartialEq)]
struct Shape {
    entry_points: Vec<(ShaderStage, String, Option<[u32; 3]>)>,
    functions: usize,
    global_variables: usize,
    named_constants: usize,
    structs: usize,
}

#[cfg(not(feature = "wgsl-out"))]
impl Shape {
    fn of_module(module: &naga::Module) -> Self {
        let predeclared: Vec<_> = module.special_types.predeclared_types.values().collect();
        Shape {
            entry_points: module
                .entry_points
                .iter()
                .map(|ep| {
                    let size = (ep.stage == ShaderStage::Compute).then_some(ep.workgroup_size);
                    (ep.stage, ep.name.clone(), size)
                })
                .collect(),
            functions: module.functions.len(),
            global_variables: module.global_variables.len(),
            named_constants: module.constants.iter().filter(|(_, c)| c.name.is_some()).count(),
            structs: module
                .types
                .iter()
                .filter(|(h, ty)| {
                    matches!(ty.inner, naga::TypeInner::Struct { .. }) && !predeclared.contains(&h)
                })
                .count(),
        }
    }

    /// Parse the top-level (column-0) declarations of naga's WGSL writer output: `struct N {`,
    /// `const N: ..`, `var<..> N: ..`, `fn N(..`, and an entry point's stage attribute line
    /// (`@vertex`, `@fragment`, `@compute @workgroup_size(x, y, z)`) right before its `fn`.
    fn of_wgsl(wgsl: &str) -> Self {
        let mut shape = Shape {
            entry_points: Vec::new(),
            functions: 0,
            global_variables: 0,
            named_constants: 0,
            structs: 0,
        };
        let mut stage: Option<(ShaderStage, Option<[u32; 3]>)> = None;
        for line in wgsl.lines() {
            let line = line.trim_end();
            if let Some(attr) = line.strip_prefix('@') {
                let words: Vec<&str> = attr.splitn(2, ' ').collect();
                stage = match words[0] {
                    "vertex" => Some((ShaderStage::Vertex, None)),
                    "fragment" => Some((ShaderStage::Fragment, None)),
                    "compute" => {
                        let size = words
                            .get(1)
                            .and_then(|w| w.strip_prefix("@workgroup_size("))
                            .and_then(|w| w.strip_suffix(')'))
                            .map(|w| w.split(", ").map(|n| n.parse::<u32>().unwrap()).collect::<Vec<_>>())
                            .unwrap_or_else(|| panic!("unexpected compute stage line: {line:?}"));
                        Some((ShaderStage::Compute, Some([size[0], size[1], size[2]])))
                    }
                    _ => stage, // `@group(..) @binding(..)` before a `var`
                };
                continue;
            }
            if let Some(rest) = line.strip_prefix("fn ") {
                let name = rest.split('(').next().unwrap().to_string();
                match stage.take() {
                    Some((st, size)) => shape.entry_points.push((st, name, size)),
                    None => shape.functions += 1,
                }
            } else if line.starts_with("var ") || line.starts_with("var<") {
                shape.global_variables += 1;
            } else if line.starts_with("const ") {
                shape.named_constants += 1;
            } else if line.starts_with("struct ") {
                shape.structs += 1;
            }
        }
        shape
    }
}

/// `name => "file"` or `name => "file" [CAPABILITY, ..]`: the capabilities (beyond
/// `Capabilities::default()`) the shader needs to validate; used by the graded build only (the
/// reference build validates with all of them, as upstream's snapshot test does).
macro_rules! golden {
    ($($test:ident => $file:literal $([$($cap:ident),+])?,)*) => {
        $( fn $test() { check($file, Capabilities::default() $($(| Capabilities::$cap)+)?); } )*
        checks! { $($test,)* }
    };
}

golden! {
    bevy_2d_shader_frag_210 => "210-bevy-2d-shader.frag",
    bevy_2d_shader_vert_210 => "210-bevy-2d-shader.vert",
    bevy_shader_vert_210 => "210-bevy-shader.vert",
    collatz_comp_246 => "246-collatz.comp",
    casting_frag_277 => "277-casting.frag",
    matrix_cast_frag_280 => "280-matrix-cast.frag",
    preprocessor_if_frag_484 => "484-preprocessor-if.frag",
    out_of_bounds_panic_vert_800 => "800-out-of-bounds-panic.vert" [PUSH_CONSTANT],
    push_constant_frag_896 => "896-push-constant.frag" [PUSH_CONSTANT],
    implicit_conversions_frag_900 => "900-implicit-conversions.frag",
    lhs_field_select_frag_901 => "901-lhs-field-select.frag",
    constant_emitting_frag_931 => "931-constant-emitting.frag",
    for_loop_if_frag_932 => "932-for-loop-if.frag",
    bevy_pbr_frag => "bevy-pbr.frag",
    bevy_pbr_vert => "bevy-pbr.vert",
    bits_glsl_frag => "bits_glsl.frag",
    bool_select_frag => "bool-select.frag",
    buffer_frag => "buffer.frag",
    clamp_splat_vert => "clamp-splat.vert",
    constant_array_size_frag => "constant-array-size.frag",
    declarations_frag => "declarations.frag",
    expressions_frag => "expressions.frag",
    fma_frag => "fma.frag",
    functions_call_frag => "functions_call.frag",
    global_constant_array_frag => "global-constant-array.frag",
    images_frag => "images.frag",
    local_var_init_in_loop_comp => "local-var-init-in-loop.comp",
    long_form_matrix_frag => "long-form-matrix.frag",
    math_functions_frag => "math-functions.frag",
    prepostfix_frag => "prepostfix.frag",
    quad_glsl_frag => "quad_glsl.frag",
    quad_glsl_vert => "quad_glsl.vert",
    sampler_functions_frag => "sampler-functions.frag",
    samplers_frag => "samplers.frag",
    statements_frag => "statements.frag",
    vector_functions_frag => "vector-functions.frag" [FLOAT64],
}
