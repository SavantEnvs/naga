//! Known-answer tests for `naga::front::glsl::Options::defines` — the preprocessor definitions a
//! caller passes to `Frontend::parse` ("akin to having `#define key value` for each pair", per the
//! `Options` docs). Every test passes a NON-EMPTY, VALID define map, so each one executes the
//! define-registration path in the GLSL lexer, then asserts the observable effect on the parsed
//! `Module` (branch taken, workgroup size, array length, literal value). Suite `glsl-defines` of the
//! oracle: each function below is one check, listed in the `checks!` table at the end (main.rs).
//!
//! Deliberately absent: any test of what an INVALID define value should do. The unpatched frontend
//! panics there (the fuzzed defect), and asserting a particular outcome (Err, skip, ...) would dictate
//! the fix rather than check behaviour every correct fix must keep.

use naga::ShaderStage::{Compute, Fragment};
use crate::common::{only_entry_point, parse, parse_with, validate};

/// A compute shader whose workgroup x-size is 2 when `KEY` is defined and 3 otherwise.
fn ifdef_workgroup(key: &str) -> String {
    format!(
        "#version 450\n#ifdef {key}\nlayout(local_size_x = 2) in;\n#else\nlayout(local_size_x = 3) in;\n#endif\nvoid main() {{}}\n"
    )
}

fn defined_key_enables_ifdef_block() {
    let src = "#version 450\n#ifdef USE_MAIN\nvoid main() {}\n#endif\n";
    let module = parse(Fragment, &[("USE_MAIN", "1")], src);
    let ep = only_entry_point(&module);
    assert_eq!(ep.name, "main");
    assert_eq!(ep.stage, Fragment);
}

fn empty_value_define_counts_as_defined() {
    // `-DFLAG` style: a key with an empty value is still defined.
    let module = parse(Compute, &[("FLAG", "")], &ifdef_workgroup("FLAG"));
    assert_eq!(only_entry_point(&module).workgroup_size, [2, 1, 1]);
}

fn other_key_does_not_define_tested_key() {
    // Defines are keyed by name: defining OTHER must not make FLAG defined.
    let module = parse(Compute, &[("OTHER", "1")], &ifdef_workgroup("FLAG"));
    assert_eq!(only_entry_point(&module).workgroup_size, [3, 1, 1]);
}

fn define_values_become_workgroup_size() {
    let src = "#version 450\nlayout(local_size_x = WG_X, local_size_y = WG_Y, local_size_z = WG_Z) in;\nvoid main() {}\n";
    let module = parse(Compute, &[("WG_X", "8"), ("WG_Y", "4"), ("WG_Z", "2")], src);
    let ep = only_entry_point(&module);
    assert_eq!(ep.stage, Compute);
    assert_eq!(ep.workgroup_size, [8, 4, 2]);
}

fn if_directive_true_when_value_matches() {
    let src = "#version 450\n#if N == 4\nlayout(local_size_x = 2) in;\n#else\nlayout(local_size_x = 3) in;\n#endif\nvoid main() {}\n";
    let module = parse(Compute, &[("N", "4")], src);
    assert_eq!(only_entry_point(&module).workgroup_size, [2, 1, 1]);
}

fn if_directive_false_when_value_differs() {
    let src = "#version 450\n#if N == 4\nlayout(local_size_x = 2) in;\n#else\nlayout(local_size_x = 3) in;\n#endif\nvoid main() {}\n";
    let module = parse(Compute, &[("N", "5")], src);
    assert_eq!(only_entry_point(&module).workgroup_size, [3, 1, 1]);
}

fn define_value_sets_array_length() {
    let src = "#version 450\nfloat weights[LEN];\nlayout(location = 0) out vec4 color;\nvoid main() { color = vec4(weights[0]); }\n";
    let module = parse(Fragment, &[("LEN", "7")], src);
    let (_, var) = module
        .global_variables
        .iter()
        .find(|(_, var)| var.name.as_deref() == Some("weights"))
        .expect("global `weights` is missing from the module");
    match module.types[var.ty].inner {
        naga::TypeInner::Array { base, size, .. } => {
            assert_eq!(size, naga::ArraySize::Constant(std::num::NonZeroU32::new(7).unwrap()));
            assert_eq!(
                module.types[base].inner,
                naga::TypeInner::Scalar { kind: naga::ScalarKind::Float, width: 4 }
            );
        }
        ref other => panic!("`weights` should be float[7], got {other:?}"),
    }
    validate(&module);
}

fn define_value_substituted_into_expression() {
    let src = "#version 450\nlayout(location = 0) out vec4 color;\nvoid main() { color = vec4(SCALE); }\n";
    let module = parse(Fragment, &[("SCALE", "2.5")], src);
    only_entry_point(&module);
    // The GLSL frontend keeps the user's `main` in `module.functions` (the entry point wraps it), and
    // may fold the literal into a constant expression — look in every expression arena.
    let is_scale = |e: &naga::Expression| {
        matches!(e, naga::Expression::Literal(naga::Literal::F32(v)) if *v == 2.5)
    };
    let found = module.const_expressions.iter().any(|(_, e)| is_scale(e))
        || module.functions.iter().any(|(_, f)| f.expressions.iter().any(|(_, e)| is_scale(e)))
        || module.entry_points.iter().any(|ep| ep.function.expressions.iter().any(|(_, e)| is_scale(e)));
    assert!(found, "the literal 2.5 from define SCALE is not in the module");
    validate(&module);
}

fn define_value_may_name_another_define() {
    // Object-like macros are rescanned: OUTER -> INNER -> 6, whatever order the map yields them in.
    let src = "#version 450\nlayout(local_size_x = OUTER) in;\nvoid main() {}\n";
    let module = parse(Compute, &[("OUTER", "INNER"), ("INNER", "6")], src);
    assert_eq!(only_entry_point(&module).workgroup_size, [6, 1, 1]);
}

fn source_undef_removes_option_define() {
    let src = "#version 450\n#undef FLAG\n#ifdef FLAG\nlayout(local_size_x = 2) in;\n#else\nlayout(local_size_x = 3) in;\n#endif\nvoid main() {}\n";
    let module = parse(Compute, &[("FLAG", "1")], src);
    assert_eq!(only_entry_point(&module).workgroup_size, [3, 1, 1]);
}

fn defines_apply_only_to_their_own_parse() {
    // `Frontend` is documented as reusable across parses; each parse gets its own defines.
    let mut frontend = naga::front::glsl::Frontend::default();
    let first = parse_with(&mut frontend, Compute, &[("FLAG", "1")], &ifdef_workgroup("FLAG"));
    assert_eq!(only_entry_point(&first).workgroup_size, [2, 1, 1]);
    let second = parse_with(&mut frontend, Compute, &[("UNRELATED", "1")], &ifdef_workgroup("FLAG"));
    assert_eq!(only_entry_point(&second).workgroup_size, [3, 1, 1]);
}

checks! {
    defined_key_enables_ifdef_block,
    empty_value_define_counts_as_defined,
    other_key_does_not_define_tested_key,
    define_values_become_workgroup_size,
    if_directive_true_when_value_matches,
    if_directive_false_when_value_differs,
    define_value_sets_array_length,
    define_value_substituted_into_expression,
    define_value_may_name_another_define,
    source_undef_removes_option_define,
    defines_apply_only_to_their_own_parse,
}
