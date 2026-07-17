//! Shared helpers of the GLSL checks (defines.rs, golden.rs). Public naga API only. Every helper
//! panics on an unexpected result, which fails the check (see main.rs).

use naga::front::glsl::{Frontend, Options};
use naga::valid::{Capabilities, ModuleInfo, ValidationFlags, Validator};
use naga::{Module, ShaderStage};

/// `Options` for `stage` with the given preprocessor defines (key, value).
pub fn options(stage: ShaderStage, defines: &[(&str, &str)]) -> Options {
    let mut options = Options::from(stage);
    for &(key, value) in defines {
        options.defines.insert(key.to_string(), value.to_string());
    }
    options
}

/// Parse `source` with a fresh `Frontend`; panics (fails the check) on a parse error.
pub fn parse(stage: ShaderStage, defines: &[(&str, &str)], source: &str) -> Module {
    parse_with(&mut Frontend::default(), stage, defines, source)
}

/// Parse `source` with the given (possibly reused) `Frontend`; panics on a parse error.
pub fn parse_with(
    frontend: &mut Frontend,
    stage: ShaderStage,
    defines: &[(&str, &str)],
    source: &str,
) -> Module {
    match frontend.parse(&options(stage, defines), source) {
        Ok(module) => module,
        Err(errors) => panic!("GLSL parse failed (defines {defines:?}): {errors:?}\n--- source:\n{source}"),
    }
}

/// Validate with every check and capability enabled (as upstream's GLSL snapshot test does).
pub fn validate(module: &Module) -> ModuleInfo {
    validate_with(module, Capabilities::all())
}

/// Validate with every check and the given capabilities; panics (fails the check) on an error.
pub fn validate_with(module: &Module, capabilities: Capabilities) -> ModuleInfo {
    match Validator::new(ValidationFlags::all(), capabilities).validate(module) {
        Ok(info) => info,
        Err(error) => panic!("validation (capabilities {capabilities:?}) failed: {error:?}"),
    }
}

/// The single entry point of `module` (fails the check unless there is exactly one).
pub fn only_entry_point(module: &Module) -> &naga::EntryPoint {
    assert_eq!(
        module.entry_points.len(),
        1,
        "expected exactly one entry point, got {:?}",
        module.entry_points.iter().map(|ep| &ep.name).collect::<Vec<_>>()
    );
    &module.entry_points[0]
}
