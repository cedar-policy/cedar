fn main() {
    #[cfg(feature = "protobufs")]
    generate_schemas();
}

/// Reads protobuf schema files (.proto) and generates Rust modules
#[cfg(feature = "protobufs")]
fn generate_schemas() {
    let mut config = prost_build::Config::new();
    config.extern_path(".cedar_policy_core", "crate::cedar_policy_core::ast::proto");
    config.extern_path(
        ".cedar_policy_validator",
        "crate::cedar_policy_validator::proto",
    );
    // PANIC SAFETY: compile-time unwrap
    #[allow(clippy::unwrap_used)]
    config
        .compile_protos(&["protobuf_schema/CLI.proto"], &["protobuf_schema"])
        .unwrap();
}
