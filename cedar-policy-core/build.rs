fn main() {
    generate_parsers();
}

/// Reads parser grammar files (.lalrpop) and generates Rust modules
fn generate_parsers() {
    lalrpop::Configuration::new()
        .process_dir("src/parser/")
        .expect("parser synth");
}
