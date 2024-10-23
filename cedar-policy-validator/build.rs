/*
 * Copyright Cedar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

fn main() {
    generate_parsers();
    #[cfg(feature = "protobufs")]
    generate_schemas();
}

/// Reads parser grammar files (.lalrpop) and generates Rust modules
fn generate_parsers() {
    // PANIC SAFETY: panicking inside our build script on a build dependency error is acceptable
    #[allow(clippy::expect_used)]
    lalrpop::Configuration::new()
        .process_dir("src/cedar_schema/")
        .expect("parser synth");
}

#[cfg(feature = "protobufs")]
/// Reads protobuf schema files (.proto) and generates Rust modules
fn generate_schemas() {
    let mut config = prost_build::Config::new();
    config.extern_path(".cedar_policy_core", "cedar_policy-core::ast::proto");
    // PANIC SAFETY: static file compiled at build time
    #[allow(clippy::expect_used)]
    config
        .compile_protos(
            &["./protobuf_schema/Validator.proto"],
            &["./protobuf_schema", "../cedar-policy-core/protobuf_schema"],
        )
        .expect("failed to compile `.proto` schema files");
}
