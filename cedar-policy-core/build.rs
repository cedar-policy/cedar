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

use std::path::PathBuf;

fn main() {
    generate_parsers();
}

/// Reads parser grammar files (.lalrpop) and generates Rust modules
#[expect(
    clippy::expect_used,
    reason = "panics in build.rs are acceptable, they just fail the build"
)]
fn generate_parsers() {
    let out_dir = std::env::var("OUT_DIR").expect("env var is created by cargo");
    lalrpop::Configuration::new()
        .set_out_dir(PathBuf::from(&out_dir).join("src/parser/"))
        .process_dir("src/parser/")
        .expect("failed to run lalrpop");

    lalrpop::Configuration::new()
        .set_out_dir(PathBuf::from(out_dir).join("src/validator/cedar_schema/"))
        .process_dir("src/validator/cedar_schema/")
        .expect("failed to run lalrpop");
}
