/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
}

/// Reads parser grammar files (.lalrpop) and generates Rust modules
fn generate_parsers() {
    // PANIC SAFETY: panicking inside our build script on a build dependency error is acceptable
    #[allow(clippy::expect_used)]
    lalrpop::Configuration::new()
        .process_dir("src/parser/")
        .expect("parser synth");
}
