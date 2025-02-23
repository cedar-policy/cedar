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
    #[cfg(feature = "protobufs")]
    generate_schemas();
}

#[cfg(feature = "protobufs")]
/// Reads protobuf schema files (.proto) and generates Rust modules
fn generate_schemas() {
    // PANIC SAFETY: panics in build.rs are acceptable, they just fail the build
    #[allow(clippy::expect_used)]
    prost_build::compile_protos(
        &[
            "./protobuf_schema/core.proto",
            "./protobuf_schema/validator.proto",
        ],
        &["./protobuf_schema"],
    )
    .expect("failed to compile `.proto` schema files");
}
