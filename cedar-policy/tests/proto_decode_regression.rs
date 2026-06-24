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

//! Tests for protobuf decode backwards compatibility.
//!
//! Each test loads a `.pb` file, decodes it, and asserts deep equality against an expected value
//! loaded from a sibling file (`.json`, `.cedar`, or `.cedarschema`). If we fail to decode a file,
//! or decode it incorrectly, then we've broken the protobuf parser. Any  such break must be fixed
//! before releasing another minor or patch version of Cedar.
//!
//! To add a new regression test case, either
//! A) Manually add a `.pb` file in the appropriate `tests/proto_test_files/<type>/` dir ,
//! then add the corresponding expectation file (same stem, appropriate extension).
//! b) Use the proto_generate_test_files and the gen_protobuf_regression_test_case macro to
//! generate a test case.
//!
//! insta will discover the new test cases you added in `entities`, `policies`, `requests` and
//! `schemas`.

#![cfg(feature = "protobufs")]

use cedar_policy::proto::traits::Protobuf;
use cedar_policy::*;
use cedar_policy_core::assert_deep_eq;
use similar_asserts::assert_eq;

#[test]
fn decode_entities() {
    insta::glob!("proto_test_files/entities", "*.pb", |path| {
        let decoded = Entities::decode(std::fs::read(path).unwrap().as_slice()).unwrap();

        let json_path = path.with_extension("json");
        let expected_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
        let expected = Entities::from_json_value(expected_json, None).unwrap();

        assert_deep_eq!(decoded, expected);
    });
}

#[test]
fn decode_policy_set() {
    insta::glob!("proto_test_files/policies", "*.pb", |path| {
        let decoded = PolicySet::decode(std::fs::read(path).unwrap().as_slice()).unwrap();

        let cedar_path = path.with_extension("cedar");
        let expected: PolicySet = std::fs::read_to_string(&cedar_path)
            .unwrap()
            .parse()
            .unwrap();

        assert_eq!(decoded, expected);
    });
}

#[test]
fn decode_schema() {
    insta::glob!("proto_test_files/schemas", "*.pb", |path| {
        let decoded = Schema::decode(std::fs::read(path).unwrap().as_slice()).unwrap();

        let cedar_path = path.with_extension("cedarschema");
        let expected = Schema::from_cedarschema_str(&std::fs::read_to_string(&cedar_path).unwrap())
            .unwrap()
            .0;

        assert_eq!(decoded.as_ref(), expected.as_ref());
    });
}

#[test]
fn decode_request() {
    insta::glob!("proto_test_files/requests", "*.pb", |path| {
        let decoded = Request::decode(std::fs::read(path).unwrap().as_slice()).unwrap();

        let json_path = path.with_extension("json");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
        let expected = Request::new(
            EntityUid::from_type_name_and_id(
                v["principal"]["type"].as_str().unwrap().parse().unwrap(),
                EntityId::new(v["principal"]["id"].as_str().unwrap()),
            ),
            EntityUid::from_type_name_and_id(
                v["action"]["type"].as_str().unwrap().parse().unwrap(),
                EntityId::new(v["action"]["id"].as_str().unwrap()),
            ),
            EntityUid::from_type_name_and_id(
                v["resource"]["type"].as_str().unwrap().parse().unwrap(),
                EntityId::new(v["resource"]["id"].as_str().unwrap()),
            ),
            Context::from_json_value(v["context"].clone(), None).unwrap(),
            None,
        )
        .unwrap();

        assert_eq!(decoded, expected);
    });
}
