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
//! Each test loads a `.pb` file, decodes it, and asserts the result is exactly
//! equal to the expected structure. If we fail to decode a file, or decode it
//! incorrectly, then we've broken the protobuf parser. Any such break must be
//! fixed before releasing another minor or patch version of Cedar.

#![cfg(feature = "protobufs")]

use cedar_policy::proto::traits::Protobuf;
use cedar_policy::*;
use similar_asserts::assert_eq;

fn proto_file(name: &str) -> Vec<u8> {
    std::fs::read(format!("tests/proto_test_files/{name}.pb")).unwrap()
}

#[test]
fn decode_entities() {
    let decoded = Entities::decode(proto_file("entities").as_slice()).unwrap();
    let expected = Entities::from_json_value(
        serde_json::json!([
            {
                "uid": { "type": "App::Org::User", "id": "alice\n\"bob'" },
                "attrs": {
                    "name": "Alice",
                    "age": 30,
                    "active": true,
                    "scores": [95, 87, 100],
                    "profile": {
                        "email": "alice@example.com",
                        "address": { "city": "Seattle", "zip": 98101 }
                    },
                    "manager": { "__entity": { "type": "App::Org::User", "id": "bob" } }
                },
                "parents": [
                    { "type": "App::Org::Group", "id": "admins" },
                    { "type": "App::Org::Group", "id": "eng" }
                ]
            },
            {
                "uid": { "type": "App::Org::User", "id": "bob" },
                "attrs": {
                    "name": "Bob",
                    "age": 45,
                    "active": false,
                    "scores": [],
                    "profile": {
                        "email": "bob@example.com",
                        "address": { "city": "", "zip": 0 }
                    },
                    "manager": { "__entity": { "type": "App::Org::User", "id": "bob" } }
                },
                "parents": [{ "type": "App::Org::Group", "id": "eng" }]
            },
            {
                "uid": { "type": "App::Org::Group", "id": "admins" },
                "attrs": {},
                "parents": [{ "type": "App::Org::Group", "id": "eng" }]
            },
            {
                "uid": { "type": "App::Org::Group", "id": "eng" },
                "attrs": {},
                "parents": []
            }
        ]),
        None,
    )
    .unwrap();
    assert_eq!(decoded, expected);
}

#[test]
fn decode_policy_set() {
    let decoded = PolicySet::decode(proto_file("policy_set").as_slice()).unwrap();

    let expected: PolicySet = r#"
        @id("ip-restrict")
        @advice("check source IP")
        forbid(
            principal is App::Org::User,
            action in [Action::"read", Action::"write"],
            resource
        ) when {
            !context.src_ip.isInRange(ip("10.0.0.0/8"))
        };

        @id("owner-edit")
        permit(
            principal,
            action == Action::"write",
            resource in App::Org::Folder::"root"
        ) when {
            resource.owner == principal && context.authenticated
        } unless {
            principal.suspended
        };

        @id("public-read")
        permit(
            principal,
            action == Action::"read",
            resource
        ) when {
            resource.public
        };
    "#
    .parse()
    .unwrap();

    assert_eq!(decoded, expected);
}

#[test]
fn decode_schema() {
    let decoded = Schema::decode(proto_file("schema").as_slice()).unwrap();
    let expected = Schema::from_cedarschema_str(
        r#"
        namespace App::Org {
            entity Role enum ["admin", "viewer"];
            entity Tag tags String;
            entity Group;
            entity User in [Group] {
                name: String,
                age: Long,
                active: Bool,
                scores: Set<Long>,
                profile: {
                    email: String,
                    address: { city: String, zip: Long },
                },
                manager: User,
                ip: ipaddr,
                suspended?: Bool,
            };
            entity Folder {
                owner: User,
                public: Bool,
            };
            action read, write appliesTo {
                principal: User,
                resource: Folder,
                context: {
                    src_ip: ipaddr,
                    authenticated: Bool,
                },
            };
        }
        "#,
    )
    .unwrap()
    .0;
    assert_eq!(decoded.as_ref(), expected.as_ref());
}

#[test]
fn decode_request() {
    let decoded = Request::decode(proto_file("request").as_slice()).unwrap();
    let expected = Request::new(
        EntityUid::from_type_name_and_id(
            "App::Org::User".parse().unwrap(),
            EntityId::new("alice\n\"bob'"),
        ),
        EntityUid::from_type_name_and_id(
            "App::Org::Action".parse().unwrap(),
            EntityId::new("read"),
        ),
        EntityUid::from_type_name_and_id(
            "App::Org::Folder".parse().unwrap(),
            EntityId::new("root"),
        ),
        Context::from_json_value(
            serde_json::json!({
                "src_ip": { "__extn": { "fn": "ip", "arg": "192.168.1.1" } },
                "authenticated": true,
                "metadata": {
                    "user_agent": "Mozilla/5.0",
                    "request_id": "abc-123-\u{1f600}"
                }
            }),
            None,
        )
        .unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(decoded, expected);
}
