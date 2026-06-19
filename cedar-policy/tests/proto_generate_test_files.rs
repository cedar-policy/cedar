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

//! This file generates the test cases for `protobuf` regression.
//!
//! Run with: cargo test -p cedar-policy --features protobufs --test proto_generate_test_files -- --ignored
//!
//! This writes `.pb` + expectation files into `tests/proto_test_files/`.
//! The `proto_decode_regression` tests then verify that decoding the `.pb` files
//! produces the expected results.

#![cfg(feature = "protobufs")]

use cedar_policy::proto::traits::Protobuf;
use cedar_policy::*;
use std::{
    fs::{create_dir_all, write},
    path::Path,
    str::FromStr,
};

const BASE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/proto_test_files");

fn write_test_files(dir: &str, ext: &str, name: &str, value: &impl Protobuf, contents: &str) {
    let dir = Path::new(BASE).join(dir);
    create_dir_all(&dir).unwrap();
    write(dir.join(format!("{name}.pb")), value.encode()).unwrap();
    write(dir.join(format!("{name}.{ext}")), contents).unwrap();
}

fn write_policy(name: &str, cedar_text: &str) {
    let pset =
        PolicySet::from_str(cedar_text).unwrap_or_else(|e| panic!("Parse error for {name}: {e}"));
    write_test_files("policies", "cedar", name, &pset, cedar_text);
}

fn write_entities(name: &str, json_text: &str) {
    let entities =
        Entities::from_json_str(json_text, None).unwrap_or_else(|e| panic!("{name}: {e}"));
    write_test_files("entities", "json", name, &entities, json_text);
}

fn write_schema(name: &str, cedarschema_text: &str) {
    let (schema, _) =
        Schema::from_cedarschema_str(cedarschema_text).unwrap_or_else(|e| panic!("{name}: {e}"));
    write_test_files("schemas", "cedarschema", name, &schema, cedarschema_text);
}

fn write_request(name: &str, json_text: &str) {
    let v: serde_json::Value = serde_json::from_str(json_text).unwrap();
    let request = Request::new(
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
    .unwrap_or_else(|e| panic!("{name}: {e}"));
    write_test_files("requests", "json", name, &request, json_text);
}

/// Generates `#[test] #[ignore] fn gen_$name() { $writer("$name", $text); }`
macro_rules! gen_test {
    ($name:ident, $writer:ident, $text:expr) => {
        #[test]
        #[ignore]
        fn $name() {
            $writer(stringify!($name), $text);
        }
    };
}

// ─── Policies: Scope Constraints ─────────────────────────────────────────────

gen_test!(
    scope_principal_eq,
    write_policy,
    r#"permit(
    principal == User::"alice",
    action,
    resource
);
"#
);

gen_test!(
    scope_principal_in,
    write_policy,
    r#"permit(
    principal in Group::"admins",
    action,
    resource
);
"#
);

gen_test!(
    scope_principal_is,
    write_policy,
    r#"permit(
    principal is User,
    action,
    resource
);
"#
);

gen_test!(
    scope_principal_is_in,
    write_policy,
    r#"permit(
    principal is User in Group::"admins",
    action,
    resource
);
"#
);

gen_test!(
    scope_resource_eq,
    write_policy,
    r#"permit(
    principal,
    action,
    resource == Folder::"root"
);
"#
);

gen_test!(
    scope_resource_in,
    write_policy,
    r#"permit(
    principal,
    action,
    resource in Folder::"root"
);
"#
);

gen_test!(
    scope_resource_is,
    write_policy,
    r#"permit(
    principal,
    action,
    resource is Folder
);
"#
);

gen_test!(
    scope_resource_is_in,
    write_policy,
    r#"permit(
    principal,
    action,
    resource is Folder in Account::"1"
);
"#
);

gen_test!(
    scope_action_eq,
    write_policy,
    r#"permit(
    principal,
    action == Action::"read",
    resource
);
"#
);

gen_test!(
    scope_action_in_list,
    write_policy,
    r#"permit(
    principal,
    action in [Action::"read", Action::"write", Action::"delete"],
    resource
);
"#
);

gen_test!(
    scope_all_any,
    write_policy,
    r#"permit(
    principal,
    action,
    resource
);
"#
);

// ─── Policies: Condition Expressions ─────────────────────────────────────────

gen_test!(
    expr_arithmetic,
    write_policy,
    r#"permit(
    principal,
    action,
    resource
) when {
    context.x + context.y - 1 == context.z * (-2)
};
"#
);

gen_test!(
    expr_comparison,
    write_policy,
    r#"permit(
    principal,
    action,
    resource
) when {
    context.age > 18 && context.age <= 65 && context.score >= 0 && context.score < 100
};
"#
);

gen_test!(
    expr_logic,
    write_policy,
    r#"permit(
    principal,
    action,
    resource
) when {
    (context.a || context.b) && !context.c
};
"#
);

gen_test!(
    expr_hierarchy,
    write_policy,
    r#"permit(
    principal,
    action,
    resource
) when {
    principal in resource.owner && resource has visibility && resource.visibility == "public"
};
"#
);

gen_test!(
    expr_string_like,
    write_policy,
    r#"permit(
    principal,
    action,
    resource
) when {
    resource.name like "photo_*.jpg" && resource.path like "*/public/*"
};
"#
);

gen_test!(
    expr_is,
    write_policy,
    r#"permit(
    principal,
    action,
    resource
) when {
    principal is User && resource is Folder in Account::"main"
};
"#
);

gen_test!(
    expr_set_record,
    write_policy,
    r#"permit(
    principal,
    action,
    resource
) when {
    [1, 2, 3].contains(context.level) &&
    [10, 20, 30].containsAll(context.scores) &&
    ["a", "b"].containsAny(context.tags)
};
"#
);

gen_test!(
    expr_if_then_else,
    write_policy,
    r#"permit(
    principal,
    action,
    resource
) when {
    (if context.admin then true else resource.public)
};
"#
);

// ─── Policies: Extension Functions ───────────────────────────────────────────

gen_test!(
    ext_ip,
    write_policy,
    r#"forbid(
    principal,
    action,
    resource
) when {
    !context.src_ip.isIpv4() ||
    context.src_ip.isIpv6() ||
    context.src_ip.isLoopback() ||
    context.src_ip.isMulticast() ||
    context.src_ip.isInRange(ip("10.0.0.0/8"))
};
"#
);

gen_test!(
    ext_decimal,
    write_policy,
    r#"permit(
    principal,
    action,
    resource
) when {
    decimal("1.23").lessThan(decimal("4.56")) &&
    decimal("1.23").lessThanOrEqual(decimal("1.23")) &&
    decimal("9.99").greaterThan(decimal("0.01")) &&
    decimal("5.00").greaterThanOrEqual(decimal("5.00"))
};
"#
);

gen_test!(
    ext_datetime,
    write_policy,
    r#"permit(
    principal,
    action,
    resource
) when {
    datetime("2024-01-01").offset(duration("1d")).durationSince(datetime("2024-01-01")).toMilliseconds() > 0 &&
    datetime("2024-06-15T12:00:00Z").toDate() == datetime("2024-06-15") &&
    datetime("2024-06-15T12:30:00Z").toTime() == duration("12h30m")
};
"#
);

gen_test!(
    ext_duration,
    write_policy,
    r#"permit(
    principal,
    action,
    resource
) when {
    duration("1d2h3m4s5ms").toMilliseconds() > 0 &&
    duration("1d2h3m4s5ms").toSeconds() > 0 &&
    duration("1d2h3m4s5ms").toMinutes() > 0 &&
    duration("1d2h3m4s5ms").toHours() > 0 &&
    duration("1d2h3m4s5ms").toDays() > 0
};
"#
);

// ─── Policies: Edge Cases ────────────────────────────────────────────────────

gen_test!(
    multiple_clauses,
    write_policy,
    r#"permit(
    principal,
    action,
    resource
) when {
    context.a
} when {
    context.b
} unless {
    context.c
} unless {
    context.d
};
"#
);

gen_test!(
    annotations,
    write_policy,
    r#"@id("annotated-policy")
@advice("this is advice with \"quotes\" and unicode: ñ café")
@reason("a reason")
permit(
    principal,
    action,
    resource
);
"#
);

gen_test!(
    forbid_policy,
    write_policy,
    r#"forbid(
    principal,
    action,
    resource
) unless {
    context.allowed
};
"#
);

gen_test!(empty_policy_set, write_policy, "");

// ─── Entities ────────────────────────────────────────────────────────────────

gen_test!(entities_empty, write_entities, "[]");

gen_test!(
    entities_no_attrs,
    write_entities,
    r#"[
    {
        "uid": { "type": "Thing", "id": "one" },
        "attrs": {},
        "parents": []
    }
]"#
);

gen_test!(
    entities_all_literal_types,
    write_entities,
    r#"[
    {
        "uid": { "type": "Item", "id": "x" },
        "attrs": {
            "str_val": "hello",
            "long_val": 9999999999,
            "bool_val": true,
            "entity_ref": { "__entity": { "type": "Item", "id": "y" } },
            "set_val": [1, 2, 3],
            "record_val": { "a": 1, "b": "two" },
            "empty_set": [],
            "empty_record": {}
        },
        "parents": []
    },
    {
        "uid": { "type": "Item", "id": "y" },
        "attrs": {},
        "parents": []
    }
]"#
);

gen_test!(
    entities_nested_records,
    write_entities,
    r#"[
    {
        "uid": { "type": "Doc", "id": "d1" },
        "attrs": {
            "meta": {
                "level1": {
                    "level2": {
                        "level3": {
                            "value": 42
                        }
                    }
                }
            }
        },
        "parents": []
    }
]"#
);

gen_test!(
    entities_ext_values,
    write_entities,
    r#"[
    {
        "uid": { "type": "Host", "id": "h1" },
        "attrs": {
            "addr": { "__extn": { "fn": "ip", "arg": "192.168.1.100/24" } },
            "price": { "__extn": { "fn": "decimal", "arg": "19.99" } },
            "created": { "__extn": { "fn": "datetime", "arg": "2024-03-15T10:30:00Z" } },
            "ttl": { "__extn": { "fn": "duration", "arg": "30m" } }
        },
        "parents": []
    }
]"#
);

gen_test!(
    entities_multiple_parents,
    write_entities,
    r#"[
    {
        "uid": { "type": "User", "id": "u1" },
        "attrs": {},
        "parents": [
            { "type": "Group", "id": "g1" },
            { "type": "Group", "id": "g2" },
            { "type": "Group", "id": "g3" },
            { "type": "Team", "id": "t1" },
            { "type": "Org", "id": "o1" }
        ]
    },
    {
        "uid": { "type": "Group", "id": "g1" },
        "attrs": {},
        "parents": []
    },
    {
        "uid": { "type": "Group", "id": "g2" },
        "attrs": {},
        "parents": []
    },
    {
        "uid": { "type": "Group", "id": "g3" },
        "attrs": {},
        "parents": []
    },
    {
        "uid": { "type": "Team", "id": "t1" },
        "attrs": {},
        "parents": []
    },
    {
        "uid": { "type": "Org", "id": "o1" },
        "attrs": {},
        "parents": []
    }
]"#
);

gen_test!(
    entities_special_chars,
    write_entities,
    r#"[
    {
        "uid": { "type": "User", "id": "" },
        "attrs": {},
        "parents": []
    },
    {
        "uid": { "type": "User", "id": "hello\nworld" },
        "attrs": {},
        "parents": []
    },
    {
        "uid": { "type": "User", "id": "quote\"here" },
        "attrs": {},
        "parents": []
    },
    {
        "uid": { "type": "User", "id": "emoji\ud83d\ude00\ud83c\udf89" },
        "attrs": {},
        "parents": []
    },
    {
        "uid": { "type": "User", "id": "tab\there" },
        "attrs": {},
        "parents": []
    }
]"#
);

// ─── Schemas ─────────────────────────────────────────────────────────────────

gen_test!(schema_empty, write_schema, "");

gen_test!(
    schema_optional_attrs,
    write_schema,
    r#"entity User {
    name: String,
    email?: String,
    age?: Long,
    active: Bool,
};
action read appliesTo {
    principal: User,
    resource: User,
};
"#
);

gen_test!(
    schema_all_ext_types,
    write_schema,
    r#"entity Server {
    addr: ipaddr,
    cost: decimal,
    created: datetime,
    uptime: duration,
};
action check appliesTo {
    principal: Server,
    resource: Server,
};
"#
);

gen_test!(
    schema_action_hierarchy,
    write_schema,
    r#"entity Doc;
entity User;
action read, write, delete appliesTo {
    principal: User,
    resource: Doc,
};
action admin in [read, write, delete] appliesTo {
    principal: User,
    resource: Doc,
};
"#
);

gen_test!(
    schema_entity_hierarchy,
    write_schema,
    r#"entity Org;
entity Team in [Org];
entity User in [Team, Org];
entity Doc {
    owner: User,
};
action view appliesTo {
    principal: [User, Team],
    resource: Doc,
};
"#
);

gen_test!(
    schema_multiple_namespaces,
    write_schema,
    r#"namespace Auth {
    entity User;
    action login appliesTo {
        principal: User,
        resource: User,
    };
}
namespace App {
    entity Document {
        owner: Auth::User,
    };
    action read appliesTo {
        principal: Auth::User,
        resource: Document,
    };
}
"#
);

// ─── Requests ────────────────────────────────────────────────────────────────

gen_test!(
    request_minimal,
    write_request,
    r#"{
    "principal": { "type": "User", "id": "alice" },
    "action": { "type": "Action", "id": "read" },
    "resource": { "type": "Doc", "id": "d1" },
    "context": {}
}"#
);

gen_test!(
    request_ext_context,
    write_request,
    r#"{
    "principal": { "type": "User", "id": "bob" },
    "action": { "type": "Action", "id": "write" },
    "resource": { "type": "File", "id": "f1" },
    "context": {
        "src_ip": { "__extn": { "fn": "ip", "arg": "10.0.0.1" } },
        "limit": { "__extn": { "fn": "decimal", "arg": "99.99" } },
        "timestamp": { "__extn": { "fn": "datetime", "arg": "2024-12-25T00:00:00Z" } },
        "timeout": { "__extn": { "fn": "duration", "arg": "5m30s" } }
    }
}"#
);

gen_test!(
    request_nested_context,
    write_request,
    r#"{
    "principal": { "type": "User", "id": "carol" },
    "action": { "type": "Action", "id": "update" },
    "resource": { "type": "Record", "id": "r1" },
    "context": {
        "env": {
            "region": "us-east-1",
            "config": {
                "debug": false,
                "levels": [1, 2, 3],
                "nested": {
                    "deep": true
                }
            }
        }
    }
}"#
);

gen_test!(
    request_special_chars,
    write_request,
    r#"{
    "principal": { "type": "User", "id": "user\nwith\nnewlines" },
    "action": { "type": "Action", "id": "do \"something\"" },
    "resource": { "type": "Res", "id": "\ud83d\ude80\ud83c\udf1f" },
    "context": {}
}"#
);
