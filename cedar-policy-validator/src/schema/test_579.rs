//! Tests described in https://github.com/cedar-policy/cedar/issues/579
//!
//! We test all possible (position, scenario) pairs where:
//!
//! position is all places a typename can occur in a schema:
//! A. Inside a context attribute type
//! B. Inside an entity attribute type
//! C. Inside the body of a common-type definition
//! D. As an entity parent type
//! E. In an action `appliesTo` declaration
//! F. In an action parent declaration
//!
//! and scenario is all the ways a typename can resolve:
//! 1. the typename is written without a namespace
//!     a. and that typename is declared in the current namespace (but not the empty namespace)
//!         1. as an entity type
//!         2. as a common type
//!     b. and that typename is declared in the empty namespace (but not the current namespace)
//!         1. as an entity type
//!         2. as a common type
//!     c. and that typename is not declared in either the current namespace or the empty namespace
//! 2. the typename is written _with_ the current namespace explicit
//!     a. and that typename is declared in the current namespace (but not the empty namespace)
//!         1. as an entity type
//!         2. as a common type
//!     b. and that typename is declared in the empty namespace (but not the current namespace)
//!         1. as an entity type
//!         2. as a common type
//!     c. and that typename is not declared in either the current namespace or the empty namespace
//! 3. the typename is written _with_ an explicit namespace NS (not the current namespace)
//!     a. and that typename is declared in the current namespace (but not the empty namespace or NS)
//!         1. as an entity type
//!         2. as a common type
//!     b. and that typename is declared in the empty namespace (but not the current namespace or NS)
//!         1. as an entity type
//!         2. as a common type
//!     c. and that typename is not declared in the current namespace, the empty namespace, or NS
//!     d. and that typename is declared in NS (and also the current namespace, but not the empty namespace)
//!         1. as an entity type
//!         2. as a common type
//!
//! We also repeat all of these tests with both the human syntax and the JSON syntax.
//! The JSON syntax distinguishes syntactically between entity and common type _references_;
//! we only do the test for the more sensible one. (For instance, for 1a1, we
//! only test an entity type reference, not a common type reference.)

use super::{SchemaWarning, ValidatorSchema};
use cedar_policy_core::extensions::Extensions;
use cedar_policy_core::test_utils::{
    expect_err, ExpectedErrorMessage, ExpectedErrorMessageBuilder,
};
use cool_asserts::assert_matches;
use serde_json::json;

/// Transform the output of functions like
/// `ValidatorSchema::from_str_natural()`, which has type `(ValidatorSchema, impl Iterator<...>)`,
/// into `(ValidatorSchema, Vec<...>)`, which implements `Debug` and thus can be used with
/// `assert_matches`, `.unwrap_err()`, etc
fn collect_warnings<A, B, E>(r: Result<(A, impl Iterator<Item = B>), E>) -> Result<(A, Vec<B>), E> {
    r.map(|(a, iter)| (a, iter.collect()))
}

#[track_caller]
fn assert_parses_successfully_human(s: &str) -> (ValidatorSchema, Vec<SchemaWarning>) {
    println!("{s}");
    collect_warnings(ValidatorSchema::from_str_natural(
        s,
        Extensions::all_available(),
    ))
    .map_err(miette::Report::new)
    .unwrap()
}

#[track_caller]
fn assert_parses_successfully_json(v: serde_json::Value) -> ValidatorSchema {
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
    ValidatorSchema::from_json_value(v, Extensions::all_available())
        .map_err(miette::Report::new)
        .unwrap()
}

#[track_caller]
fn assert_parse_error_human(s: &str, e: &ExpectedErrorMessage<'_>) {
    println!("{s}");
    assert_matches!(collect_warnings(ValidatorSchema::from_str_natural(s, Extensions::all_available())), Err(err) => {
        expect_err(s, &miette::Report::new(err), e);
    });
}

#[track_caller]
fn assert_parse_error_json(v: serde_json::Value, e: &ExpectedErrorMessage<'_>) {
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
    assert_matches!(ValidatorSchema::from_json_value(v.clone(), Extensions::all_available()), Err(err) => {
        expect_err(&v, &miette::Report::new(err), e);
    });
}

/// Makes a schema for all the XXa1 test cases, where different XX plug in
/// different `mytype_use` (schema constructs that use `MyType`).
///
/// In all of these cases, `MyType` is declared as an entity type in the
/// current namespace (NS1).
fn a1_human(mytype_use: &str) -> String {
    format!(
        r#"
        namespace NS1 {{
            entity User, Resource;
            entity MyType;
            {mytype_use}
        }}
        "#
    )
}

/// Makes a schema for all the XXa1 test cases, where different XX plug in a
/// different schema construct that uses `MyType` (e.g., with a function
/// like `A1X1_json()`).
///
/// In all of these cases, `MyType` is declared as an entity type in the
/// current namespace (NS1).
fn a1_json() -> serde_json::Value {
    json!({
        "NS1": {
            "entityTypes": {
                "User": { "memberOfTypes": [] },
                "Resource": { "memberOfTypes": [] },
                "MyType": { "memberOfTypes": [] },
            },
            "actions": {}
        }
    })
}

/// Makes a schema for all the XXa2 test cases, where different XX plug in
/// different `mytype_use` (schema constructs that use `MyType`).
///
/// In all of these cases, `MyType` is declared as a common type in the
/// current namespace (NS1).
fn a2_human(mytype_use: &str) -> String {
    format!(
        r#"
        namespace NS1 {{
            entity User, Resource;
            type MyType = String;
            {mytype_use}
        }}
        "#
    )
}

/// Makes a schema for all the XXa2 test cases, where different XX plug in a
/// different schema construct that uses `MyType` (e.g., with a function
/// like `A1X1_json()`).
///
/// In all of these cases, `MyType` is declared as a common type in the
/// current namespace (NS1).
fn a2_json() -> serde_json::Value {
    json!({
        "NS1": {
            "entityTypes": {
                "User": { "memberOfTypes": [] },
                "Resource": { "memberOfTypes": [] },
            },
            "commonTypes": {
                "MyType": { "type": "String" },
            },
            "actions": {}
        }
    })
}

/// Makes a schema for all the XXb1 test cases, where different XX plug in
/// different `mytype_use` (schema constructs that use `MyType`).
///
/// In all of these cases, `MyType` is declared as an entity type in the
/// empty namespace.
fn b1_human(mytype_use: &str) -> String {
    format!(
        r#"
        entity MyType;
        namespace NS1 {{
            entity User, Resource;
            {mytype_use}
        }}
        "#
    )
}

/// Makes a schema for all the XXb1 test cases, where different XX plug in a
/// different schema construct that uses `MyType` (e.g., with a function
/// like `A1X1_json()`).
///
/// In all of these cases, `MyType` is declared as an entity type in the
/// empty namespace.
fn b1_json() -> serde_json::Value {
    json!({
        "": {
            "entityTypes": {
                "MyType": { "memberOfTypes": [] }
            },
            "actions": {}
        },
        "NS1": {
            "entityTypes": {
                "User": { "memberOfTypes": [] },
                "Resource": { "memberOfTypes": [] },
            },
            "actions": {}
        }
    })
}

/// Makes a schema for all the XXb2 test cases, where different XX plug in
/// different `mytype_use` (schema constructs that use `MyType`).
///
/// In all of these cases, `MyType` is declared as a common type in the
/// empty namespace.
fn b2_human(mytype_use: &str) -> String {
    format!(
        r#"
        type MyType = String;
        namespace NS1 {{
            entity User, Resource;
            {mytype_use}
        }}
        "#
    )
}

/// Makes a schema for all the XXb2 test cases, where different XX plug in a
/// different schema construct that uses `MyType` (e.g., with a function
/// like `A1X1_json()`).
///
/// In all of these cases, `MyType` is declared as a common type in the
/// empty namespace.
fn b2_json() -> serde_json::Value {
    json!({
        "": {
            "commonTypes": {
                "MyType": { "type": "String" }
            },
            "entityTypes": {},
            "actions": {}
        },
        "NS1": {
            "entityTypes": {
                "User": { "memberOfTypes": [] },
                "Resource": { "memberOfTypes": [] },
            },
            "actions": {}
        }
    })
}

/// Makes a schema for all the XXc test cases, where different XX plug in
/// different `mytype_use` (schema constructs that use `MyType`).
///
/// In all of these cases, `MyType` is not declared in any namespace.
fn c_human(mytype_use: &str) -> String {
    format!(
        r#"
        namespace NS1 {{
            entity User, Resource;
            {mytype_use}
        }}
        "#
    )
}

/// Makes a schema for all the XXc test cases, where different XX plug in a
/// different schema construct that uses `MyType` (e.g., with a function
/// like `A1X1_json()`).
///
/// In all of these cases, `MyType` is not declared in any namespace.
fn c_json() -> serde_json::Value {
    json!({
        "NS1": {
            "entityTypes": {
                "User": { "memberOfTypes": [] },
                "Resource": { "memberOfTypes": [] },
            },
            "actions": {}
        }
    })
}

/// Makes a schema for all the XXd1 test cases, where different XX plug in
/// different `mytype_use` (schema constructs that use `MyType`).
///
/// In all of these cases, `MyType` is declared as an entity type in an
/// unrelated namespace (NS2).
fn d1_human(mytype_use: &str) -> String {
    format!(
        r#"
        namespace NS2 {{
            entity MyType;
        }}
        namespace NS1 {{
            entity User, Resource;
            {mytype_use}
        }}
        "#
    )
}

/// Makes a schema for all the XXd1 test cases, where different XX plug in a
/// different schema construct that uses `MyType` (e.g., with a function
/// like `A1X1_json()`).
///
/// In all of these cases, `MyType` is declared as an entity type in an
/// unrelated namespace (NS2).
fn d1_json() -> serde_json::Value {
    json!({
        "NS2": {
            "entityTypes": {
                "MyType": { "memberOfTypes": [] },
            },
            "actions": {}
        },
        "NS1": {
            "entityTypes": {
                "User": { "memberOfTypes": [] },
                "Resource": { "memberOfTypes": [] },
            },
            "actions": {}
        }
    })
}

/// Makes a schema for all the XXd2 test cases, where different XX plug in
/// different `mytype_use` (schema constructs that use `MyType`).
///
/// In all of these cases, `MyType` is declared as a common type in an
/// unrelated namespace (NS2).
fn d2_human(mytype_use: &str) -> String {
    format!(
        r#"
        namespace NS2 {{
            type MyType = String;
        }}
        namespace NS1 {{
            entity User, Resource;
            {mytype_use}
        }}
        "#
    )
}

/// Makes a schema for all the XXd2 test cases, where different XX plug in a
/// different schema construct that uses `MyType` (e.g., with a function
/// like `A1X1_json()`).
///
/// In all of these cases, `MyType` is declared as a common type in an
/// unrelated namespace (NS2).
fn d2_json() -> serde_json::Value {
    json!({
        "NS2": {
            "commonTypes": {
                "MyType": { "type": "String" },
            },
            "entityTypes": {},
            "actions": {}
        },
        "NS1": {
            "entityTypes": {
                "User": { "memberOfTypes": [] },
                "Resource": { "memberOfTypes": [] },
            },
            "actions": {}
        }
    })
}

/// Generate human-schema syntax for a `MyType` use of kind A1.
fn A1_human() -> &'static str {
    r#"action Read appliesTo { principal: [User], resource: [Resource], context: { foo: MyType }};"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind A1X1 (for any X), returning the new schema.
fn A1X1_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["actions"]["Read"] = json!({
        "appliesTo": {
            "principalTypes": ["User"],
            "resourceTypes": ["Resource"],
            "context": {
                "type": "Record",
                "attributes": {
                    "foo": { "type": "Entity", "name": "MyType" }
                }
            }
        }
    });
    schema
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind A1X2 (for any X), returning the new schema.
fn A1X2_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["actions"]["Read"] = json!({
        "appliesTo": {
            "principalTypes": ["User"],
            "resourceTypes": ["Resource"],
            "context": {
                "type": "Record",
                "attributes": {
                    "foo": { "type": "MyType" }
                }
            }
        }
    });
    schema
}

/// Generate human-schema syntax for a `MyType` use of kind A2.
fn A2_human() -> &'static str {
    r#"action Read appliesTo { principal: [User], resource: [Resource], context: { foo: NS1::MyType }};"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind A2X1 (for any X), returning the new schema.
fn A2X1_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["actions"]["Read"] = json!({
        "appliesTo": {
            "principalTypes": ["User"],
            "resourceTypes": ["Resource"],
            "context": {
                "type": "Record",
                "attributes": {
                    "foo": { "type": "Entity", "name": "NS1::MyType" }
                }
            }
        }
    });
    schema
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind A2X2 (for any X), returning the new schema.
fn A2X2_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["actions"]["Read"] = json!({
        "appliesTo": {
            "principalTypes": ["User"],
            "resourceTypes": ["Resource"],
            "context": {
                "type": "Record",
                "attributes": {
                    "foo": { "type": "NS1::MyType" }
                }
            }
        }
    });
    schema
}

/// Generate human-schema syntax for a `MyType` use of kind A3.
fn A3_human() -> &'static str {
    r#"action Read appliesTo { principal: [User], resource: [Resource], context: { foo: NS2::MyType }};"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind A3X1 (for any X), returning the new schema.
fn A3X1_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["actions"]["Read"] = json!({
        "appliesTo": {
            "principalTypes": ["User"],
            "resourceTypes": ["Resource"],
            "context": {
                "type": "Record",
                "attributes": {
                    "foo": { "type": "Entity", "name": "NS2::MyType" }
                }
            }
        }
    });
    schema
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind A3X2 (for any X), returning the new schema.
fn A3X2_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["actions"]["Read"] = json!({
        "appliesTo": {
            "principalTypes": ["User"],
            "resourceTypes": ["Resource"],
            "context": {
                "type": "Record",
                "attributes": {
                    "foo": { "type": "NS2::MyType" }
                }
            }
        }
    });
    schema
}

/// Generate human-schema syntax for a `MyType` use of kind B1.
fn B1_human() -> &'static str {
    r#"entity E { foo: MyType };"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind B1X1 (for any X), returning the new schema.
fn B1X1_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["entityTypes"]["E"] = json!({
        "memberOfTypes": [],
        "shape": {
            "type": "Record",
            "attributes": {
                "foo": { "type": "Entity", "name": "MyType" }
            }
        }
    });
    schema
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind B1X2 (for any X), returning the new schema.
fn B1X2_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["entityTypes"]["E"] = json!({
        "memberOfTypes": [],
        "shape": {
            "type": "Record",
            "attributes": {
                "foo": { "type": "MyType" }
            }
        }
    });
    schema
}

/// Generate human-schema syntax for a `MyType` use of kind B2.
fn B2_human() -> &'static str {
    r#"entity E { foo: NS1::MyType };"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind B2X1 (for any X), returning the new schema.
fn B2X1_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["entityTypes"]["E"] = json!({
        "memberOfTypes": [],
        "shape": {
            "type": "Record",
            "attributes": {
                "foo": { "type": "Entity", "name": "NS1::MyType" }
            }
        }
    });
    schema
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind B2X2 (for any X), returning the new schema.
fn B2X2_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["entityTypes"]["E"] = json!({
        "memberOfTypes": [],
        "shape": {
            "type": "Record",
            "attributes": {
                "foo": { "type": "NS1::MyType" }
            }
        }
    });
    schema
}

/// Generate human-schema syntax for a `MyType` use of kind B3.
fn B3_human() -> &'static str {
    r#"entity E { foo: NS2::MyType };"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind B3X1 (for any X), returning the new schema.
fn B3X1_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["entityTypes"]["E"] = json!({
        "memberOfTypes": [],
        "shape": {
            "type": "Record",
            "attributes": {
                "foo": { "type": "Entity", "name": "NS2::MyType" }
            }
        }
    });
    schema
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind B3X2 (for any X), returning the new schema.
fn B3X2_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["entityTypes"]["E"] = json!({
        "memberOfTypes": [],
        "shape": {
            "type": "Record",
            "attributes": {
                "foo": { "type": "NS2::MyType" }
            }
        }
    });
    schema
}

/// Generate human-schema syntax for a `MyType` use of kind C1.
fn C1_human() -> &'static str {
    r#"type E = { foo: MyType };"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind C1X1 (for any X), returning the new schema.
fn C1X1_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["commonTypes"]["E"] = json!({
        "type": "Record",
        "attributes": {
            "foo": { "type": "Entity", "name": "MyType" }
            }
    });
    schema
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind C1X2 (for any X), returning the new schema.
fn C1X2_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["commonTypes"]["E"] = json!({
        "type": "Record",
        "attributes": {
            "foo": { "type": "MyType" }
        }
    });
    schema
}

/// Generate human-schema syntax for a `MyType` use of kind C2.
fn C2_human() -> &'static str {
    r#"type E = { foo: NS1::MyType };"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind C2X1 (for any X), returning the new schema.
fn C2X1_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["commonTypes"]["E"] = json!({
        "type": "Record",
        "attributes": {
            "foo": { "type": "Entity", "name": "NS1::MyType" }
            }
    });
    schema
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind C2X2 (for any X), returning the new schema.
fn C2X2_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["commonTypes"]["E"] = json!({
        "type": "Record",
        "attributes": {
            "foo": { "type": "NS1::MyType" }
        }
    });
    schema
}

/// Generate human-schema syntax for a `MyType` use of kind C3.
fn C3_human() -> &'static str {
    r#"type E = { foo: NS2::MyType };"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind C3X1 (for any X), returning the new schema.
fn C3X1_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["commonTypes"]["E"] = json!({
        "type": "Record",
        "attributes": {
            "foo": { "type": "Entity", "name": "NS2::MyType" }
            }
    });
    schema
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind C3X2 (for any X), returning the new schema.
fn C3X2_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["commonTypes"]["E"] = json!({
        "type": "Record",
        "attributes": {
            "foo": { "type": "NS2::MyType" }
        }
    });
    schema
}

/// Generate human-schema syntax for a `MyType` use of kind D1.
fn D1_human() -> &'static str {
    r#"entity E in [MyType];"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind D1XX (for any XX), returning the new schema.
///
/// Unlike for A1/B1/C1, we do not need to distinguish between
/// D1X1 and D1X2, because this position does not distinguish between
/// an entity reference and a common-type reference.
fn D1_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["entityTypes"]["E"] = json!({
        "memberOfTypes": [ "MyType" ]
    });
    schema
}

/// Generate human-schema syntax for a `MyType` use of kind D2.
fn D2_human() -> &'static str {
    r#"entity E in [NS1::MyType];"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind D2XX (for any XX), returning the new schema.
///
/// Unlike for A2/B2/C2, we do not need to distinguish between
/// D2X1 and D2X2, because this position does not distinguish between
/// an entity reference and a common-type reference.
fn D2_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["entityTypes"]["E"] = json!({
        "memberOfTypes": [ "NS1::MyType" ]
    });
    schema
}

/// Generate human-schema syntax for a `MyType` use of kind D3.
fn D3_human() -> &'static str {
    r#"entity E in [NS2::MyType];"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind D3XX (for any XX), returning the new schema.
///
/// Unlike for A3/B3/C3, we do not need to distinguish between
/// D3X1 and D3X2, because this position does not distinguish between
/// an entity reference and a common-type reference.
fn D3_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["entityTypes"]["E"] = json!({
        "memberOfTypes": [ "NS2::MyType" ]
    });
    schema
}

/// Generate human-schema syntax for a `MyType` use of kind E1.
fn E1_human() -> &'static str {
    r#"action Read appliesTo { principal: [MyType], resource: [Resource] };"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind E1XX (for any XX), returning the new schema.
///
/// Unlike for A1/B1/C1, we do not need to distinguish between
/// E1X1 and E1X2, because this position does not distinguish between
/// an entity reference and a common-type reference.
fn E1_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["actions"]["Read"] = json!({
        "appliesTo": { "principalTypes": ["MyType"], "resourceTypes": ["Resource"] }
    });
    schema
}

/// Generate human-schema syntax for a `MyType` use of kind E2.
fn E2_human() -> &'static str {
    r#"action Read appliesTo { principal: [NS1::MyType], resource: [Resource] };"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind E1XX (for any XX), returning the new schema.
///
/// Unlike for A2/B2/C2, we do not need to distinguish between
/// E2X1 and E2X2, because this position does not distinguish between
/// an entity reference and a common-type reference.
fn E2_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["actions"]["Read"] = json!({
        "appliesTo": { "principalTypes": ["NS1::MyType"], "resourceTypes": ["Resource"] }
    });
    schema
}

/// Generate human-schema syntax for a `MyType` use of kind E3.
fn E3_human() -> &'static str {
    r#"action Read appliesTo { principal: [NS2::MyType], resource: [Resource] };"#
}

/// Given a starting JSON schema (e.g., from `a1_json()`),
/// add a `MyType` use of kind E1XX (for any XX), returning the new schema.
///
/// Unlike for A3/B3/C3, we do not need to distinguish between
/// E3X1 and E3X2, because this position does not distinguish between
/// an entity reference and a common-type reference.
fn E3_json(mut schema: serde_json::Value) -> serde_json::Value {
    schema["NS1"]["actions"]["Read"] = json!({
        "appliesTo": { "principalTypes": ["NS2::MyType"], "resourceTypes": ["Resource"] }
    });
    schema
}

/// Generate human-schema syntax for F1a.
/// (F tests cannot use the standard `a1_human()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F1a_human() -> &'static str {
    r#"
    namespace NS1 {
        action ActionGroup;
        action Read in [ActionGroup];
    }
    "#
}

/// Generate JSON syntax for F1a.
/// (F tests cannot use the standard `a1_json()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F1a_json() -> serde_json::Value {
    json!({
        "NS1": {
            "entityTypes": {},
            "actions": {
                "ActionGroup": {},
                "Read": {
                    "memberOf": [ { "id": "ActionGroup" } ],
                }
            }
        }
    })
}

/// Generate human-schema syntax for F1b.
/// (F tests cannot use the standard `a1_human()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F1b_human() -> &'static str {
    r#"
    action ActionGroup;
    namespace NS1 {
        action Read in [ActionGroup];
    }
    "#
}

/// Generate JSON syntax for F1b.
/// (F tests cannot use the standard `a1_json()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F1b_json() -> serde_json::Value {
    json!({
        "": {
            "entityTypes": {},
            "actions": {
                "ActionGroup": {},
            }
        },
        "NS1": {
            "entityTypes": {},
            "actions": {
                "Read": {
                    "memberOf": [ { "id": "ActionGroup" } ],
                }
            }
        }
    })
}

/// Generate human-schema syntax for F1c.
/// (F tests cannot use the standard `a1_human()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F1c_human() -> &'static str {
    r#"
    namespace NS1 {
        action Read in [ActionGroup];
    }
    "#
}

/// Generate JSON syntax for F1c.
/// (F tests cannot use the standard `a1_json()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F1c_json() -> serde_json::Value {
    json!({
        "NS1": {
            "entityTypes": {},
            "actions": {
                "Read": {
                    "memberOf": [ { "id": "ActionGroup" } ],
                }
            }
        }
    })
}

/// Generate human-schema syntax for F2a.
/// (F tests cannot use the standard `a1_human()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F2a_human() -> &'static str {
    r#"
    namespace NS1 {
        action ActionGroup;
        action Read in [NS1::Action::"ActionGroup"];
    }
    "#
}

/// Generate JSON syntax for F2a.
/// (F tests cannot use the standard `a1_json()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F2a_json() -> serde_json::Value {
    json!({
        "NS1": {
            "entityTypes": {},
            "actions": {
                "ActionGroup": {},
                "Read": {
                    "memberOf": [ { "type": "NS1::Action", "id": "ActionGroup" } ],
                }
            }
        }
    })
}

/// Generate human-schema syntax for F2b.
/// (F tests cannot use the standard `a1_human()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F2b_human() -> &'static str {
    r#"
    action ActionGroup;
    namespace NS1 {
        action Read in [NS1::Action::"ActionGroup"];
    }
    "#
}

/// Generate JSON syntax for F2b.
/// (F tests cannot use the standard `a1_json()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F2b_json() -> serde_json::Value {
    json!({
        "" : {
            "entityTypes": {},
            "actions": {
                "ActionGroup": {},
            }
        },
        "NS1": {
            "entityTypes": {},
            "actions": {
                "Read": {
                    "memberOf": [ { "type": "NS1::Action", "id": "ActionGroup" } ],
                }
            }
        }
    })
}

/// Generate human-schema syntax for F2c.
/// (F tests cannot use the standard `a1_human()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F2c_human() -> &'static str {
    r#"
    namespace NS1 {
        action Read in [NS1::Action::"ActionGroup"];
    }
    "#
}

/// Generate JSON syntax for F2c.
/// (F tests cannot use the standard `a1_json()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F2c_json() -> serde_json::Value {
    json!({
        "NS1": {
            "entityTypes": {},
            "actions": {
                "Read": {
                    "memberOf": [ { "type": "NS1::Action", "id": "ActionGroup" } ],
                }
            }
        }
    })
}

/// Generate human-schema syntax for F3a.
/// (F tests cannot use the standard `a1_human()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F3a_human() -> &'static str {
    r#"
    namespace NS1 {
        action ActionGroup;
        action Read in [NS2::Action::"ActionGroup"];
    }
    "#
}

/// Generate JSON syntax for F3a.
/// (F tests cannot use the standard `a1_json()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F3a_json() -> serde_json::Value {
    json!({
        "NS1": {
            "entityTypes": {},
            "actions": {
                "ActionGroup": {},
                "Read": {
                    "memberOf": [ { "type": "NS2::Action", "id": "ActionGroup" } ],
                }
            }
        }
    })
}

/// Generate human-schema syntax for F3b.
/// (F tests cannot use the standard `a1_human()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F3b_human() -> &'static str {
    r#"
    action ActionGroup;
    namespace NS1 {
        action Read in [NS2::Action::"ActionGroup"];
    }
    "#
}

/// Generate JSON syntax for F3b.
/// (F tests cannot use the standard `a1_json()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F3b_json() -> serde_json::Value {
    json!({
        "": {
            "entityTypes": {},
            "actions": {
                "ActionGroup": {},
            }
        },
        "NS1": {
            "entityTypes": {},
            "actions": {
                "Read": {
                    "memberOf": [ { "type": "NS2::Action", "id": "ActionGroup" } ],
                }
            }
        }
    })
}

/// Generate human-schema syntax for F3c.
/// (F tests cannot use the standard `a1_human()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F3c_human() -> &'static str {
    r#"
    namespace NS1 {
        action Read in [NS2::Action::"ActionGroup"];
    }
    "#
}

/// Generate JSON syntax for F3c.
/// (F tests cannot use the standard `a1_json()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F3c_json() -> serde_json::Value {
    json!({
        "NS1": {
            "entityTypes": {},
            "actions": {
                "Read": {
                    "memberOf": [ { "type": "NS2::Action", "id": "ActionGroup" } ],
                }
            }
        }
    })
}

/// Generate human-schema syntax for F3d.
/// (F tests cannot use the standard `a1_human()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F3d_human() -> &'static str {
    r#"
    namespace NS2 {
        action ActionGroup;
    }
    namespace NS1 {
        action Read in [NS2::Action::"ActionGroup"];
    }
    "#
}

/// Generate JSON syntax for F3d.
/// (F tests cannot use the standard `a1_json()` etc, because they need action
/// declarations instead of entity/common declarations.)
fn F3d_json() -> serde_json::Value {
    json!({
        "NS2": {
            "entityTypes": {},
            "actions": {
                "ActionGroup": {},
            }
        },
        "NS1": {
            "entityTypes": {},
            "actions": {
                "Read": {
                    "memberOf": [ { "type": "NS2::Action", "id": "ActionGroup" } ],
                }
            }
        }
    })
}

// ####
//
// For explanations of all of the below tests and their naming, see comments
// at the top of this file.
//
// ####

#[test]
fn A1a1() {
    assert_parses_successfully_human(&a1_human(A1_human()));
    assert_parses_successfully_json(A1X1_json(a1_json()));
}
#[test]
fn A1a2() {
    assert_parses_successfully_human(&a2_human(A1_human()));
    assert_parses_successfully_json(A1X2_json(a2_json()));
}
#[test]
fn A1b1() {
    assert_parses_successfully_human(&b1_human(A1_human()));
    assert_parses_successfully_json(A1X1_json(b1_json()));
}
#[test]
fn A1b2() {
    assert_parses_successfully_human(&b2_human(A1_human()));
    assert_parses_successfully_json(A1X2_json(b2_json()));
}
#[test]
fn A1c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(A1_human()), &expected_human);
    assert_parse_error_json(A1X1_json(c_json()), &expected_json);
}
#[test]
fn A2a1() {
    assert_parses_successfully_human(&a1_human(A2_human()));
    assert_parses_successfully_json(A2X1_json(a1_json()));
}
#[test]
fn A2a2() {
    assert_parses_successfully_human(&a2_human(A2_human()));
    assert_parses_successfully_json(A2X2_json(a2_json()));
}
#[test]
fn A2b1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&b1_human(A2_human()), &expected_human);
    assert_parse_error_json(A2X1_json(b1_json()), &expected_json);
}
#[test]
fn A2b2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as a common type")
            .build();
    assert_parse_error_human(&b2_human(A2_human()), &expected_human);
    assert_parse_error_json(A2X2_json(b2_json()), &expected_json);
}
#[test]
fn A2c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(A2_human()), &expected_human);
    assert_parse_error_json(A2X1_json(c_json()), &expected_json);
}
#[test]
fn A3a1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&a1_human(A3_human()), &expected_human);
    assert_parse_error_json(A3X1_json(a1_json()), &expected_json);
}
#[test]
fn A3a2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common type")
            .build();
    assert_parse_error_human(&a2_human(A3_human()), &expected_human);
    assert_parse_error_json(A3X2_json(a2_json()), &expected_json);
}
#[test]
fn A3b1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&b1_human(A3_human()), &expected_human);
    assert_parse_error_json(A3X1_json(b1_json()), &expected_json);
}
#[test]
fn A3b2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common type")
            .build();
    assert_parse_error_human(&b2_human(A3_human()), &expected_human);
    assert_parse_error_json(A3X2_json(b2_json()), &expected_json);
}
#[test]
fn A3c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(A3_human()), &expected_human);
    assert_parse_error_json(A3X1_json(c_json()), &expected_json);
}
#[test]
fn A3d1() {
    assert_parses_successfully_human(&d1_human(A3_human()));
    assert_parses_successfully_json(A3X1_json(d1_json()));
}
#[test]
fn A3d2() {
    assert_parses_successfully_human(&d2_human(A3_human()));
    assert_parses_successfully_json(A3X2_json(d2_json()));
}
#[test]
fn B1a1() {
    assert_parses_successfully_human(&a1_human(B1_human()));
    assert_parses_successfully_json(B1X1_json(a1_json()));
}
#[test]
fn B1a2() {
    assert_parses_successfully_human(&a2_human(B1_human()));
    assert_parses_successfully_json(B1X2_json(a2_json()));
}
#[test]
fn B1b1() {
    assert_parses_successfully_human(&b1_human(B1_human()));
    assert_parses_successfully_json(B1X1_json(b1_json()));
}
#[test]
fn B1b2() {
    assert_parses_successfully_human(&b2_human(B1_human()));
    assert_parses_successfully_json(B1X2_json(b2_json()));
}
#[test]
fn B1c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(B1_human()), &expected_human);
    assert_parse_error_json(B1X1_json(c_json()), &expected_json);
}
#[test]
fn B2a1() {
    assert_parses_successfully_human(&a1_human(B2_human()));
    assert_parses_successfully_json(B2X1_json(a1_json()));
}
#[test]
fn B2a2() {
    assert_parses_successfully_human(&a2_human(B2_human()));
    assert_parses_successfully_json(B2X2_json(a2_json()));
}
#[test]
fn B2b1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&b1_human(B2_human()), &expected_human);
    assert_parse_error_json(B2X1_json(b1_json()), &expected_json);
}
#[test]
fn B2b2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as a common type")
            .build();
    assert_parse_error_human(&b2_human(B2_human()), &expected_human);
    assert_parse_error_json(B2X2_json(b2_json()), &expected_json);
}
#[test]
fn B2c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(B2_human()), &expected_human);
    assert_parse_error_json(B2X1_json(c_json()), &expected_json);
}
#[test]
fn B3a1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&a1_human(B3_human()), &expected_human);
    assert_parse_error_json(B3X1_json(a1_json()), &expected_json);
}
#[test]
fn B3a2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common type")
            .build();
    assert_parse_error_human(&a2_human(B3_human()), &expected_human);
    assert_parse_error_json(B3X2_json(a2_json()), &expected_json);
}
#[test]
fn B3b1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&b1_human(B3_human()), &expected_human);
    assert_parse_error_json(B3X1_json(b1_json()), &expected_json);
}
#[test]
fn B3b2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common type")
            .build();
    assert_parse_error_human(&b2_human(B3_human()), &expected_human);
    assert_parse_error_json(B3X2_json(b2_json()), &expected_json);
}
#[test]
fn B3c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(B3_human()), &expected_human);
    assert_parse_error_json(B3X1_json(c_json()), &expected_json);
}
#[test]
fn B3d1() {
    assert_parses_successfully_human(&d1_human(B3_human()));
    assert_parses_successfully_json(B3X1_json(d1_json()));
}
#[test]
fn B3d2() {
    assert_parses_successfully_human(&d2_human(B3_human()));
    assert_parses_successfully_json(B3X2_json(d2_json()));
}
#[test]
fn C1a1() {
    assert_parses_successfully_human(&a1_human(C1_human()));
    assert_parses_successfully_json(C1X1_json(a1_json()));
}
#[test]
fn C1a2() {
    assert_parses_successfully_human(&a2_human(C1_human()));
    assert_parses_successfully_json(C1X2_json(a2_json()));
}
#[test]
fn C1b1() {
    assert_parses_successfully_human(&b1_human(C1_human()));
    assert_parses_successfully_json(C1X1_json(b1_json()));
}
#[test]
fn C1b2() {
    assert_parses_successfully_human(&b2_human(C1_human()));
    assert_parses_successfully_json(C1X2_json(b2_json()));
}
#[test]
fn C1c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(C1_human()), &expected_human);
    assert_parse_error_json(C1X1_json(c_json()), &expected_json);
}
#[test]
fn C2a1() {
    assert_parses_successfully_human(&a1_human(C2_human()));
    assert_parses_successfully_json(C2X1_json(a1_json()));
}
#[test]
fn C2a2() {
    assert_parses_successfully_human(&a2_human(C2_human()));
    assert_parses_successfully_json(C2X2_json(a2_json()));
}
#[test]
fn C2b1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&b1_human(C2_human()), &expected_human);
    assert_parse_error_json(C2X1_json(b1_json()), &expected_json);
}
#[test]
fn C2b2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as a common type")
            .build();
    assert_parse_error_human(&b2_human(C2_human()), &expected_human);
    assert_parse_error_json(C2X2_json(b2_json()), &expected_json);
}
#[test]
fn C2c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(C2_human()), &expected_human);
    assert_parse_error_json(C2X1_json(c_json()), &expected_json);
}
#[test]
fn C3a1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&a1_human(C3_human()), &expected_human);
    assert_parse_error_json(C3X1_json(a1_json()), &expected_json);
}
#[test]
fn C3a2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common type")
            .build();
    assert_parse_error_human(&a2_human(C3_human()), &expected_human);
    assert_parse_error_json(C3X2_json(a2_json()), &expected_json);
}
#[test]
fn C3b1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&b1_human(C3_human()), &expected_human);
    assert_parse_error_json(C3X1_json(b1_json()), &expected_json);
}
#[test]
fn C3b2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common type")
            .build();
    assert_parse_error_human(&b2_human(C3_human()), &expected_human);
    assert_parse_error_json(C3X2_json(b2_json()), &expected_json);
}
#[test]
fn C3c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as a common or entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(C3_human()), &expected_human);
    assert_parse_error_json(C3X1_json(c_json()), &expected_json);
}
#[test]
fn C3d1() {
    assert_parses_successfully_human(&d1_human(C3_human()));
    assert_parses_successfully_json(C3X1_json(d1_json()));
}
#[test]
fn C3d2() {
    assert_parses_successfully_human(&d2_human(C3_human()));
    assert_parses_successfully_json(C3X2_json(d2_json()));
}
#[test]
fn D1a1() {
    assert_parses_successfully_human(&a1_human(D1_human()));
    assert_parses_successfully_json(D1_json(a1_json()));
}
#[test]
fn D1a2() {
    // this is an error because we currently don't support `entity E in [common-type]`.
    // The error message could be more clear, e.g., specialized to check whether
    // the type that failed to resolve would have resolved to a common type if
    // it were allowed to.
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            .build();
    assert_parse_error_human(&a2_human(D1_human()), &expected_human);
    assert_parse_error_json(D1_json(a2_json()), &expected_json);
}
#[test]
fn D1b1() {
    assert_parses_successfully_human(&b1_human(D1_human()));
    assert_parses_successfully_json(D1_json(b1_json()));
}
#[test]
fn D1b2() {
    // this is an error because we currently don't support `entity E in [common-type]`.
    // The error message could be more clear, e.g., specialized to check whether
    // the type that failed to resolve would have resolved to a common type if
    // it were allowed to.
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            .build();
    assert_parse_error_human(&b2_human(D1_human()), &expected_human);
    assert_parse_error_json(D1_json(b2_json()), &expected_json);
}
#[test]
fn D1c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(D1_human()), &expected_human);
    assert_parse_error_json(D1_json(c_json()), &expected_json);
}
#[test]
fn D2a1() {
    assert_parses_successfully_human(&a1_human(D2_human()));
    assert_parses_successfully_json(D2_json(a1_json()));
}
#[test]
fn D2a2() {
    // this is an error because we currently don't support `entity E in [common-type]`.
    // The error message could be more clear, e.g., specialized to check whether
    // the type that failed to resolve would have resolved to a common type if
    // it were allowed to.
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&a2_human(D2_human()), &expected_human);
    assert_parse_error_json(D2_json(a2_json()), &expected_json);
}
#[test]
fn D2b1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&b1_human(D2_human()), &expected_human);
    assert_parse_error_json(D2_json(b1_json()), &expected_json);
}
#[test]
fn D2b2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&b2_human(D2_human()), &expected_human);
    assert_parse_error_json(D2_json(b2_json()), &expected_json);
}
#[test]
fn D2c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(D2_human()), &expected_human);
    assert_parse_error_json(D2_json(c_json()), &expected_json);
}
#[test]
fn D3a1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&a1_human(D3_human()), &expected_human);
    assert_parse_error_json(D3_json(a1_json()), &expected_json);
}
#[test]
fn D3a2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&a2_human(D3_human()), &expected_human);
    assert_parse_error_json(D3_json(a2_json()), &expected_json);
}
#[test]
fn D3b1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&b1_human(D3_human()), &expected_human);
    assert_parse_error_json(D3_json(b1_json()), &expected_json);
}
#[test]
fn D3b2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&b2_human(D3_human()), &expected_human);
    assert_parse_error_json(D3_json(b2_json()), &expected_json);
}
#[test]
fn D3c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(D3_human()), &expected_human);
    assert_parse_error_json(D3_json(c_json()), &expected_json);
}
#[test]
fn D3d1() {
    assert_parses_successfully_human(&d1_human(D3_human()));
    assert_parses_successfully_json(D3_json(d1_json()));
}
#[test]
fn D3d2() {
    // this is an error because we currently don't support `entity E in [common-type]`.
    // The error message could be more clear, e.g., specialized to check whether
    // the type that failed to resolve would have resolved to a common type if
    // it were allowed to.
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&d2_human(D3_human()), &expected_human);
    assert_parse_error_json(D3_json(d2_json()), &expected_json);
}
#[test]
fn E1a1() {
    assert_parses_successfully_human(&a1_human(E1_human()));
    assert_parses_successfully_json(E1_json(a1_json()));
}
#[test]
fn E1a2() {
    // this is an error because we currently don't support `appliesTo { principal: [common-type] }`.
    // The error message could be more clear, e.g., specialized to check whether
    // the type that failed to resolve would have resolved to a common type if
    // it were allowed to.
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            .build();
    assert_parse_error_human(&a2_human(E1_human()), &expected_human);
    assert_parse_error_json(E1_json(a2_json()), &expected_json);
}
#[test]
fn E1b1() {
    assert_parses_successfully_human(&b1_human(E1_human()));
    assert_parses_successfully_json(E1_json(b1_json()));
}
#[test]
fn E1b2() {
    // this is an error because we currently don't support `appliesTo { principal: [common-type] }`.
    // The error message could be more clear, e.g., specialized to check whether
    // the type that failed to resolve would have resolved to a common type if
    // it were allowed to.
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            .build();
    assert_parse_error_human(&b2_human(E1_human()), &expected_human);
    assert_parse_error_json(E1_json(b2_json()), &expected_json);
}
#[test]
fn E1c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: MyType")
            .help("neither `NS1::MyType` nor `MyType` refers to anything that has been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(E1_human()), &expected_human);
    assert_parse_error_json(E1_json(c_json()), &expected_json);
}
#[test]
fn E2a1() {
    assert_parses_successfully_human(&a1_human(E2_human()));
    assert_parses_successfully_json(E2_json(a1_json()));
}
#[test]
fn E2a2() {
    // this is an error because we currently don't support `appliesTo { principal: [common-type] }`.
    // The error message could be more clear, e.g., specialized to check whether
    // the type that failed to resolve would have resolved to a common type if
    // it were allowed to.
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&a2_human(E2_human()), &expected_human);
    assert_parse_error_json(E2_json(a2_json()), &expected_json);
}
#[test]
fn E2b1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&b1_human(E2_human()), &expected_human);
    assert_parse_error_json(E2_json(b1_json()), &expected_json);
}
#[test]
fn E2b2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&b2_human(E2_human()), &expected_human);
    assert_parse_error_json(E2_json(b2_json()), &expected_json);
}
#[test]
fn E2c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS1::MyType")
            .help("`NS1::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(E2_human()), &expected_human);
    assert_parse_error_json(E2_json(c_json()), &expected_json);
}
#[test]
fn E3a1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&a1_human(E3_human()), &expected_human);
    assert_parse_error_json(E3_json(a1_json()), &expected_json);
}
#[test]
fn E3a2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&a2_human(E3_human()), &expected_human);
    assert_parse_error_json(E3_json(a2_json()), &expected_json);
}
#[test]
fn E3b1() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&b1_human(E3_human()), &expected_human);
    assert_parse_error_json(E3_json(b1_json()), &expected_json);
}
#[test]
fn E3b2() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS2::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&b2_human(E3_human()), &expected_human);
    assert_parse_error_json(E3_json(b2_json()), &expected_json);
}
#[test]
fn E3c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            // TODO: why don't we have an underline here? (Uncommenting this produces test failure)
            //.exactly_one_underline("NS1::MyType")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&c_human(E3_human()), &expected_human);
    assert_parse_error_json(E3_json(c_json()), &expected_json);
}
#[test]
fn E3d1() {
    assert_parses_successfully_human(&d1_human(E3_human()));
    assert_parses_successfully_json(E3_json(d1_json()));
}
#[test]
fn E3d2() {
    // this is an error because we currently don't support `appliesTo { principal: [common-type] }`.
    // The error message could be more clear, e.g., specialized to check whether
    // the type that failed to resolve would have resolved to a common type if
    // it were allowed to.
    let expected_human =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("failed to resolve type: NS2::MyType")
            .help("`NS2::MyType` has not been declared as an entity type")
            .build();
    assert_parse_error_human(&d2_human(E3_human()), &expected_human);
    assert_parse_error_json(E3_json(d2_json()), &expected_json);
}
#[test]
fn F1a() {
    assert_parses_successfully_human(F1a_human());
    assert_parses_successfully_json(F1a_json());
}
#[test]
fn F1b() {
    assert_parses_successfully_human(F1b_human());
    assert_parses_successfully_json(F1b_json());
}
#[test]
fn F1c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("undeclared action: Action::\"ActionGroup\"")
            .help("any actions appearing as parents need to be declared as actions")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("undeclared action: Action::\"ActionGroup\"")
            .help("any actions appearing as parents need to be declared as actions")
            .build();
    assert_parse_error_human(F1c_human(), &expected_human);
    assert_parse_error_json(F1c_json(), &expected_json);
}
#[test]
fn F2a() {
    assert_parses_successfully_human(F2a_human());
    assert_parses_successfully_json(F2a_json());
}
#[test]
fn F2b() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("undeclared action: NS1::Action::\"ActionGroup\"")
            .help("any actions appearing as parents need to be declared as actions")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("undeclared action: NS1::Action::\"ActionGroup\"")
            .help("any actions appearing as parents need to be declared as actions")
            .build();
    assert_parse_error_human(F2b_human(), &expected_human);
    assert_parse_error_json(F2b_json(), &expected_json);
}
#[test]
fn F2c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("undeclared action: NS1::Action::\"ActionGroup\"")
            .help("any actions appearing as parents need to be declared as actions")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("undeclared action: NS1::Action::\"ActionGroup\"")
            .help("any actions appearing as parents need to be declared as actions")
            .build();
    assert_parse_error_human(F2c_human(), &expected_human);
    assert_parse_error_json(F2c_json(), &expected_json);
}
#[test]
fn F3a() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("undeclared action: NS2::Action::\"ActionGroup\"")
            .help("any actions appearing as parents need to be declared as actions")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("undeclared action: NS2::Action::\"ActionGroup\"")
            .help("any actions appearing as parents need to be declared as actions")
            .build();
    assert_parse_error_human(F3a_human(), &expected_human);
    assert_parse_error_json(F3a_json(), &expected_json);
}
#[test]
fn F3b() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("undeclared action: NS2::Action::\"ActionGroup\"")
            .help("any actions appearing as parents need to be declared as actions")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("undeclared action: NS2::Action::\"ActionGroup\"")
            .help("any actions appearing as parents need to be declared as actions")
            .build();
    assert_parse_error_human(F3b_human(), &expected_human);
    assert_parse_error_json(F3b_json(), &expected_json);
}
#[test]
fn F3c() {
    let expected_human =
        ExpectedErrorMessageBuilder::error("undeclared action: NS2::Action::\"ActionGroup\"")
            .help("any actions appearing as parents need to be declared as actions")
            .build();
    let expected_json =
        ExpectedErrorMessageBuilder::error("undeclared action: NS2::Action::\"ActionGroup\"")
            .help("any actions appearing as parents need to be declared as actions")
            .build();
    assert_parse_error_human(F3c_human(), &expected_human);
    assert_parse_error_json(F3c_json(), &expected_json);
}
#[test]
fn F3d() {
    assert_parses_successfully_human(F3d_human());
    assert_parses_successfully_json(F3d_json());
}
