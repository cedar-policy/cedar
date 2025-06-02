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

//! Contains test for typechecking complete Cedar policies with namespaced
//! schema files.

use cool_asserts::assert_matches;
use serde_json::json;
use std::collections::HashSet;
use std::str::FromStr;
use std::vec;

use crate::{
    ast::{Expr, PolicyID, StaticPolicy},
    extensions::Extensions,
    parser::parse_policy,
};

use super::test_utils::{
    assert_exactly_one_diagnostic, assert_policy_typecheck_fails, assert_policy_typecheck_warns,
    assert_policy_typechecks, assert_sets_equal, assert_typecheck_fails, assert_typechecks,
    expr_id_placeholder, get_loc,
};
use crate::validator::{
    diagnostics::ValidationError,
    json_schema,
    types::{EntityLUB, Type},
    validation_errors::AttributeAccess,
    RawName, SchemaError, ValidationWarning, ValidatorSchema,
};

fn namespaced_entity_type_schema() -> json_schema::Fragment<RawName> {
    json_schema::Fragment::from_json_str(
        r#"
            { "N::S": {
                "entityTypes": {
                    "Foo": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "name": { "type": "String" }
                            }
                        }
                    },
                    "Bar": {}
                },
                "actions": {
                  "baz": {
                    "appliesTo": {
                      "principalTypes": [ "Bar" ],
                      "resourceTypes": [ "Foo" ]
                    }
                  }
                }
            }}
            "#,
    )
    .expect("Expected valid schema")
}

#[test]
fn namespaced_entity_eq() {
    assert_typechecks(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"N::S::Foo::"alice" == N::S::Foo::"alice""#).expect("Expr should parse."),
        &Type::True,
    );
    assert_typechecks(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"N::S::Foo::"alice" == N::S::Foo::"bob""#).expect("Expr should parse."),
        &Type::False,
    );
    assert_typechecks(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"N::S::Foo::"alice" == N::S::Bar::"bob""#).expect("Expr should parse."),
        &Type::False,
    );
    assert_typechecks(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"N::S::Action::"baz" == N::S::Action::"baz""#)
            .expect("Expr should parse."),
        &Type::True,
    );
}

#[test]
fn namespaced_entity_in() {
    assert_typechecks(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"N::S::Foo::"alice" in N::S::Foo::"bob""#).expect("Expr should parse."),
        &Type::primitive_boolean(),
    );
    assert_typechecks(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"N::S::Foo::"alice" in N::S::Bar::"bob""#).expect("Expr should parse."),
        &Type::False,
    );
}

#[test]
fn namespaced_entity_has() {
    assert_typechecks(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"N::S::Foo::"alice" has foo"#).expect("Expr should parse."),
        &Type::False,
    );
    assert_typechecks(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"N::S::Foo::"alice" has name"#).expect("Expr should parse."),
        &Type::primitive_boolean(),
    );
}

#[test]
fn namespaced_entity_get_attr() {
    assert_typechecks(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"N::S::Foo::"alice".name"#).expect("Expr should parse."),
        &Type::primitive_string(),
    );
}

#[test]
fn namespaced_entity_can_type_error() {
    let src = r#"N::S::Foo::"alice" > 1"#;
    let errors = assert_typecheck_fails(
        namespaced_entity_type_schema(),
        &Expr::from_str(src).expect("Expr should parse."),
        Some(&Type::primitive_boolean()),
    );
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::expected_one_of_types(
            get_loc(src, r#"N::S::Foo::"alice""#),
            expr_id_placeholder(),
            vec![Type::primitive_long()],
            Type::named_entity_reference_from_str("N::S::Foo"),
            None,
        )
    );
}

#[test]
fn namespaced_entity_wrong_namespace() {
    let errors = assert_typecheck_fails(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"N::S::T::Foo::"alice""#).expect("Expr should parse."),
        None,
    );
    assert_sets_equal(errors, []);
    let errors = assert_typecheck_fails(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"N::Foo::"alice""#).expect("Expr should parse."),
        None,
    );
    assert_sets_equal(errors, []);
    let errors = assert_typecheck_fails(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"Foo::"alice""#).expect("Expr should parse."),
        None,
    );
    assert_sets_equal(errors, []);
    let errors = assert_typecheck_fails(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"N::Action::"baz""#).expect("Expr should parse."),
        None,
    );
    assert_sets_equal(errors, []);
    let errors = assert_typecheck_fails(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"Action::N::S::"baz""#).expect("Expr should parse."),
        None,
    );
    assert_sets_equal(errors, []);
    let errors = assert_typecheck_fails(
        namespaced_entity_type_schema(),
        &Expr::from_str(r#"Action::"baz""#).expect("Expr should parse."),
        None,
    );
    assert_sets_equal(errors, []);
}

#[test]
fn namespaced_entity_type_in_attribute() {
    let schema = json_schema::Fragment::from_json_str(
        r#"{ "N::S":
            {
                "entityTypes": {
                    "Foo": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "bar": { "type": "Entity", "name": "N::S::Bar" },
                                "baz": { "type": "Entity", "name": "Bar" }
                            }
                        }
                    },
                    "Bar": {}
                },
                "actions": {}
              }}
            "#,
    )
    .expect("Expected valid schema");
    // Explicit namespace is kept on the attribute type and correctly used in
    // comparison.
    assert_typechecks(
        schema.clone(),
        &Expr::from_str(r#"N::S::Foo::"foo".bar == N::S::Bar::"bar""#).expect("Expr should parse."),
        &Type::primitive_boolean(),
    );
    assert_typechecks(
        schema.clone(),
        &Expr::from_str(r#"N::S::Foo::"foo".bar == N::S::Foo::"foo""#).expect("Expr should parse."),
        &Type::singleton_boolean(false),
    );
    // Implicit namespace is applied to the attribute type and correctly used in
    // comparison.
    assert_typechecks(
        schema.clone(),
        &Expr::from_str(r#"N::S::Foo::"foo".baz == N::S::Bar::"bar""#).expect("Expr should parse."),
        &Type::primitive_boolean(),
    );
    assert_typechecks(
        schema,
        &Expr::from_str(r#"N::S::Foo::"foo".baz == N::S::Foo::"foo""#).expect("Expr should parse."),
        &Type::singleton_boolean(false),
    );
}

#[test]
fn namespaced_entity_type_member_of() {
    let schema = json_schema::Fragment::from_json_value(serde_json::json!(
    {"N::S": {
        "entityTypes": {
            "Foo": {
                "memberOfTypes": ["N::S::Bar"]
            },
            "Fiz": {
                "memberOfTypes": ["Bar"]
            },
            "Bar": { },
            "Resource" : { }
        },
        "actions": {
          "baz": {
            "appliesTo": {
              "principalTypes": [ "Foo", "Fiz" ],
              "resourceTypes": [ "Resource" ]
            }
          }
        }
    }}
    ))
    .expect("Expected valid schema");
    // Two request environments will be typechecked. One with `Foo` and one with
    // `Fiz`. Both are `memberOf` `Bar`, but write it as qualified and
    // unqualified respectively.
    assert_policy_typechecks(schema, parse_policy(None, r#"
        permit(principal in N::S::Bar::"bar", action, resource) when { principal == N::S::Foo::"foo" };
    "#).unwrap());
}

#[test]
fn namespaced_entity_type_applies_to() {
    let schema = json_schema::Fragment::from_json_value(serde_json::json!(
    {"N::S": {
        "entityTypes": {
            "Foo": { },
            "Bar": { }
        },
        "actions": {
          "baz": {
            "appliesTo": {
              // `Foo` is implicitly namespaced while `Bar` is explicitly
              // namespaced. Both should be valid.
              "principalTypes": [ "Foo" ],
              "resourceTypes": [ "N::S::Bar" ]
            }
          }
        }
      }}
    ))
    .expect("Expected valid schema");
    assert_policy_typechecks(schema, parse_policy(None, r#"
        permit(principal == N::S::Foo::"a", action == N::S::Action::"baz", resource == N::S::Bar::"b");
    "#).unwrap());
}

#[test]
fn multiple_namespaces_literals() {
    let authorization_model = json_schema::Fragment::from_json_value(json!(
        {
            "A": {
                "entityTypes": {"Foo": {}},
                "actions": {}
            },
            "B": {
                "entityTypes": {"Foo": {}},
                "actions": {}
            },
            "C": {
                "entityTypes": {"Foo": {}},
                "actions": {}
            }
        }
    ))
    .unwrap();
    let schema: ValidatorSchema = authorization_model.try_into().unwrap();

    assert_typechecks(
        schema.clone(),
        &Expr::from_str("A::Foo::\"foo\"").unwrap(),
        &Type::named_entity_reference_from_str("A::Foo"),
    );
    assert_typechecks(
        schema.clone(),
        &Expr::from_str("B::Foo::\"foo\"").unwrap(),
        &Type::named_entity_reference_from_str("B::Foo"),
    );
    assert_typechecks(
        schema,
        &Expr::from_str("C::Foo::\"foo\"").unwrap(),
        &Type::named_entity_reference_from_str("C::Foo"),
    );
}

#[test]
fn multiple_namespaces_attributes() {
    let authorization_model = json_schema::Fragment::from_json_value(json!(
        {
            "A": {
                "entityTypes": {
                    "Foo": {
                      "shape": {
                          "type": "Record",
                          "attributes": {
                              "x": {"type": "Entity", "name": "B::Foo"}
                          }
                      }
                    }
                },
                "actions": {}
            },
            "B": {
                "entityTypes": {"Foo": {}},
                "actions": {}
            }
        }
    ))
    .unwrap();
    let schema: ValidatorSchema = authorization_model.try_into().unwrap();

    assert_typechecks(
        schema.clone(),
        &Expr::from_str("A::Foo::\"foo\".x").unwrap(),
        &Type::named_entity_reference_from_str("B::Foo"),
    );
    let src = "B::Foo::\"foo\".x";
    let errors = assert_typecheck_fails(schema, &Expr::from_str(src).unwrap(), None);
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::unsafe_attribute_access(
            get_loc(src, src),
            PolicyID::from_string("expr"),
            AttributeAccess::EntityLUB(
                EntityLUB::single_entity("B::Foo".parse().unwrap()),
                vec!["x".into()],
            ),
            None,
            false,
        )
    );
}

#[test]
fn multiple_namespaces_member_of() {
    let schema = json_schema::Fragment::from_json_value(json!(
        {
            "A": {
                "entityTypes": {
                    "Foo": {
                        "memberOfTypes": ["B::Foo"]
                    },
                    "Bar": {}
                },
                "actions": {
                    "act": {
                        "appliesTo": {
                            "principalTypes": ["Foo"],
                            "resourceTypes" : ["Bar"]
                        }
                    }
                }
            },
            "B": {
                "entityTypes": {"Foo": {}},
                "actions": {}
            }
        }
    ))
    .unwrap();

    assert_policy_typechecks(
        schema,
        parse_policy(
            None,
            r#"permit(principal in B::Foo::"foo", action == A::Action::"act", resource);"#,
        )
        .unwrap(),
    );
}

#[test]
fn multiple_namespaces_applies_to() {
    let schema = json_schema::Fragment::from_json_value(json!(
        {
            "A": {
                "entityTypes": {
                  "Foo": {
                      "shape": {
                          "type": "Record",
                          "attributes": {
                              "y": { "type": "Long" },
                          }
                      }
                  },
                },
                "actions": {
                    "act1": {
                        "appliesTo": {
                            "principalTypes": [ "Foo" ],
                            "resourceTypes": [ "B::Foo" ],
                        }
                    },
                    "act2": {
                        "appliesTo": {
                            "principalTypes": [ "B::Foo" ],
                            "resourceTypes": [ "Foo" ],
                        }
                    }
                }
            },
            "B": {
                "entityTypes": {
                    "Foo": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "x": { "type": "String" },
                            }
                        }
                    },
                },
                "actions": { }
            }
        }
    ))
    .unwrap();

    assert_policy_typechecks(
        schema.clone(),
        parse_policy(
            None,
            r#"permit(principal == A::Foo::"bar", action == A::Action::"act1", resource) when { resource.x like "bar*" };"#,
        )
        .unwrap(),
    );
    assert_policy_typechecks(
        schema,
        parse_policy(
            None,
            r#"permit(principal == B::Foo::"bar", action == A::Action::"act2", resource) when { resource.y > 0};"#,
        )
        .unwrap(),
    );
}

// Test cases added for namespace bug found by DRT.

#[track_caller] // report the caller's location as the location of the panic, not the location in this function
fn assert_policy_typecheck_fails_namespace_schema(p: StaticPolicy) -> HashSet<ValidationError> {
    assert_policy_typecheck_fails(namespaced_entity_type_schema(), p)
}

#[test]
fn namespaced_entity_is_wrong_type_and() {
    let src = r#"
            permit(principal, action, resource)
            when {
                (true && N::S::Foo::"alice")
            };
        "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).expect("Policy should parse.");
    let errors = assert_policy_typecheck_fails_namespace_schema(policy);
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::expected_type(
            get_loc(src, r#"N::S::Foo::"alice""#),
            PolicyID::from_string("0"),
            Type::primitive_boolean(),
            Type::named_entity_reference_from_str("N::S::Foo"),
            None,
        )
    );
}

#[test]
fn namespaced_entity_is_wrong_type_when() {
    let src = r#"
            permit(principal, action, resource)
            when {
                N::S::Foo::"alice"
            };
            "#;
    let policy = parse_policy(Some(PolicyID::from_string("0")), src).expect("Policy should parse.");
    let errors = assert_policy_typecheck_fails_namespace_schema(policy);
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::expected_type(
            get_loc(src, r#"N::S::Foo::"alice""#),
            PolicyID::from_string("0"),
            Type::primitive_boolean(),
            Type::named_entity_reference_from_str("N::S::Foo"),
            None,
        )
    );
}

#[test]
fn multi_namespace_action_eq() {
    let (schema, _) = json_schema::Fragment::from_cedarschema_str(
        r#"
            entity E1;
            action "A" appliesTo { context: {}, principal : [E1], resource : [E1] };
            namespace NS1 {
                entity E;
                action "B" appliesTo { context: {}, principal : [E], resource : [E]};
            }
            namespace NS2 {
                entity E;
                action "B" appliesTo { context: {}, principal : [E], resource : [E]};
            }
        "#,
        Extensions::all_available(),
    )
    .unwrap();

    assert_policy_typechecks(
        schema.clone(),
        parse_policy(
            None,
            r#"permit(principal, action == Action::"A", resource);"#,
        )
        .unwrap(),
    );
    assert_policy_typechecks(
        schema.clone(),
        parse_policy(
            None,
            r#"permit(principal, action == NS1::Action::"B", resource);"#,
        )
        .unwrap(),
    );

    let policy = parse_policy(
        None,
        r#"permit(principal, action, resource) when { NS1::Action::"B" == NS2::Action::"B" };"#,
    )
    .unwrap();
    let warnings = assert_policy_typecheck_warns(schema, policy.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(
            policy.loc().cloned(),
            PolicyID::from_string("policy0"),
        )
    );
}

#[test]
fn multi_namespace_action_in() {
    let (schema, _) = json_schema::Fragment::from_cedarschema_str(
        r#"
            entity E1;
            namespace NS1 { action "Group"; }
            namespace NS2 { action "Group" in [NS1::Action::"Group"]; }
            namespace NS3 {
                action "Group" in [NS2::Action::"Group"];
                entity E;
                action "Action" in [Action::"Group"] appliesTo { context: {}, principal: [E], resource: [E] };
            }
            namespace NS4 { action "Group"; }
        "#,
        Extensions::all_available(),
    )
    .unwrap();

    assert_policy_typechecks(
        schema.clone(),
        parse_policy(
            None,
            r#"permit(principal, action in NS1::Action::"Group", resource);"#,
        )
        .unwrap(),
    );
    assert_policy_typechecks(
        schema.clone(),
        parse_policy(
            None,
            r#"permit(principal, action in NS2::Action::"Group", resource);"#,
        )
        .unwrap(),
    );
    assert_policy_typechecks(
        schema.clone(),
        parse_policy(
            None,
            r#"permit(principal, action in NS3::Action::"Group", resource);"#,
        )
        .unwrap(),
    );
    assert_policy_typechecks(
        schema.clone(),
        parse_policy(
            None,
            r#"permit(principal, action in NS3::Action::"Action", resource);"#,
        )
        .unwrap(),
    );

    let policy = parse_policy(
        None,
        r#"permit(principal, action in NS4::Action::"Group", resource);"#,
    )
    .unwrap();
    let warnings = assert_policy_typecheck_warns(schema, policy.clone());
    let warning = assert_exactly_one_diagnostic(warnings);
    assert_eq!(
        warning,
        ValidationWarning::impossible_policy(
            policy.loc().cloned(),
            PolicyID::from_string("policy0"),
        )
    );
}

#[test]
fn test_cedar_policy_642() {
    let (schema, _) = json_schema::Fragment::from_cedarschema_str(
        r#"
        namespace NS1 {
            entity SystemEntity2 in SystemEntity1;
            entity SystemEntity1, PrincipalEntity;
            action Group1;
        }
        namespace NS2 {
            entity SystemEntity1 in NS1::SystemEntity2;
            action "Group1" in NS1::Action::"Group1";
            action "Action1" in Action::"Group1" appliesTo {
                principal: [NS1::PrincipalEntity],
                resource: [NS2::SystemEntity1],
            };
        }
        "#,
        Extensions::all_available(),
    )
    .unwrap();

    assert_policy_typechecks(
        schema,
        parse_policy(
            None,
            r#"
            permit(
                principal in NS1::PrincipalEntity::"user1",
                action in NS1::Action::"Group1",
                resource in NS1::SystemEntity1::"entity1"
            );"#,
        )
        .unwrap(),
    );
}

#[test]
fn multi_namespace_action_group_cycle() {
    let (schema, _) = json_schema::Fragment::from_cedarschema_str(
        r#"
            namespace A { action "Act" in C::Action::"Act"; }
            namespace B { action "Act" in A::Action::"Act"; }
            namespace C { action "Act" in B::Action::"Act"; }
        "#,
        Extensions::all_available(),
    )
    .unwrap();
    assert_matches!(
        ValidatorSchema::try_from(schema),
        Err(SchemaError::CycleInActionHierarchy(_))
    )
}
