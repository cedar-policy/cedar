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

//! Contains test for typechecking with integer overflow detection.
#![cfg(test)]
// GRCOV_STOP_COVERAGE

// Testing simple expressions over literals.
mod exprs {
    use std::{collections::HashSet, str::FromStr};

    use cedar_policy_core::ast::Expr;

    use crate::{
        typecheck::{
            test_utils::{
                assert_typechecks_empty_schema, empty_schema_file, with_typechecker_from_schema,
            },
            ArithmeticOpBoundsInfo, Bounds128,
        },
        types::Type,
        TypeErrorKind, ValidationMode,
    };

    fn assert_expr_overflows(expr: Expr, overflow_bounds: Bounds128) {
        with_typechecker_from_schema(empty_schema_file(), |mut typechecker| {
            typechecker.mode = ValidationMode::Strict;
            let mut type_errors = HashSet::new();
            let ans = typechecker.typecheck_expr(&expr, &mut type_errors);

            match type_errors.iter().next().map(|e| &e.kind) {
                Some(TypeErrorKind::ArithmeticOverflow(info)) => {
                    let result_bounds = match info {
                        ArithmeticOpBoundsInfo::BinaryOp { result_bounds, .. } => result_bounds,
                        ArithmeticOpBoundsInfo::Multiplication { result_bounds, .. } => {
                            result_bounds
                        }
                        ArithmeticOpBoundsInfo::UnaryOp { result_bounds, .. } => result_bounds,
                    };
                    assert_eq!(result_bounds, &overflow_bounds,);
                }
                _ => panic!(
                    "Expected that exactly one over flow error would be found. Saw {:?}",
                    type_errors
                ),
            };
            assert!(
                !ans.typechecked(),
                "Expected that typechecking would fail, but result was {:?}",
                ans
            );
        });
    }

    #[test]
    fn literal_typechecks() {
        assert_typechecks_empty_schema(Expr::val(0), Type::singleton_long(0));
        assert_typechecks_empty_schema(Expr::val(i64::MIN), Type::singleton_long(i64::MIN));
        assert_typechecks_empty_schema(Expr::val(i64::MAX), Type::singleton_long(i64::MAX));
    }

    #[test]
    fn neg_typechecks() {
        assert_typechecks_empty_schema(Expr::neg(Expr::val(0)), Type::singleton_long(0));
        assert_typechecks_empty_schema(Expr::neg(Expr::val(1)), Type::singleton_long(-1));
        assert_typechecks_empty_schema(
            Expr::neg(Expr::val(i64::MAX)),
            Type::singleton_long(-i64::MAX),
        );
    }

    #[test]
    fn neg_overflow() {
        assert_expr_overflows(
            Expr::neg(Expr::val(i64::MIN)),
            Bounds128 {
                min: -Into::<i128>::into(i64::MIN),
                max: -Into::<i128>::into(i64::MIN),
            },
        );
    }

    #[test]
    fn mul_typechecks() {
        assert_typechecks_empty_schema(Expr::mul(Expr::val(i64::MIN), 0), Type::singleton_long(0));
        assert_typechecks_empty_schema(
            Expr::mul(Expr::val(i64::MIN), 1),
            Type::singleton_long(i64::MIN),
        );
        assert_typechecks_empty_schema(Expr::mul(Expr::val(i64::MAX), 0), Type::singleton_long(0));
        assert_typechecks_empty_schema(
            Expr::mul(Expr::val(i64::MAX), 1),
            Type::singleton_long(i64::MAX),
        );
    }

    #[test]
    fn mul_overflow() {
        assert_expr_overflows(
            Expr::mul(Expr::val(i64::MIN / 3), 4),
            Bounds128 {
                min: (Into::<i128>::into(i64::MIN) / 3) * 4,
                max: (Into::<i128>::into(i64::MIN) / 3) * 4,
            },
        );
        assert_expr_overflows(
            Expr::mul(Expr::val(i64::MAX), 2),
            Bounds128 {
                min: Into::<i128>::into(i64::MAX) * 2,
                max: Into::<i128>::into(i64::MAX) * 2,
            },
        );
    }

    #[test]
    fn add_typechecks() {
        assert_typechecks_empty_schema(
            Expr::add(Expr::val(i64::MAX), Expr::val(0)),
            Type::singleton_long(i64::MAX),
        );
    }

    #[test]
    fn add_overflow() {
        assert_expr_overflows(
            Expr::add(Expr::val(i64::MAX), Expr::val(1)),
            Bounds128 {
                min: Into::<i128>::into(i64::MAX) + 1,
                max: Into::<i128>::into(i64::MAX) + 1,
            },
        );
    }

    #[test]
    fn sub_typechecks() {
        assert_typechecks_empty_schema(
            Expr::sub(Expr::val(i64::MIN), Expr::val(0)),
            Type::singleton_long(i64::MIN),
        );
    }

    #[test]
    fn sub_overflow() {
        assert_expr_overflows(
            Expr::sub(Expr::val(i64::MIN), Expr::val(1)),
            Bounds128 {
                min: Into::<i128>::into(i64::MIN) - 1,
                max: Into::<i128>::into(i64::MIN) - 1,
            },
        );
    }

    #[test]
    fn if_overflow() {
        assert_expr_overflows(
            Expr::from_str(&format!(
                "(if 1 > 0 then {} else {}) + 1",
                i64::MIN,
                i64::MAX
            ))
            .unwrap(),
            Bounds128 {
                min: Into::<i128>::into(i64::MIN) + 1,
                max: Into::<i128>::into(i64::MAX) + 1,
            },
        );
        assert_expr_overflows(
            Expr::from_str(&format!(
                "(if 1 > 0 then {} else {}) - 1",
                i64::MIN,
                i64::MAX
            ))
            .unwrap(),
            Bounds128 {
                min: Into::<i128>::into(i64::MIN) - 1,
                max: Into::<i128>::into(i64::MAX) - 1,
            },
        );
        assert_expr_overflows(
            Expr::from_str(&format!(
                "(if 1 > 0 then {} else {}) * 2",
                i64::MIN,
                i64::MAX
            ))
            .unwrap(),
            Bounds128 {
                min: Into::<i128>::into(i64::MIN) * 2,
                max: Into::<i128>::into(i64::MAX) * 2,
            },
        );
        assert_expr_overflows(
            Expr::from_str(&format!("- (if 1 > 0 then {} else {})", i64::MIN, i64::MAX)).unwrap(),
            Bounds128 {
                min: -Into::<i128>::into(i64::MAX),
                max: -Into::<i128>::into(i64::MIN),
            },
        );
    }
}

// Testing full policies relying on bounds in the schema.
mod schema_bounds {
    use std::{collections::HashSet, sync::Arc};

    use cedar_policy_core::{ast::Template, parser::parse_policy};

    use crate::{
        typecheck::{test_utils::assert_policy_typechecks, Bounds128},
        NamespaceDefinition, ValidatorSchema,
    };

    use crate::{
        typecheck::{test_utils::with_typechecker_from_schema, ArithmeticOpBoundsInfo},
        TypeErrorKind, ValidationMode,
    };

    fn assert_overflows(
        schema: impl TryInto<ValidatorSchema, Error = impl core::fmt::Debug>,
        policy: impl Into<Arc<Template>>,
        overflow_bounds: Bounds128,
    ) {
        with_typechecker_from_schema(schema, |mut typechecker| {
            typechecker.mode = ValidationMode::Strict;
            let mut type_errors = HashSet::new();
            let ans = typechecker.typecheck_policy(&policy.into(), &mut type_errors);

            match type_errors.iter().next().map(|e| &e.kind) {
                Some(TypeErrorKind::ArithmeticOverflow(info)) => {
                    let result_bounds = match info {
                        ArithmeticOpBoundsInfo::BinaryOp { result_bounds, .. } => result_bounds,
                        ArithmeticOpBoundsInfo::Multiplication { result_bounds, .. } => {
                            result_bounds
                        }
                        ArithmeticOpBoundsInfo::UnaryOp { result_bounds, .. } => result_bounds,
                    };
                    assert_eq!(result_bounds, &overflow_bounds,);
                }
                _ => panic!(
                    "Expected that exactly one over flow error would be found. Saw {:?}",
                    type_errors
                ),
            };
            assert!(
                !ans,
                "Expected that typechecking would fail, but result was {:?}",
                ans
            );
        });
    }

    fn schema_file() -> NamespaceDefinition {
        serde_json::from_value(serde_json::json!(
            {
                "entityTypes": {
                  "User": {
                    "shape": {
                      "type": "Record",
                      "attributes": {
                        "x8": { "type": "Long", "min": 1, "max": 8 },
                        "flag": { "type": "Boolean", "required": true },
                        "x_any": { "type": "Long" }
                      }
                    }
                  }
                },
                "actions": {
                  "view": {
                    "appliesTo": {
                      "principalTypes": ["User"],
                      "resourceTypes": ["User"]
                    }
                  }
                }
              }
        ))
        .unwrap()
    }

    #[test]
    fn add_typechecks() {
        assert_policy_typechecks(
            schema_file(),
            parse_policy(None, r#"
                permit(principal == User::"alice", action, resource)
                when { principal.x8 + 9223372036854775799 > 0 };
            "#,).unwrap(),
        );
    }

    #[test]
    fn sub_typechecks() {
        assert_policy_typechecks(
            schema_file(),
            parse_policy(None, r#"
                permit(principal == User::"alice", action, resource)
                when { -9223372036854775800 - principal.x8 < 0 };
            "#,).unwrap(),
        );
    }

    #[test]
    fn mul_typechecks() {
        assert_policy_typechecks(
            schema_file(),
            parse_policy(None, r#"
                permit(principal == User::"alice", action, resource)
                when { 1152921504606846975 * principal.x8 > 0 };
            "#,).unwrap(),
        );
    }

    #[test]
    fn neg_typechecks() {
        assert_policy_typechecks(
            schema_file(),
            parse_policy(None, r#"
                permit(principal == User::"alice", action, resource)
                when { -(-9223372036854775799 - principal.x8) > 0 };
            "#,).unwrap(),
        );
    }

    #[test]
    fn if_typechecks() {
        assert_policy_typechecks(
            schema_file(),
            parse_policy(None, r#"
                permit(principal == User::"alice", action, resource)
                when { 
                    ((if principal.flag then principal.x8 else - principal.x8) + 9223372036854775799) > 0
                };
            "#,).unwrap(),
        );
        assert_policy_typechecks(
            schema_file(),
            parse_policy(None, r#"
                permit(principal == User::"alice", action, resource)
                when { 
                    (-9223372036854775800 - (if principal.flag then principal.x8 else - principal.x8)) > 0
                };
            "#,).unwrap(),
        );
    }

    #[test]
    fn add_overflow() {
        assert_overflows(schema_file(), parse_policy(None, r#"
            permit(principal == User::"alice", action, resource)
            when { principal.x8 + 9223372036854775800 > 0 };
        "#).unwrap(),
        Bounds128 {
            min: 9223372036854775801,
            max: 9223372036854775808,
        });
    }

    #[test]
    fn sub_overflow() {
        assert_overflows(schema_file(), parse_policy(None, r#"
            permit(principal == User::"alice", action, resource)
            when { -9223372036854775801 - principal.x8 < 0 };
        "#).unwrap(),
        Bounds128 {
            min: -9223372036854775809,
            max: -9223372036854775802,
        });
    }

    #[test]
    fn mul_overflow() {
        assert_overflows(schema_file(), parse_policy(None, r#"
            permit(principal == User::"alice", action, resource)
            when { 1152921504606846976 * principal.x8 > 0 };
        "#).unwrap(),
        Bounds128 {
            min: 1152921504606846976,
            max: 9223372036854775808,
        });
    }

    #[test]
    fn neg_overflow() {
        assert_overflows(schema_file(), parse_policy(None, r#"
            permit(principal == User::"alice", action, resource)
            when { -(-9223372036854775800 - principal.x8) > 0 };
        "#).unwrap(),
        Bounds128 {
            min: 9223372036854775801,
            max: 9223372036854775808,
        });
    }

    #[test]
    fn if_overflow() {
        assert_overflows(schema_file(), parse_policy(None, r#"
            permit(principal == User::"alice", action, resource)
            when { 
                ((if principal.flag then principal.x8 else - principal.x8) + 9223372036854775800) > 0
            };
        "#).unwrap(),
        Bounds128 {
            min: 9223372036854775792,
            max: 9223372036854775808,
        });
        assert_overflows(schema_file(), parse_policy(None, r#"
            permit(principal == User::"alice", action, resource)
            when { 
                (-9223372036854775801 - (if principal.flag then principal.x8 else - principal.x8)) > 0
            };
        "#).unwrap(),
        Bounds128 {
            min: 0,
            max: 0,
        });
    }
}
