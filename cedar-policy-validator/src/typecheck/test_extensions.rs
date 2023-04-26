//! Contains tests for typechecking Cedar extensions
#![cfg(test)]
// GRCOV_STOP_COVERAGE

use cedar_policy_core::{
    ast::{Expr, Name},
    parser,
};

use crate::{type_error::TypeError, types::Type};

use super::test_utils::{assert_typecheck_fails_empty_schema, assert_typechecks_empty_schema};

#[test]
#[cfg(feature = "ipaddr")]
fn ip_extension_typechecks() {
    let ipaddr_name = Name::parse_unqualified_name("ipaddr").expect("should be a valid identifier");
    let expr = parser::parse_expr("ip(\"127.0.0.1\")").expect("parsing should succeed");
    assert_typechecks_empty_schema(expr, Type::extension(ipaddr_name));
    let expr = parser::parse_expr("ip(\"1:2:3:4::/48\").isIpv4()").expect("parsing should succeed");
    assert_typechecks_empty_schema(expr, Type::primitive_boolean());
    let expr = parser::parse_expr("ip(\"127.0.0.1\").isInRange(ip(\"1:2:3:4::/48\"))")
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(expr, Type::primitive_boolean());
}

#[test]
#[cfg(feature = "ipaddr")]
fn ip_extension_typecheck_fails() {
    let ipaddr_name = Name::parse_unqualified_name("ipaddr").expect("should be a valid identifier");
    let expr = parser::parse_expr("ip(3)").expect("parsing should succeed");
    assert_typecheck_fails_empty_schema(
        expr,
        Type::extension(ipaddr_name.clone()),
        vec![TypeError::expected_type(
            Expr::val(3),
            Type::primitive_string(),
            Type::primitive_long(),
        )],
    );
    let expr = parser::parse_expr("ip(\"foo\")").expect("parsing should succeed");
    assert_typecheck_fails_empty_schema(
        expr.clone(),
        Type::extension(ipaddr_name.clone()),
        vec![TypeError::arg_validation_error(
            expr,
            "Failed to parse as IP address: \"foo\"".into(),
        )],
    );
    let expr = parser::parse_expr("ip(\"127.0.0.1\").isIpv4(3)").expect("parsing should succeed");
    assert_typecheck_fails_empty_schema(
        expr.clone(),
        Type::primitive_boolean(),
        vec![TypeError::wrong_number_args(expr, 1, 2)],
    );
    let expr =
        parser::parse_expr("ip(\"127.0.0.1\").isInRange(3)").expect("parsing should succeed");
    assert_typecheck_fails_empty_schema(
        expr,
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val(3),
            Type::extension(ipaddr_name),
            Type::primitive_long(),
        )],
    );
}

#[test]
#[cfg(feature = "decimal")]
fn decimal_extension_typechecks() {
    let decimal_name =
        Name::parse_unqualified_name("decimal").expect("should be a valid identifier");
    let expr = parser::parse_expr("decimal(\"1.23\")").expect("parsing should succeed");
    assert_typechecks_empty_schema(expr, Type::extension(decimal_name));
    let expr = parser::parse_expr("decimal(\"1.23\").lessThan(decimal(\"1.24\"))")
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(expr, Type::primitive_boolean());
    let expr = parser::parse_expr("decimal(\"1.23\").lessThanOrEqual(decimal(\"1.24\"))")
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(expr, Type::primitive_boolean());
    let expr = parser::parse_expr("decimal(\"1.23\").greaterThan(decimal(\"1.24\"))")
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(expr, Type::primitive_boolean());
    let expr = parser::parse_expr("decimal(\"1.23\").greaterThanOrEqual(decimal(\"1.24\"))")
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(expr, Type::primitive_boolean());
}

#[test]
#[cfg(feature = "decimal")]
fn decimal_extension_typecheck_fails() {
    let decimal_name =
        Name::parse_unqualified_name("decimal").expect("should be a valid identifier");
    let expr = parser::parse_expr("decimal(3)").expect("parsing should succeed");
    assert_typecheck_fails_empty_schema(
        expr,
        Type::extension(decimal_name.clone()),
        vec![TypeError::expected_type(
            Expr::val(3),
            Type::primitive_string(),
            Type::primitive_long(),
        )],
    );
    let expr = parser::parse_expr("decimal(\"foo\")").expect("parsing should succeed");
    assert_typecheck_fails_empty_schema(
        expr.clone(),
        Type::extension(decimal_name.clone()),
        vec![TypeError::arg_validation_error(
            expr,
            "Failed to parse as a decimal value: \"foo\"".into(),
        )],
    );
    let expr =
        parser::parse_expr("decimal(\"1.23\").lessThan(3, 4)").expect("parsing should succeed");
    assert_typecheck_fails_empty_schema(
        expr.clone(),
        Type::primitive_boolean(),
        vec![TypeError::wrong_number_args(expr, 2, 3)],
    );
    let expr = parser::parse_expr("decimal(\"1.23\").lessThan(3)").expect("parsing should succeed");
    assert_typecheck_fails_empty_schema(
        expr,
        Type::primitive_boolean(),
        vec![TypeError::expected_type(
            Expr::val(3),
            Type::extension(decimal_name),
            Type::primitive_long(),
        )],
    );
}
