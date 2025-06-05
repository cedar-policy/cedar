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

//! Contains tests for typechecking Cedar extensions

use crate::ast::Expr;
use crate::validator::{diagnostics::ValidationError, types::Type};
use std::str::FromStr;

use super::test_utils::{
    assert_exactly_one_diagnostic, assert_typecheck_fails_empty_schema,
    assert_typechecks_empty_schema, expr_id_placeholder, get_loc,
};

#[test]
#[cfg(feature = "ipaddr")]
fn ip_extension_typechecks() {
    use crate::ast::Name;

    let ipaddr_name = Name::parse_unqualified_name("ipaddr").expect("should be a valid identifier");
    let expr = Expr::from_str("ip(\"127.0.0.1\")").expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::extension(ipaddr_name));
    let expr = Expr::from_str("ip(\"1:2:3:4::/48\").isIpv4()").expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_boolean());
    let expr = Expr::from_str("ip(\"127.0.0.1\").isInRange(ip(\"1:2:3:4::/48\"))")
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_boolean());
}

#[test]
#[cfg(feature = "ipaddr")]
fn ip_extension_typecheck_fails() {
    use crate::ast::Name;

    use crate::validator::typecheck::test::test_utils::assert_exactly_one_diagnostic;

    let ipaddr_name = Name::parse_unqualified_name("ipaddr").expect("should be a valid identifier");
    let src = "ip(3)";
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors = assert_typecheck_fails_empty_schema(&expr, &Type::extension(ipaddr_name.clone()));
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::expected_type(
            get_loc(src, "3"),
            expr_id_placeholder(),
            Type::primitive_string(),
            Type::primitive_long(),
            None,
        )
    );
    let src = "ip(\"foo\")";
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors = assert_typecheck_fails_empty_schema(&expr, &Type::extension(ipaddr_name.clone()));
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::function_argument_validation(
            get_loc(src, src),
            expr_id_placeholder(),
            "Failed to parse as IP address: `\"foo\"`".into(),
        )
    );
    let src = "ip(\"127.0.0.1\").isIpv4(3)";
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors = assert_typecheck_fails_empty_schema(&expr, &Type::primitive_boolean());
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::wrong_number_args(get_loc(src, src), expr_id_placeholder(), 1, 2,)
    );
    let src = "ip(\"127.0.0.1\").isInRange(3)";
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors = assert_typecheck_fails_empty_schema(&expr, &Type::primitive_boolean());
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::expected_type(
            get_loc(src, "3"),
            expr_id_placeholder(),
            Type::extension(ipaddr_name),
            Type::primitive_long(),
            None,
        )
    );
}

#[test]
#[cfg(feature = "decimal")]
fn decimal_extension_typechecks() {
    use crate::ast::Name;

    let decimal_name =
        Name::parse_unqualified_name("decimal").expect("should be a valid identifier");
    let expr = Expr::from_str("decimal(\"1.23\")").expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::extension(decimal_name));
    let expr = Expr::from_str("decimal(\"1.23\").lessThan(decimal(\"1.24\"))")
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_boolean());
    let expr = Expr::from_str("decimal(\"1.23\").lessThanOrEqual(decimal(\"1.24\"))")
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_boolean());
    let expr = Expr::from_str("decimal(\"1.23\").greaterThan(decimal(\"1.24\"))")
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_boolean());
    let expr = Expr::from_str("decimal(\"1.23\").greaterThanOrEqual(decimal(\"1.24\"))")
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_boolean());
}

#[test]
#[cfg(feature = "decimal")]
fn decimal_extension_typecheck_fails() {
    use crate::ast::Name;

    let decimal_name =
        Name::parse_unqualified_name("decimal").expect("should be a valid identifier");
    let src = "decimal(3)";
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors = assert_typecheck_fails_empty_schema(&expr, &Type::extension(decimal_name.clone()));
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::expected_type(
            get_loc(src, "3"),
            expr_id_placeholder(),
            Type::primitive_string(),
            Type::primitive_long(),
            None,
        )
    );
    let src = "decimal(\"foo\")";
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors = assert_typecheck_fails_empty_schema(&expr, &Type::extension(decimal_name.clone()));
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::function_argument_validation(
            get_loc(src, src),
            expr_id_placeholder(),
            "Failed to parse as a decimal value: `\"foo\"`".into(),
        )
    );
    let src = "decimal(\"1.23\").lessThan(3, 4)";
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors = assert_typecheck_fails_empty_schema(&expr, &Type::primitive_boolean());
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::wrong_number_args(get_loc(src, src), expr_id_placeholder(), 2, 3,)
    );
    let src = "decimal(\"1.23\").lessThan(4)";
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors = assert_typecheck_fails_empty_schema(&expr, &Type::primitive_boolean());
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::expected_type(
            get_loc(src, "4"),
            expr_id_placeholder(),
            Type::extension(decimal_name),
            Type::primitive_long(),
            None,
        )
    );
}

#[test]
#[cfg(feature = "datetime")]
fn datetime_extension_typechecks() {
    use crate::ast::Name;

    let datetime_name =
        Name::parse_unqualified_name("datetime").expect("should be a valid identifier");
    let duration_name =
        Name::parse_unqualified_name("duration").expect("should be a valid identifier");

    let expr = Expr::from_str("datetime(\"2024-10-28\")").expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::extension(datetime_name.clone()));
    let expr = Expr::from_str(r#"datetime("2024-10-28").offset(duration("1d"))"#)
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::extension(datetime_name.clone()));
    let expr = Expr::from_str(r#"datetime("2024-10-28").durationSince(datetime("2024-10-28"))"#)
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::extension(duration_name.clone()));
    let expr =
        Expr::from_str(r#"datetime("2024-10-28").toDate()"#).expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::extension(datetime_name));
    let expr =
        Expr::from_str(r#"datetime("2024-10-28").toTime()"#).expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::extension(duration_name.clone()));
    let expr = Expr::from_str(r#"datetime("2024-10-28") < datetime("2024-10-28")"#)
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_boolean());
    let expr = Expr::from_str(r#"datetime("2024-10-28") <= datetime("2024-10-28")"#)
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_boolean());
    let expr = Expr::from_str(r#"datetime("2024-10-28") > datetime("2024-10-28")"#)
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_boolean());
    let expr = Expr::from_str(r#"datetime("2024-10-28") >= datetime("2024-10-28")"#)
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_boolean());
    let expr = Expr::from_str(r#"datetime("2024-10-28") == datetime("2024-10-28")"#)
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_boolean());
    let expr = Expr::from_str(r#"datetime("2024-10-28") != datetime("2024-10-28")"#)
        .expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_boolean());

    let expr = Expr::from_str("duration(\"1h\")").expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::extension(duration_name));
    let expr =
        Expr::from_str(r#"duration("1h").toMilliseconds()"#).expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_long());
    let expr = Expr::from_str(r#"duration("1h").toSeconds()"#).expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_long());
    let expr = Expr::from_str(r#"duration("1h").toMinutes()"#).expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_long());
    let expr = Expr::from_str(r#"duration("1h").toHours()"#).expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_long());
    let expr = Expr::from_str(r#"duration("1h").toDays()"#).expect("parsing should succeed");
    assert_typechecks_empty_schema(&expr, &Type::primitive_long());
}

#[test]
#[cfg(feature = "datetime")]
fn datetime_extension_typecheck_fails() {
    use crate::ast::Name;

    let datetime_name =
        Name::parse_unqualified_name("datetime").expect("should be a valid identifier");
    let duration_name =
        Name::parse_unqualified_name("duration").expect("should be a valid identifier");

    let src = "datetime(3)";
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors =
        assert_typecheck_fails_empty_schema(&expr, &Type::extension(datetime_name.clone()));
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::expected_type(
            get_loc(src, "3"),
            expr_id_placeholder(),
            Type::primitive_string(),
            Type::primitive_long(),
            None,
        )
    );
    let src = "datetime(\"foo\")";
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors =
        assert_typecheck_fails_empty_schema(&expr, &Type::extension(datetime_name.clone()));
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::function_argument_validation(
            get_loc(src, src),
            expr_id_placeholder(),
            "Failed to parse as a datetime value: `\"foo\"`".into(),
        )
    );

    let src = "duration(3)";
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors =
        assert_typecheck_fails_empty_schema(&expr, &Type::extension(duration_name.clone()));
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::expected_type(
            get_loc(src, "3"),
            expr_id_placeholder(),
            Type::primitive_string(),
            Type::primitive_long(),
            None,
        )
    );
    let src = "duration(\"foo\")";
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors =
        assert_typecheck_fails_empty_schema(&expr, &Type::extension(duration_name.clone()));
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::function_argument_validation(
            get_loc(src, src),
            expr_id_placeholder(),
            "Failed to parse as a duration value: `\"foo\"`".into(),
        )
    );

    let src = r#"datetime("2024-10-28").offset(3, 4)"#;
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors =
        assert_typecheck_fails_empty_schema(&expr, &Type::extension(datetime_name.clone()));
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::wrong_number_args(get_loc(src, src), expr_id_placeholder(), 2, 3,)
    );
    let src = r#"datetime("2024-10-28").offset(9)"#;
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors =
        assert_typecheck_fails_empty_schema(&expr, &Type::extension(datetime_name.clone()));
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::expected_type(
            get_loc(src, "9"),
            expr_id_placeholder(),
            Type::extension(duration_name.clone()),
            Type::primitive_long(),
            None,
        )
    );

    let src = r#"datetime("2024-10-29") < duration("1h")"#;
    let expr = Expr::from_str(src).expect("parsing should succeed");
    let errors = assert_typecheck_fails_empty_schema(&expr, &Type::primitive_boolean());
    let type_error = assert_exactly_one_diagnostic(errors);
    assert_eq!(
        type_error,
        ValidationError::expected_type(
            get_loc(src, r#"duration("1h")"#),
            expr_id_placeholder(),
            Type::extension(datetime_name),
            Type::extension(duration_name),
            None,
        )
    );
}
