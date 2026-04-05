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
//! Note on panic safety
//! If any of the panics in this file are triggered, that means that this file has become
//! out-of-date with the decimal extension definition in Core.
//! This is tested by the `extension_schema_correctness()` test

use crate::ast::{Expr, ExprKind, Literal, Name};
use crate::extensions::decimal;
use crate::validator::extension_schema::{
    ArgumentCheckFn, ArgumentValidationError, ExtensionFunctionType, ExtensionSchema,
};
use crate::validator::types::{self, Type};
use itertools::Itertools;
use miette::Diagnostic;

use super::eval_extension_constructor;

// Note on safety:
// This module depends on the Cedar parser only constructing AST with valid extension calls
// If any of the panics in this file are triggered, that means that this file has become
// out-of-date with the decimal extension definition in Core.

const VALID_DECIMAL_HELP: &str = "valid decimal strings look like `12.34`: digits are required on both sides of `.`, up to 4 fractional digits are allowed, and the value must be in range -922337203685477.5808 to 922337203685477.5807";

#[expect(clippy::panic, reason = "see `Note on safety` above")]
fn get_argument_types(fname: &Name, decimal_ty: &Type) -> Vec<types::Type> {
    if !fname.as_ref().is_unqualified() {
        panic!("unexpected decimal extension function name: {fname}")
    }
    match fname.basename().as_ref() {
        "decimal" => vec![Type::primitive_string()],
        "lessThan" | "lessThanOrEqual" | "greaterThan" | "greaterThanOrEqual" => {
            vec![decimal_ty.clone(), decimal_ty.clone()]
        }
        _ => panic!("unexpected decimal extension function name: {fname}"),
    }
}

#[expect(clippy::panic, reason = "see `Note on safety` above")]
fn get_return_type(fname: &Name, decimal_ty: &Type) -> Type {
    if !fname.as_ref().is_unqualified() {
        panic!("unexpected decimal extension function name: {fname}")
    }
    match fname.basename().as_ref() {
        "decimal" => decimal_ty.clone(),
        "lessThan" | "lessThanOrEqual" | "greaterThan" | "greaterThanOrEqual" => {
            Type::primitive_boolean()
        }
        _ => panic!("unexpected decimal extension function name: {fname}"),
    }
}

#[expect(clippy::panic, reason = "see `Note on safety` above")]
fn get_argument_check(fname: &Name) -> Option<ArgumentCheckFn> {
    if !fname.as_ref().is_unqualified() {
        panic!("unexpected decimal extension function name: {fname}")
    }
    match fname.basename().as_ref() {
        "decimal" => {
            let fname = fname.clone();
            Some(Box::new(move |args| {
                validate_decimal_string(fname.clone(), args)
            }))
        }
        "lessThan" | "lessThanOrEqual" | "greaterThan" | "greaterThanOrEqual" => None,
        _ => panic!("unexpected decimal extension function name: {fname}"),
    }
}

/// Construct the extension schema
pub fn extension_schema() -> ExtensionSchema {
    let decimal_ext = decimal::extension();
    let decimal_ty = Type::extension(decimal_ext.name().clone());

    let fun_tys = decimal_ext.funcs().map(|f| {
        let return_type = get_return_type(f.name(), &decimal_ty);
        debug_assert!(f
            .return_type()
            .map(|ty| return_type.is_consistent_with(ty))
            .unwrap_or_else(|| return_type == Type::Never));
        ExtensionFunctionType::new(
            f.name().clone(),
            get_argument_types(f.name(), &decimal_ty),
            return_type,
            get_argument_check(f.name()),
            false,
        )
    });
    ExtensionSchema::new(decimal_ext.name().clone(), fun_tys, std::iter::empty())
}

/// Extra validation step for the `decimal` function.
/// Note we already checked that `exprs` contains correct number of arguments,
/// these arguments have the correct types, and that they are all literals.
fn validate_decimal_string(
    decimal_constructor_name: Name,
    exprs: &[Expr],
) -> Result<(), ArgumentValidationError> {
    match exprs.iter().exactly_one().map(|a| a.expr_kind()) {
        Ok(ExprKind::Lit(lit_arg @ Literal::String(s))) => {
            match eval_extension_constructor(decimal_constructor_name, s.clone()) {
                Ok(_) => Ok(()),
                Err(err) => Err(ArgumentValidationError::new(
                    format!("failed to parse as a decimal value: `{lit_arg}`"),
                    Some(
                        err.help()
                            .map(|h| h.to_string())
                            .unwrap_or_else(|| VALID_DECIMAL_HELP.to_string()),
                    ),
                )),
            }
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Ensures that `extension_schema()` does not panic
    #[test]
    fn extension_schema_correctness() {
        let _ = extension_schema();
    }
}
