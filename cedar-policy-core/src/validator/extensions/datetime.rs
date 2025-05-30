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
use crate::extensions::datetime;
use crate::validator::extension_schema::{ArgumentCheckFn, ExtensionFunctionType, ExtensionSchema};
use crate::validator::types::{self, Type};
use itertools::Itertools;

use super::eval_extension_constructor;

// Note on safety:
// This module depends on the Cedar parser only constructing AST with valid extension calls
// If any of the panics in this file are triggered, that means that this file has become
// out-of-date with the datetime extension definition in Core.

// PANIC SAFETY see `Note on safety` above
#[allow(clippy::panic)]
fn get_argument_types(fname: &Name, datetime_ty: &Type, duration_ty: &Type) -> Vec<types::Type> {
    if !fname.as_ref().is_unqualified() {
        panic!("unexpected datetime extension function name: {fname}")
    }
    match fname.basename().as_ref() {
        "datetime" | "duration" => vec![Type::primitive_string()],
        "offset" => vec![datetime_ty.clone(), duration_ty.clone()],
        "durationSince" => vec![datetime_ty.clone(), datetime_ty.clone()],
        "toDate" => vec![datetime_ty.clone()],
        "toTime" => vec![datetime_ty.clone()],
        "toMilliseconds" | "toSeconds" | "toMinutes" | "toHours" | "toDays" => {
            vec![duration_ty.clone()]
        }
        _ => panic!("unexpected datetime extension function name: {fname}"),
    }
}

// PANIC SAFETY see `Note on safety` above
#[allow(clippy::panic)]
fn get_return_type(fname: &Name, datetime_ty: &Type, duration_ty: &Type) -> Type {
    if !fname.as_ref().is_unqualified() {
        panic!("unexpected datetime extension function name: {fname}")
    }
    match fname.basename().as_ref() {
        "datetime" | "offset" | "toDate" => datetime_ty.clone(),
        "duration" | "durationSince" | "toTime" => duration_ty.clone(),
        "toMilliseconds" | "toSeconds" | "toMinutes" | "toHours" | "toDays" => {
            Type::primitive_long()
        }
        _ => panic!("unexpected datetime extension function name: {fname}"),
    }
}

// PANIC SAFETY see `Note on safety` above
#[allow(clippy::panic)]
fn get_argument_check(fname: &Name) -> Option<ArgumentCheckFn> {
    if !fname.as_ref().is_unqualified() {
        panic!("unexpected datetime extension function name: {fname}")
    }
    match fname.basename().as_ref() {
        "datetime" => {
            let fname = fname.clone();
            Some(Box::new(move |args| {
                validate_datetime_string(fname.clone(), args)
            }))
        }
        "duration" => {
            let fname = fname.clone();
            Some(Box::new(move |args| {
                validate_duration_string(fname.clone(), args)
            }))
        }
        "offset" | "durationSince" | "toDate" | "toTime" | "toMilliseconds" | "toSeconds"
        | "toMinutes" | "toHours" | "toDays" => None,
        _ => panic!("unexpected datetime extension function name: {fname}"),
    }
}

/// Construct the extension schema
pub fn extension_schema() -> ExtensionSchema {
    let datetime_ext = datetime::extension();
    let datetime_ty = Type::extension(datetime_ext.name().clone());
    //PANIC SAFETY: `duration` is a valid name
    #[allow(clippy::unwrap_used)]
    let duration_ty_name: Name = "duration".parse().unwrap();
    let duration_ty = Type::extension(duration_ty_name.clone());

    let fun_tys = datetime_ext.funcs().map(|f| {
        let return_type = get_return_type(f.name(), &datetime_ty, &duration_ty);
        debug_assert!(f
            .return_type()
            .map(|ty| return_type.is_consistent_with(ty))
            .unwrap_or_else(|| return_type == Type::Never));
        ExtensionFunctionType::new(
            f.name().clone(),
            get_argument_types(f.name(), &datetime_ty, &duration_ty),
            return_type,
            get_argument_check(f.name()),
        )
    });
    ExtensionSchema::new(
        datetime_ext.name().clone(),
        fun_tys,
        [datetime_ext.name().clone(), duration_ty_name],
    )
}

/// Extra validation step for the `datetime` function.
/// Note we already checked that `exprs` contains correct number of arguments,
/// these arguments have the correct types, and that they are all literals.
fn validate_datetime_string(datetime_constructor_name: Name, exprs: &[Expr]) -> Result<(), String> {
    match exprs.iter().exactly_one().map(|a| a.expr_kind()) {
        Ok(ExprKind::Lit(lit_arg @ Literal::String(s))) => {
            eval_extension_constructor(datetime_constructor_name, s.clone())
                .map(|_| ())
                .map_err(|_| format!("Failed to parse as a datetime value: `{lit_arg}`"))
        }
        _ => Ok(()),
    }
}

/// Extra validation step for the `duration` function.
/// Note we already checked that `exprs` contains correct number of arguments,
/// these arguments have the correct types, and that they are all literals.
fn validate_duration_string(duration_constructor_name: Name, exprs: &[Expr]) -> Result<(), String> {
    match exprs.iter().exactly_one().map(|a| a.expr_kind()) {
        Ok(ExprKind::Lit(lit_arg @ Literal::String(s))) => {
            eval_extension_constructor(duration_constructor_name, s.clone())
                .map(|_| ())
                .map_err(|_| format!("Failed to parse as a duration value: `{lit_arg}`"))
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
