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
//! Note on panic safety
//! If any of the panics in this file are triggered, that means that this file has become
//! out-of-date with the decimal extension definition in CedarCore.
//! This is tested by the `extension_schema_correctness()` test

use crate::extension_schema::{ArgumentCheckFn, ExtensionFunctionType, ExtensionSchema};
use crate::types::{self, Type};
use cedar_policy_core::ast::{Expr, ExprKind, Literal, RestrictedExpr};
use cedar_policy_core::evaluator::RestrictedEvaluator;
use cedar_policy_core::extensions::{ipaddr, Extensions};
use std::str::FromStr;

/// Note on safety:
/// This module depends on the Cedar parser only constructing AST with valid extension calls
/// If any of the panics in this file are triggered, that means that this file has become
/// out-of-date with the ipaddr extension definition in CedarCore.

// PANIC SAFETY see `Note on safety` above
#[allow(clippy::panic)]
fn get_argument_types(fname: &str, ipaddr_ty: &Type) -> Vec<types::Type> {
    match fname {
        "ip" => vec![Type::primitive_string()],
        "isIpv4" | "isIpv6" | "isLoopback" | "isMulticast" => vec![ipaddr_ty.clone()],
        "isInRange" => vec![ipaddr_ty.clone(), ipaddr_ty.clone()],
        _ => panic!("unexpected ipaddr extension function name: {fname}"),
    }
}

// PANIC SAFETY see `Note on safety` above
#[allow(clippy::panic)]
fn get_return_type(fname: &str, ipaddr_ty: &Type) -> Type {
    match fname {
        "ip" => ipaddr_ty.clone(),
        "isIpv4" | "isIpv6" | "isLoopback" | "isMulticast" | "isInRange" => {
            Type::primitive_boolean()
        }
        _ => panic!("unexpected ipaddr extension function name: {fname}"),
    }
}

// PANIC SAFETY see `Note on safety` above
#[allow(clippy::panic)]
fn get_argument_check(fname: &str) -> Option<ArgumentCheckFn> {
    match fname {
        "ip" => Some(Box::new(validate_ip_string)),
        "isIpv4" | "isIpv6" | "isLoopback" | "isMulticast" | "isInRange" => None,
        _ => panic!("unexpected ipaddr extension function name: {fname}"),
    }
}

/// Construct the extension schema
pub fn extension_schema() -> ExtensionSchema {
    let ipaddr_ext = ipaddr::extension();
    let ipaddr_ty = Type::extension(ipaddr_ext.name().clone());

    let fun_tys: Vec<ExtensionFunctionType> = ipaddr_ext
        .funcs()
        .map(|f| {
            let fname = f.name();
            let fstring = fname.to_string();
            let return_type = get_return_type(&fstring, &ipaddr_ty);
            debug_assert!(f
                .return_type()
                .map(|ty| return_type.is_consistent_with(ty))
                .unwrap_or_else(|| return_type == Type::Never));
            ExtensionFunctionType::new(
                fname.clone(),
                get_argument_types(&fstring, &ipaddr_ty),
                return_type,
                get_argument_check(&fstring),
            )
        })
        .collect();
    ExtensionSchema::new(ipaddr_ext.name().clone(), fun_tys)
}

/// Extra validation step for the `ip` function.
/// Note that `exprs` will have already been checked to contain the correct number of arguments.
fn validate_ip_string(exprs: &[Expr]) -> Result<(), String> {
    match exprs.first() {
        Some(arg) if matches!(arg.expr_kind(), ExprKind::Lit(Literal::String(_))) => {
            let exts = Extensions::all_available();
            let evaluator = RestrictedEvaluator::new(&exts);

            match RestrictedExpr::from_str(&format!("ip({arg})")) {
                Ok(expr) => match evaluator.interpret(expr.as_borrowed()) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(format!("Failed to parse as IP address: `{arg}`")),
                },
                Err(_) => Err(format!("Failed to parse as IP address: `{arg}`")),
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
