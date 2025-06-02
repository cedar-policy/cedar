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
use crate::extensions::ipaddr;
use crate::validator::extension_schema::{ArgumentCheckFn, ExtensionFunctionType, ExtensionSchema};
use crate::validator::types::{self, Type};
use itertools::Itertools;

use super::eval_extension_constructor;

// Note on safety:
// This module depends on the Cedar parser only constructing AST with valid extension calls
// If any of the panics in this file are triggered, that means that this file has become
// out-of-date with the ipaddr extension definition in Core.

// PANIC SAFETY see `Note on safety` above
#[allow(clippy::panic)]
fn get_argument_types(fname: &Name, ipaddr_ty: &Type) -> Vec<types::Type> {
    if !fname.as_ref().is_unqualified() {
        panic!("unexpected ipaddr extension function name: {fname}")
    }
    match fname.basename().as_ref() {
        "ip" => vec![Type::primitive_string()],
        "isIpv4" | "isIpv6" | "isLoopback" | "isMulticast" => vec![ipaddr_ty.clone()],
        "isInRange" => vec![ipaddr_ty.clone(), ipaddr_ty.clone()],
        _ => panic!("unexpected ipaddr extension function name: {fname}"),
    }
}

// PANIC SAFETY see `Note on safety` above
#[allow(clippy::panic)]
fn get_return_type(fname: &Name, ipaddr_ty: &Type) -> Type {
    if !fname.as_ref().is_unqualified() {
        panic!("unexpected ipaddr extension function name: {fname}")
    }
    match fname.basename().as_ref() {
        "ip" => ipaddr_ty.clone(),
        "isIpv4" | "isIpv6" | "isLoopback" | "isMulticast" | "isInRange" => {
            Type::primitive_boolean()
        }
        _ => panic!("unexpected ipaddr extension function name: {fname}"),
    }
}

// PANIC SAFETY see `Note on safety` above
#[allow(clippy::panic)]
fn get_argument_check(fname: &Name) -> Option<ArgumentCheckFn> {
    if !fname.as_ref().is_unqualified() {
        panic!("unexpected ipaddr extension function name: {fname}")
    }
    match fname.basename().as_ref() {
        "ip" => {
            let fname = fname.clone();
            Some(Box::new(move |args| {
                validate_ip_string(fname.clone(), args)
            }))
        }
        "isIpv4" | "isIpv6" | "isLoopback" | "isMulticast" | "isInRange" => None,
        _ => panic!("unexpected ipaddr extension function name: {fname}"),
    }
}

/// Construct the extension schema
pub fn extension_schema() -> ExtensionSchema {
    let ipaddr_ext = ipaddr::extension();
    let ipaddr_ty = Type::extension(ipaddr_ext.name().clone());

    let fun_tys = ipaddr_ext.funcs().map(|f| {
        let return_type = get_return_type(f.name(), &ipaddr_ty);
        debug_assert!(f
            .return_type()
            .map(|ty| return_type.is_consistent_with(ty))
            .unwrap_or_else(|| return_type == Type::Never));
        ExtensionFunctionType::new(
            f.name().clone(),
            get_argument_types(f.name(), &ipaddr_ty),
            return_type,
            get_argument_check(f.name()),
        )
    });
    ExtensionSchema::new(ipaddr_ext.name().clone(), fun_tys, std::iter::empty())
}

/// Extra validation step for the `ip` function.
/// Note we already checked that `exprs` contains correct number of arguments,
/// these arguments have the correct types, and that they are all literals.
fn validate_ip_string(ip_constructor_name: Name, exprs: &[Expr]) -> Result<(), String> {
    match exprs.iter().exactly_one().map(|a| a.expr_kind()) {
        Ok(ExprKind::Lit(lit_arg @ Literal::String(s))) => {
            eval_extension_constructor(ip_constructor_name, s.clone())
                .map(|_| ())
                .map_err(|_| format!("Failed to parse as IP address: `{lit_arg}`"))
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
