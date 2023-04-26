use crate::extension_schema::{ArgumentCheckFn, ExtensionFunctionType, ExtensionSchema};
use crate::types::{self, Type};
use cedar_policy_core::ast::{Expr, ExprKind, Literal};
use cedar_policy_core::evaluator::RestrictedEvaluator;
use cedar_policy_core::extensions::{ipaddr, Extensions};
use cedar_policy_core::parser::parse_restrictedexpr;

/// If any of the panics in this file are triggered, that means that this file has become
/// out-of-date with the ipaddr extension definition in CedarCore.

fn get_argument_types(fname: &str, ipaddr_ty: &Type) -> Vec<types::Type> {
    match fname {
        "ip" => vec![Type::primitive_string()],
        "isIpv4" | "isIpv6" | "isLoopback" | "isMulticast" => vec![ipaddr_ty.clone()],
        "isInRange" => vec![ipaddr_ty.clone(), ipaddr_ty.clone()],
        _ => panic!("unexpected ipaddr extension function name: {fname}"),
    }
}

fn get_return_type(fname: &str, ipaddr_ty: &Type) -> Type {
    match fname {
        "ip" => ipaddr_ty.clone(),
        "isIpv4" | "isIpv6" | "isLoopback" | "isMulticast" | "isInRange" => {
            Type::primitive_boolean()
        }
        _ => panic!("unexpected ipaddr extension function name: {fname}"),
    }
}

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
    match exprs.get(0) {
        Some(arg) if matches!(arg.expr_kind(), ExprKind::Lit(Literal::String(_))) => {
            let exts = Extensions::all_available();
            let evaluator = RestrictedEvaluator::new(&exts);
            let expr = parse_restrictedexpr(&format!("ip({arg})")).expect("parsing error");
            match evaluator.interpret(expr.as_borrowed()) {
                Ok(_) => Ok(()),
                Err(_) => Err(format!("Failed to parse as IP address: {arg}")),
            }
        }
        _ => Ok(()),
    }
}
