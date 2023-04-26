use crate::extension_schema::{ExtensionFunctionType, ExtensionSchema};
use crate::types::{self, Type};
use cedar_policy_core::extensions::partial_evaluation;

/// If any of the panics in this file are triggered, that means that this file has become
/// out-of-date with the decimal extension definition in CedarCore.

fn get_argument_types(fname: &str) -> Vec<types::Type> {
    match fname {
        "error" => vec![Type::primitive_string()],
        "unknown" => vec![Type::primitive_string()],
        _ => panic!("unexpected decimal extension function name: {fname}"),
    }
}

fn get_return_type(fname: &str) -> Type {
    match fname {
        "error" => Type::Never,
        "unknown" => Type::Never,
        _ => panic!("unexpected decimal extension function name: {fname}"),
    }
}

/// Construct the extension schema
pub fn extension_schema() -> ExtensionSchema {
    let pe_ext = partial_evaluation::extension();

    let fun_tys: Vec<ExtensionFunctionType> = pe_ext
        .funcs()
        .map(|f| {
            let fname = f.name();
            let fstring = fname.to_string();
            let return_type = get_return_type(&fstring);
            debug_assert!(f
                .return_type()
                .map(|ty| return_type.is_consistent_with(ty))
                .unwrap_or_else(|| return_type == Type::Never));
            ExtensionFunctionType::new(
                fname.clone(),
                get_argument_types(&fstring),
                return_type,
                None,
            )
        })
        .collect();
    ExtensionSchema::new(pe_ext.name().clone(), fun_tys)
}
