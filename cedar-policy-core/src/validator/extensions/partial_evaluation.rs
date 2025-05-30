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

#![cfg(feature = "partial-eval")]
use crate::extensions::partial_evaluation;
use crate::validator::extension_schema::{ExtensionFunctionType, ExtensionSchema};
use crate::validator::types::{self, Type};

// Note on safety:
// This module depends on the Cedar parser only constructing AST with valid extension calls
// If any of the panics in this file are triggered, that means that this file has become
// out-of-date with the decimal extension definition in Core.

// PANIC SAFETY see `Note on safety` above
#[allow(clippy::panic)]
fn get_argument_types(fname: &str) -> Vec<types::Type> {
    match fname {
        "error" => vec![Type::primitive_string()],
        "unknown" => vec![Type::primitive_string()],
        _ => panic!("unexpected decimal extension function name: {fname}"),
    }
}

// PANIC SAFETY see `Note on safety` above
#[allow(clippy::panic)]
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

    let fun_tys = pe_ext.funcs().map(|f| {
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
    });
    ExtensionSchema::new(pe_ext.name().clone(), fun_tys, std::iter::empty())
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
