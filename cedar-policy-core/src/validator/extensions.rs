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

//! This module contains type information for all of the standard Cedar extensions.

use std::collections::{BTreeSet, HashMap};

use crate::{
    ast::{Name, RestrictedExpr, Value},
    evaluator::{EvaluationError, RestrictedEvaluator},
    extensions::{util, Extensions},
};
use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

use crate::validator::extension_schema::{ExtensionFunctionType, ExtensionSchema};

use self::extension_initialization_errors::FuncMultiplyDefinedError;

#[cfg(feature = "ipaddr")]
pub mod ipaddr;

#[cfg(feature = "decimal")]
pub mod decimal;

#[cfg(feature = "datetime")]
pub mod datetime;

pub mod partial_evaluation;

lazy_static::lazy_static! {
    static ref ALL_AVAILABLE_EXTENSION_SCHEMA_OBJECTS : Vec<ExtensionSchema> = vec![
        #[cfg(feature = "ipaddr")]
        ipaddr::extension_schema(),
        #[cfg(feature = "decimal")]
        decimal::extension_schema(),
        #[cfg(feature = "datetime")]
        datetime::extension_schema(),
        #[cfg(feature = "partial-eval")]
        partial_evaluation::extension_schema(),
    ];

    static ref ALL_AVAILABLE_EXTENSION_SCHEMAS : ExtensionSchemas<'static> = ExtensionSchemas::build_all_available();
}

/// Aggregate structure containing information such as function signatures for multiple [`ExtensionSchema`].
/// Ensures that no function name is defined mode than once.
/// Intentionally does not derive `Clone` to avoid clones of the `HashMap`. For the
/// moment, it's easy to pass this around by reference. We could make this
/// `Arc<..>` if that becomes annoying.
#[derive(Debug)]
pub struct ExtensionSchemas<'a> {
    /// Types for all extension functions, collected from every extension used
    /// to construct this object.  Built ahead of time so that we know during
    /// extension function lookup that at most one extension functions exists
    /// for a name.
    function_types: HashMap<&'a Name, &'a ExtensionFunctionType>,
    /// Extension types that support operator overloading
    types_with_operator_overloading: BTreeSet<&'a Name>,
}

impl<'a> ExtensionSchemas<'a> {
    fn build_all_available() -> ExtensionSchemas<'static> {
        // PANIC SAFETY: Builtin extension function definitions never conflict. Also tested by many different test cases.
        #[allow(clippy::expect_used)]
        ExtensionSchemas::specific_extension_schemas(&ALL_AVAILABLE_EXTENSION_SCHEMA_OBJECTS)
            .expect("Default extension schemas should never error on initialization")
    }

    /// Get schemas for all the available extensions.
    pub fn all_available() -> &'static ExtensionSchemas<'static> {
        &ALL_AVAILABLE_EXTENSION_SCHEMAS
    }

    /// Get a new `ExtensionsSchemas` with these specific extensions enabled. No
    /// two extensions may declare functions with the same name.
    pub fn specific_extension_schemas(
        extension_schemas: &'a [ExtensionSchema],
    ) -> Result<ExtensionSchemas<'a>, ExtensionInitializationError> {
        // Build function type map, ensuring that no functions share the same name.
        let function_types = util::collect_no_duplicates(
            extension_schemas
                .iter()
                .flat_map(|ext| ext.function_types())
                .map(|f| (f.name(), f)),
        )
        .map_err(|name| FuncMultiplyDefinedError { name: name.clone() })?;

        // We already ensure that names of extension types do not collide, at the language level
        let types_with_operator_overloading = extension_schemas
            .iter()
            .flat_map(|f| f.types_with_operator_overloading())
            .collect();

        Ok(Self {
            function_types,
            types_with_operator_overloading,
        })
    }

    /// Get the [`ExtensionFunctionType`] for a function with this [`Name`].
    /// Return `None` if no such function exists.
    pub fn func_type(&self, name: &Name) -> Option<&ExtensionFunctionType> {
        self.function_types.get(name).copied()
    }

    /// Query if `ext_ty_name` supports operator overloading
    pub fn has_type_with_operator_overloading(&self, ext_ty_name: &Name) -> bool {
        self.types_with_operator_overloading.contains(ext_ty_name)
    }

    /// Get all extension types that support operator overloading
    pub fn types_with_operator_overloading(&self) -> impl Iterator<Item = &Name> + '_ {
        self.types_with_operator_overloading.iter().copied()
    }
}

/// Evaluates ane extension function on a single string literal argument. Used
/// to validate arguments to extension constructor functions.
fn eval_extension_constructor(
    constructor_name: Name,
    lit_str_arg: SmolStr,
) -> Result<Value, EvaluationError> {
    let exts = Extensions::all_available();
    let evaluator = RestrictedEvaluator::new(exts);
    let constructor_call_expr =
        RestrictedExpr::call_extension_fn(constructor_name, [RestrictedExpr::val(lit_str_arg)]);
    evaluator.interpret(constructor_call_expr.as_borrowed())
}

/// Errors occurring while initializing extensions. These are internal errors, so
/// this enum should not become part of the public API unless we publicly expose
/// user-defined extension functions.
#[derive(Diagnostic, Debug, Error)]
pub enum ExtensionInitializationError {
    /// An extension function was defined by multiple extensions.
    #[error(transparent)]
    #[diagnostic(transparent)]
    FuncMultiplyDefined(#[from] extension_initialization_errors::FuncMultiplyDefinedError),
}

/// Error subtypes for [`ExtensionInitializationError`]
mod extension_initialization_errors {
    use crate::ast::Name;
    use miette::Diagnostic;
    use thiserror::Error;

    /// An extension function was defined by multiple extensions.
    #[derive(Diagnostic, Debug, Error)]
    #[error("extension function `{name}` is defined multiple times")]
    pub struct FuncMultiplyDefinedError {
        /// Name of the function that was multiply defined
        pub(crate) name: Name,
    }
}
