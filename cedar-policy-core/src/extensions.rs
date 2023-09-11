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

//! This module contains all of the standard Cedar extensions.

#[cfg(feature = "ipaddr")]
pub mod ipaddr;

#[cfg(feature = "decimal")]
pub mod decimal;
pub mod partial_evaluation;

use crate::ast::{Extension, ExtensionFunction, Name};
use crate::entities::SchemaType;
use thiserror::Error;

lazy_static::lazy_static! {
    static ref ALL_AVAILABLE_EXTENSIONS: Vec<Extension> = vec![
        #[cfg(feature = "ipaddr")]
        ipaddr::extension(),
        #[cfg(feature = "decimal")]
        decimal::extension(),
        partial_evaluation::extension(),
    ];
}

/// Holds data on all the Extensions which are active for a given evaluation.
///
/// Clone is cheap for this type.
#[derive(Debug, Clone)]
pub struct Extensions<'a> {
    /// the actual extensions
    extensions: &'a [Extension],
}

impl Extensions<'static> {
    /// Get a new `Extensions` containing data on all the available extensions.
    pub fn all_available() -> Extensions<'static> {
        Extensions {
            extensions: &ALL_AVAILABLE_EXTENSIONS,
        }
    }

    /// Get a new `Extensions` with no extensions enabled.
    pub fn none() -> Extensions<'static> {
        Extensions { extensions: &[] }
    }
}

impl<'a> Extensions<'a> {
    /// Get a new `Extensions` with these specific extensions enabled.
    pub fn specific_extensions(extensions: &'a [Extension]) -> Extensions<'a> {
        Extensions { extensions }
    }

    /// Get the names of all active extensions.
    pub fn ext_names(&self) -> impl Iterator<Item = &Name> {
        self.extensions.iter().map(|ext| ext.name())
    }

    /// Get the extension function with the given name, from these extensions.
    ///
    /// Returns an error if the function is not defined by any extension, or if
    /// it is defined multiple times.
    pub fn func(&self, name: &Name) -> Result<&ExtensionFunction> {
        // NOTE: in the future, we could build a single HashMap of function
        // name to ExtensionFunction, combining all extension functions
        // into one map, to make this lookup faster.
        let extension_funcs: Vec<&ExtensionFunction> = self
            .extensions
            .iter()
            .filter_map(|ext| ext.get_func(name))
            .collect();
        match extension_funcs.get(0) {
            None => Err(ExtensionFunctionLookupError::FuncDoesNotExist { name: name.clone() }),
            Some(first) if extension_funcs.len() == 1 => Ok(first),
            _ => Err(ExtensionFunctionLookupError::FuncMultiplyDefined {
                name: name.clone(),
                num_defs: extension_funcs.len(),
            }),
        }
    }

    /// Iterate over all extension functions defined by all of these extensions.
    ///
    /// No guarantee that this list won't have duplicates or repeated names.
    pub(crate) fn all_funcs(&self) -> impl Iterator<Item = &'a ExtensionFunction> {
        self.extensions.iter().flat_map(|ext| ext.funcs())
    }

    /// Lookup a single-argument constructor by its return type and argument type.
    /// This will ignore polymorphic functions (that accept multiple argument types).
    ///
    /// `Ok(None)` means no constructor has that signature.
    /// `Err` is returned in the case that multiple constructors have that signature.
    pub(crate) fn lookup_single_arg_constructor(
        &self,
        return_type: &SchemaType,
        arg_type: &SchemaType,
    ) -> Result<Option<&ExtensionFunction>> {
        let matches = self
            .all_funcs()
            .filter(|f| {
                f.is_constructor()
                    && f.return_type() == Some(return_type)
                    && f.arg_types().get(0).map(Option::as_ref) == Some(Some(arg_type))
            })
            .collect::<Vec<_>>();
        match matches.get(0) {
            None => Ok(None),
            Some(first) if matches.len() == 1 => Ok(Some(first)),
            _ => Err(
                ExtensionFunctionLookupError::MultipleConstructorsSameSignature {
                    return_type: Box::new(return_type.clone()),
                    arg_type: Box::new(arg_type.clone()),
                },
            ),
        }
    }
}

/// Errors thrown when looking up an extension function in [`Extensions`].
#[derive(Debug, PartialEq, Eq, Clone, Error)]
pub enum ExtensionFunctionLookupError {
    /// Tried to call a function that doesn't exist
    #[error("extension function does not exist: {name}")]
    FuncDoesNotExist {
        /// Name of the function that doesn't exist
        name: Name,
    },

    /// Attempted to typecheck an expression that had no type
    #[error("extension function has no type: {name}")]
    HasNoType {
        /// Name of the function that returns no type
        name: Name,
    },

    /// Tried to call a function but it was defined multiple times (e.g., by
    /// multiple different extensions)
    #[error("function is defined {num_defs} times: {name}")]
    FuncMultiplyDefined {
        /// Name of the function that is multiply defined
        name: Name,
        /// How many times that function is defined
        num_defs: usize,
    },

    /// Two extension constructors (in the same or different extensions) had
    /// exactly the same type signature.  This is currently not allowed.
    #[error(
        "multiple extension constructors with the same type signature {arg_type} -> {return_type}"
    )]
    MultipleConstructorsSameSignature {
        /// return type of the shared constructor signature
        return_type: Box<SchemaType>,
        /// argument type of the shared constructor signature
        arg_type: Box<SchemaType>,
    },
}

/// Type alias for convenience
pub type Result<T> = std::result::Result<T, ExtensionFunctionLookupError>;

#[cfg(test)]
pub mod test {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn no_common_extension_function_names() {
        // Our expr display must search for callstyle given a name, so
        // no names can be used for both callstyles

        // Test that names are all unique for ease of use.
        // This overconstrains our current requirements, but shouldn't change
        // until we identify a strong need.
        let all_names: Vec<_> = Extensions::all_available()
            .extensions
            .iter()
            .flat_map(|e| e.funcs().map(|f| f.name().clone()))
            .collect();
        let dedup_names: HashSet<_> = all_names.iter().collect();
        assert_eq!(all_names.len(), dedup_names.len());
    }
}
