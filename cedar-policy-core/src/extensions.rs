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

//! This module contains all of the standard Cedar extensions.

#[cfg(feature = "ipaddr")]
pub mod ipaddr;

#[cfg(feature = "decimal")]
pub mod decimal;
pub mod partial_evaluation;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;

use crate::ast::{Extension, ExtensionFunction, Name};
use crate::entities::SchemaType;
use miette::Diagnostic;
use thiserror::Error;

use self::extension_function_lookup_errors::FuncDoesNotExistError;
use self::extension_initialization_errors::{
    FuncMultiplyDefinedError, MultipleConstructorsSameSignatureError,
};

lazy_static::lazy_static! {
    static ref ALL_AVAILABLE_EXTENSION_OBJECTS: Vec<Extension> = vec![
        #[cfg(feature = "ipaddr")]
        ipaddr::extension(),
        #[cfg(feature = "decimal")]
        decimal::extension(),
        partial_evaluation::extension(),
    ];

    static ref ALL_AVAILABLE_EXTENSIONS : Extensions<'static> = Extensions::build_all_available();

    static ref EXTENSIONS_NONE : Extensions<'static> = Extensions {
        extensions: &[],
        functions: Arc::new(HashMap::new()),
        single_arg_constructors: Arc::new(HashMap::new()),
    };
}

/// Holds data on all the Extensions which are active for a given evaluation.
///
/// Clone is cheap for this type.
#[derive(Clone, Debug)]
pub struct Extensions<'a> {
    /// the actual extensions
    extensions: &'a [Extension],
    /// All extension functions, collected from every extension used to
    /// construct the this object.  Built ahead of time so that we can know
    /// during extension function lookup that at most one extension functions
    /// exists for a name. This should also make the lookup more efficient.
    functions: Arc<HashMap<&'a Name, &'a ExtensionFunction>>,
    /// All single argument extension function constructors, index by the
    /// signature (a tuple `(arg_type, return type)`). Built ahead of time so
    /// that we know each constructor has a unique type signature.
    single_arg_constructors: Arc<HashMap<(&'a SchemaType, &'a SchemaType), &'a ExtensionFunction>>,
}

impl Extensions<'static> {
    /// Get a new `Extensions` containing data on all the available extensions.
    fn build_all_available() -> Extensions<'static> {
        // PANIC SAFETY: This functions is early in on in many different tests, so any panic will be noticed immediately.
        #[allow(clippy::expect_used)]
        Self::specific_extensions(&ALL_AVAILABLE_EXTENSION_OBJECTS)
            .expect("Default extensions should never error on initialization")
    }

    /// An [`Extensions`] object with static lifetime contain all available extensions.
    pub fn all_available() -> Extensions<'static> {
        ALL_AVAILABLE_EXTENSIONS.clone()
    }

    /// Get a new `Extensions` with no extensions enabled.
    pub fn none() -> Extensions<'static> {
        EXTENSIONS_NONE.clone()
    }
}

impl<'a> Extensions<'a> {
    fn collect_no_duplicates<K, V>(
        i: impl Iterator<Item = (K, V)>,
    ) -> std::result::Result<HashMap<K, V>, K>
    where
        K: Clone + std::hash::Hash + Eq,
    {
        let mut map = HashMap::with_capacity(i.size_hint().0);
        for (k, v) in i {
            match map.entry(k) {
                Entry::Occupied(occupied) => {
                    return Err(occupied.key().clone());
                }
                Entry::Vacant(vacant) => {
                    vacant.insert(v);
                }
            }
        }
        Ok(map)
    }

    /// Get a new `Extensions` with these specific extensions enabled.
    pub fn specific_extensions(
        extensions: &'a [Extension],
    ) -> std::result::Result<Extensions<'a>, ExtensionInitializationError> {
        let functions = Self::collect_no_duplicates(
            extensions
                .iter()
                .flat_map(|e| e.funcs())
                .map(|f| (f.name(), f)),
        )
        .map_err(|name| FuncMultiplyDefinedError { name: name.clone() })?;

        let single_arg_constructors = Self::collect_no_duplicates(
            extensions.iter().flat_map(|e| e.funcs()).filter_map(|f| {
                if f.is_constructor() {
                    if let (Some(Some(arg_ty)), Some(ret_ty)) =
                        (f.arg_types().first(), f.return_type())
                    {
                        return Some(((arg_ty, ret_ty), f));
                    }
                }
                None
            }),
        )
        .map_err(
            |(arg_type, return_type)| MultipleConstructorsSameSignatureError {
                return_type: Box::new(return_type.clone()),
                arg_type: Box::new(arg_type.clone()),
            },
        )?;

        Ok(Extensions {
            extensions,
            functions: Arc::new(functions),
            single_arg_constructors: Arc::new(single_arg_constructors),
        })
    }

    /// Get the names of all active extensions.
    pub fn ext_names(&self) -> impl Iterator<Item = &Name> {
        self.extensions.iter().map(|ext| ext.name())
    }

    /// Get all extension type names declared by active extensions.
    ///
    /// (More specifically, all extension type names such that any function in
    /// an active extension could produce a value of that extension type.)
    pub fn ext_types(&self) -> impl Iterator<Item = &Name> {
        self.extensions.iter().flat_map(|ext| ext.ext_types())
    }

    /// Get the extension function with the given name, from these extensions.
    ///
    /// Returns an error if the function is not defined by any extension
    pub fn func(
        &self,
        name: &Name,
    ) -> std::result::Result<&ExtensionFunction, FuncDoesNotExistError> {
        match self.functions.get(name) {
            None => Err(FuncDoesNotExistError {
                name: name.clone(),
                source_loc: None,
            }),
            Some(func) => Ok(func),
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
    ) -> Option<&ExtensionFunction> {
        self.single_arg_constructors
            .get(&(arg_type, return_type))
            .map(|e| *e)
    }
}

/// Errors occurring while initializing extensions. There are internal errors, so
/// this enum should not become part of the public API unless we publicly expose
/// user-defined extensions function.
#[derive(Diagnostic, Debug, PartialEq, Eq, Clone, Error)]
pub enum ExtensionInitializationError {
    /// Tried to construct an extensions struct where an extension function was
    /// defined by multiple extensions.
    #[error(transparent)]
    #[diagnostic(transparent)]
    FuncMultiplyDefined(#[from] extension_initialization_errors::FuncMultiplyDefinedError),

    /// Two extension constructors (in the same or different extensions) had
    /// exactly the same type signature.  This is currently not allowed.
    #[error(transparent)]
    #[diagnostic(transparent)]
    MultipleConstructorsSameSignature(
        #[from] extension_initialization_errors::MultipleConstructorsSameSignatureError,
    ),
}

mod extension_initialization_errors {
    use crate::{ast::Name, entities::SchemaType};
    use miette::Diagnostic;
    use thiserror::Error;

    /// Tried to construct an extensions struct where an extension function was
    /// defined by multiple extensions.
    #[derive(Diagnostic, Debug, PartialEq, Eq, Clone, Error)]
    #[error("extension function `{name}` is defined multiple times")]
    pub struct FuncMultiplyDefinedError {
        /// Name of the function that was multiply defined
        pub(crate) name: Name,
    }

    /// Two extension constructors (in the same or different extensions) had
    /// exactly the same type signature.  This is currently not allowed.
    #[derive(Diagnostic, Debug, PartialEq, Eq, Clone, Error)]
    #[error(
        "multiple extension constructors have the same type signature {arg_type} -> {return_type}"
    )]
    pub struct MultipleConstructorsSameSignatureError {
        /// return type of the shared constructor signature
        pub(crate) return_type: Box<SchemaType>,
        /// argument type of the shared constructor signature
        pub(crate) arg_type: Box<SchemaType>,
    }
}

/// Errors thrown when looking up an extension function in [`Extensions`].
//
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, PartialEq, Eq, Clone, Diagnostic, Error)]
pub enum ExtensionFunctionLookupError {
    /// Tried to call a function that doesn't exist
    #[error(transparent)]
    #[diagnostic(transparent)]
    FuncDoesNotExist(#[from] extension_function_lookup_errors::FuncDoesNotExistError),

    /// Attempted to typecheck a function without a return type
    #[error(transparent)]
    #[diagnostic(transparent)]
    HasNoType(#[from] extension_function_lookup_errors::HasNoTypeError),
}

/// Error subtypes for [`ExtensionFunctionLookupError`]
pub mod extension_function_lookup_errors {
    use crate::ast::Name;
    use crate::parser::Loc;
    use miette::Diagnostic;
    use thiserror::Error;

    /// Tried to call a function that doesn't exist
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    #[error("extension function `{name}` does not exist")]
    pub struct FuncDoesNotExistError {
        /// Name of the function that doesn't exist
        pub(crate) name: Name,
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    impl FuncDoesNotExistError {
        pub(crate) fn with_maybe_source_loc(self, source_loc: Option<Loc>) -> Self {
            Self { source_loc, ..self }
        }

        pub(crate) fn source_loc(&self) -> Option<&Loc> {
            self.source_loc.as_ref()
        }
    }

    impl Diagnostic for FuncDoesNotExistError {
        impl_diagnostic_from_source_loc_field!();

        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
    }

    /// Attempted to typecheck a function without a return type
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    #[error("extension function `{name}` has no return type")]
    pub struct HasNoTypeError {
        /// Name of the function that has no return type
        pub(crate) name: Name,
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    impl Diagnostic for HasNoTypeError {
        impl_diagnostic_from_source_loc_field!();

        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
        fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            None
        }
    }
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
