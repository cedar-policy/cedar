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

use std::collections::HashMap;

use crate::ast::{Extension, ExtensionFunction, Name};
use crate::entities::SchemaType;
use crate::parser::Loc;
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
        #[cfg(feature = "partial-eval")]
        partial_evaluation::extension(),
    ];

    static ref ALL_AVAILABLE_EXTENSIONS : Extensions<'static> = Extensions::build_all_available();

    static ref EXTENSIONS_NONE : Extensions<'static> = Extensions {
        extensions: &[],
        functions: HashMap::new(),
        single_arg_constructors: HashMap::new(),
    };
}

/// Structure representing the type signature of an extension function
/// constructor. We assume constructors take exactly one argument.
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub(crate) struct ExtensionConstructorSignature<'a> {
    /// The type of the constructors single argument.
    pub(crate) argument_type: &'a SchemaType,
    /// The constructors return type.
    pub(crate) return_type: &'a SchemaType,
}

/// Holds data on all the Extensions which are active for a given evaluation.
///
/// This structure is intentionally not `Clone` because we can use it entirely
/// by reference.
#[derive(Debug)]
pub struct Extensions<'a> {
    /// the actual extensions
    extensions: &'a [Extension],
    /// All extension functions, collected from every extension used to
    /// construct this object.  Built ahead of time so that we know during
    /// extension function lookup that at most one extension function exists
    /// for a name. This should also make the lookup more efficient.
    functions: HashMap<&'a Name, &'a ExtensionFunction>,
    /// All single argument extension function constructors, indexed by their
    /// type signature. Built ahead of time so that we know each constructor has
    /// a unique type signature.
    single_arg_constructors: HashMap<ExtensionConstructorSignature<'a>, &'a ExtensionFunction>,
}

impl Extensions<'static> {
    /// Get a new `Extensions` containing data on all the available extensions.
    fn build_all_available() -> Extensions<'static> {
        // PANIC SAFETY: Builtin extensions define functions/constructors only once. Also tested by many different test cases.
        #[allow(clippy::expect_used)]
        Self::specific_extensions(&ALL_AVAILABLE_EXTENSION_OBJECTS)
            .expect("Default extensions should never error on initialization")
    }

    /// An [`Extensions`] object with static lifetime contain all available extensions.
    pub fn all_available() -> &'static Extensions<'static> {
        &ALL_AVAILABLE_EXTENSIONS
    }

    /// Get a new `Extensions` with no extensions enabled.
    pub fn none() -> &'static Extensions<'static> {
        &EXTENSIONS_NONE
    }
}

impl<'a> Extensions<'a> {
    /// Get a new `Extensions` with these specific extensions enabled.
    pub fn specific_extensions(
        extensions: &'a [Extension],
    ) -> std::result::Result<Extensions<'a>, ExtensionInitializationError> {
        // Build functions map, ensuring that no functions share the same name.
        let functions = util::collect_no_duplicates(
            extensions
                .iter()
                .flat_map(|e| e.funcs())
                .map(|f| (f.name(), f)),
        )
        .map_err(|name| FuncMultiplyDefinedError { name: name.clone() })?;

        // Build the constructor map, ensuring that no constructors share a type signature.
        let single_arg_constructors = util::collect_no_duplicates(
            extensions.iter().flat_map(|e| e.funcs()).filter_map(|f| {
                if f.is_constructor() {
                    if let (Some(argument_type), Some(return_type)) =
                        (f.arg_types().first(), f.return_type())
                    {
                        return Some((
                            ExtensionConstructorSignature {
                                argument_type,
                                return_type,
                            },
                            f,
                        ));
                    }
                }
                None
            }),
        )
        .map_err(|sig| MultipleConstructorsSameSignatureError {
            arg_type: Box::new(sig.argument_type.clone()),
            return_type: Box::new(sig.return_type.clone()),
        })?;

        Ok(Extensions {
            extensions,
            functions,
            single_arg_constructors,
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
    ) -> std::result::Result<&ExtensionFunction, ExtensionFunctionLookupError> {
        self.functions.get(name).copied().ok_or_else(|| {
            FuncDoesNotExistError {
                name: name.clone(),
                source_loc: name.loc().cloned(),
            }
            .into()
        })
    }

    /// Iterate over all extension functions defined by all of these extensions.
    ///
    /// No guarantee that this list won't have duplicates or repeated names.
    pub(crate) fn all_funcs(&self) -> impl Iterator<Item = &'a ExtensionFunction> {
        self.extensions.iter().flat_map(|ext| ext.funcs())
    }

    /// Lookup a single-argument constructor by its return type and argument type.
    ///
    /// `None` means no constructor has that signature.
    pub(crate) fn lookup_single_arg_constructor(
        &self,
        type_signature: &ExtensionConstructorSignature<'_>,
    ) -> Option<&ExtensionFunction> {
        self.single_arg_constructors.get(type_signature).copied()
    }
}

/// Errors occurring while initializing extensions. There are internal errors, so
/// this enum should not become part of the public API unless we publicly expose
/// user-defined extension function.
#[derive(Diagnostic, Debug, PartialEq, Eq, Clone, Error)]
pub enum ExtensionInitializationError {
    /// An extension function was defined by multiple extensions.
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

/// Error subtypes for [`ExtensionInitializationError`]
mod extension_initialization_errors {
    use crate::{ast::Name, entities::SchemaType};
    use miette::Diagnostic;
    use thiserror::Error;

    /// An extension function was defined by multiple extensions.
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
        /// argument type of the shared constructor signature
        pub(crate) arg_type: Box<SchemaType>,
        /// return type of the shared constructor signature
        pub(crate) return_type: Box<SchemaType>,
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
}

impl ExtensionFunctionLookupError {
    pub(crate) fn source_loc(&self) -> Option<&Loc> {
        match self {
            Self::FuncDoesNotExist(e) => e.source_loc.as_ref(),
        }
    }

    pub(crate) fn with_maybe_source_loc(self, source_loc: Option<Loc>) -> Self {
        match self {
            Self::FuncDoesNotExist(e) => {
                Self::FuncDoesNotExist(extension_function_lookup_errors::FuncDoesNotExistError {
                    source_loc,
                    ..e
                })
            }
        }
    }
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

    impl Diagnostic for FuncDoesNotExistError {
        impl_diagnostic_from_source_loc_opt_field!(source_loc);
    }
}

/// Type alias for convenience
pub type Result<T> = std::result::Result<T, ExtensionFunctionLookupError>;

/// Utilities shared with the `cedar-policy-validator` extensions module.
pub mod util {
    use std::collections::{hash_map::Entry, HashMap};

    /// Utility to build a `HashMap` of key value pairs from an iterator,
    /// returning an `Err` result if there are any duplicate keys in the
    /// iterator.
    pub fn collect_no_duplicates<K, V>(
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
}

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
