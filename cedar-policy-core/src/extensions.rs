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

use crate::ast::{Extension, ExtensionFunction, Name};
use crate::entities::SchemaType;
use crate::parser::Loc;
use miette::Diagnostic;
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
#[derive(Debug, Clone, Copy)]
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

    /// Get all extension type names declared by active extensions.
    ///
    /// (More specifically, all extension type names such that any function in
    /// an active extension could produce a value of that extension type.)
    pub fn ext_types(&self) -> impl Iterator<Item = &Name> {
        self.extensions.iter().flat_map(|ext| ext.ext_types())
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
        match extension_funcs.first() {
            None => Err(extension_function_lookup_errors::FuncDoesNotExistError {
                name: name.clone(),
                source_loc: None,
            }
            .into()),
            Some(first) if extension_funcs.len() == 1 => Ok(first),
            _ => Err(extension_function_lookup_errors::FuncMultiplyDefinedError {
                name: name.clone(),
                num_defs: extension_funcs.len(),
                source_loc: None,
            }
            .into()),
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
                    && f.arg_types().first().map(Option::as_ref) == Some(Some(arg_type))
            })
            .collect::<Vec<_>>();
        match matches.first() {
            None => Ok(None),
            Some(first) if matches.len() == 1 => Ok(Some(first)),
            _ => Err(
                extension_function_lookup_errors::MultipleConstructorsSameSignatureError {
                    return_type: Box::new(return_type.clone()),
                    arg_type: Box::new(arg_type.clone()),
                    source_loc: None,
                }
                .into(),
            ),
        }
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

    /// Tried to call a function but it was defined multiple times (e.g., by
    /// multiple different extensions)
    #[error(transparent)]
    #[diagnostic(transparent)]
    FuncMultiplyDefined(#[from] extension_function_lookup_errors::FuncMultiplyDefinedError),

    /// Attempted to typecheck a function without a return type
    #[error(transparent)]
    #[diagnostic(transparent)]
    HasNoType(#[from] extension_function_lookup_errors::HasNoTypeError),

    /// Two extension constructors (in the same or different extensions) had
    /// exactly the same type signature.  This is currently not allowed.
    #[error(transparent)]
    #[diagnostic(transparent)]
    MultipleConstructorsSameSignature(
        #[from] extension_function_lookup_errors::MultipleConstructorsSameSignatureError,
    ),
}

impl ExtensionFunctionLookupError {
    pub(crate) fn source_loc(&self) -> Option<&Loc> {
        match self {
            Self::FuncDoesNotExist(e) => e.source_loc.as_ref(),
            Self::FuncMultiplyDefined(e) => e.source_loc.as_ref(),
            Self::HasNoType(e) => e.source_loc.as_ref(),
            Self::MultipleConstructorsSameSignature(e) => e.source_loc.as_ref(),
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
            Self::FuncMultiplyDefined(e) => Self::FuncMultiplyDefined(
                extension_function_lookup_errors::FuncMultiplyDefinedError { source_loc, ..e },
            ),
            Self::HasNoType(e) => {
                Self::HasNoType(extension_function_lookup_errors::HasNoTypeError {
                    source_loc,
                    ..e
                })
            }
            Self::MultipleConstructorsSameSignature(e) => Self::MultipleConstructorsSameSignature(
                extension_function_lookup_errors::MultipleConstructorsSameSignatureError {
                    source_loc,
                    ..e
                },
            ),
        }
    }
}

/// Error subtypes for [`ExtensionFunctionLookupError`]
pub mod extension_function_lookup_errors {
    use crate::ast::Name;
    use crate::entities::SchemaType;
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

    /// Tried to call a function that doesn't exist
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    #[error("extension function `{name}` is defined {num_defs} times")]
    pub struct FuncMultiplyDefinedError {
        /// Name of the function that was multiply defined
        pub(crate) name: Name,
        /// How many times that function is defined
        pub(crate) num_defs: usize,
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    impl Diagnostic for FuncMultiplyDefinedError {
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

    /// Two extension constructors (in the same or different extensions) had
    /// exactly the same type signature.  This is currently not allowed.
    //
    // CAUTION: this type is publicly exported in `cedar-policy`.
    // Don't make fields `pub`, don't make breaking changes, and use caution
    // when adding public methods.
    #[derive(Debug, PartialEq, Eq, Clone, Error)]
    #[error(
        "multiple extension constructors have the same type signature {arg_type} -> {return_type}"
    )]
    pub struct MultipleConstructorsSameSignatureError {
        /// return type of the shared constructor signature
        pub(crate) return_type: Box<SchemaType>,
        /// argument type of the shared constructor signature
        pub(crate) arg_type: Box<SchemaType>,
        /// Source location
        pub(crate) source_loc: Option<Loc>,
    }

    impl Diagnostic for MultipleConstructorsSameSignatureError {
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
