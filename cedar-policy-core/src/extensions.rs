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

#[cfg(feature = "datetime")]
pub mod datetime;
pub mod partial_evaluation;

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use crate::ast::{CallStyle, Extension, ExtensionFunction, Name, UnreservedId};
use crate::entities::SchemaType;
use crate::extensions::extension_initialization_errors::MultipleConstructorsSameSignatureError;
use crate::fuzzy_match::fuzzy_search_limited;
use crate::parser::Loc;
use miette::Diagnostic;
use smol_str::{SmolStr, ToSmolStr};
use thiserror::Error;

use self::extension_function_lookup_errors::FuncDoesNotExistError;
use self::extension_initialization_errors::FuncMultiplyDefinedError;

static ALL_AVAILABLE_EXTENSION_OBJECTS: LazyLock<Vec<Extension>> = LazyLock::new(|| {
    vec![
        #[cfg(feature = "ipaddr")]
        ipaddr::extension(),
        #[cfg(feature = "decimal")]
        decimal::extension(),
        #[cfg(feature = "datetime")]
        datetime::extension(),
        #[cfg(feature = "partial-eval")]
        partial_evaluation::extension(),
    ]
});

static ALL_AVAILABLE_EXTENSIONS: LazyLock<Extensions<'static>> =
    LazyLock::new(Extensions::build_all_available);

static EXTENSIONS_NONE: LazyLock<Extensions<'static>> = LazyLock::new(|| Extensions {
    extensions: &[],
    functions: HashMap::new(),
    single_arg_constructors: HashMap::new(),
});

static EXTENSION_STYLES: LazyLock<ExtStyles<'static>> = LazyLock::new(ExtStyles::load);

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
    /// return type. Built ahead of time so that we know each constructor has
    /// a unique return type.
    single_arg_constructors: HashMap<&'a SchemaType, &'a ExtensionFunction>,
}

impl Extensions<'static> {
    /// Get a new `Extensions` containing data on all the available extensions.
    fn build_all_available() -> Extensions<'static> {
        #[expect(
            clippy::expect_used,
            reason = "Builtin extensions define functions/constructors only once. Also tested by many different test cases."
        )]
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
    /// Obtain the non-empty vector of types supporting operator overloading
    pub fn types_with_operator_overloading(&self) -> impl Iterator<Item = &Name> + '_ {
        self.extensions
            .iter()
            .flat_map(|ext| ext.types_with_operator_overloading())
    }
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

        // Build the constructor map, ensuring that no constructors share a return type
        let single_arg_constructors = util::collect_no_duplicates(
            extensions
                .iter()
                .flat_map(|e| e.funcs())
                .filter(|f| f.is_single_arg_constructor())
                .filter_map(|f| f.return_type().map(|return_type| (return_type, f))),
        )
        .map_err(|return_type| MultipleConstructorsSameSignatureError {
            return_type: Box::new(return_type.clone()),
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

    /// Lookup a single-argument constructor by its return type
    pub(crate) fn lookup_single_arg_constructor(
        &self,
        return_type: &SchemaType,
    ) -> Option<&ExtensionFunction> {
        self.single_arg_constructors.get(return_type).copied()
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

    /// Two extension constructors (in the same or different extensions) exist
    /// for one extension type.  This is currently not allowed.
    #[derive(Diagnostic, Debug, PartialEq, Eq, Clone, Error)]
    #[error("multiple extension constructors for the same extension type {return_type}")]
    pub struct MultipleConstructorsSameSignatureError {
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

/// Extension functions have different callstyles. This stores information about the expected
/// callstyle for each function. Provided static methods can be used to check the expected syntax
/// of a given function call.
#[derive(Debug)]
pub(crate) struct ExtStyles<'a> {
    /// All extension function names (just functions, not methods), as `Name`s
    functions: HashSet<&'a Name>,
    /// All extension function methods. `UnreservedId` is appropriate because methods cannot be namespaced.
    methods: HashSet<UnreservedId>,
    /// All extension function and method names (both qualified and unqualified), in their string (`Display`) form
    functions_and_methods_as_str: HashSet<SmolStr>,
}

impl ExtStyles<'static> {
    fn load() -> ExtStyles<'static> {
        let mut functions = HashSet::new();
        let mut methods = HashSet::new();
        let mut functions_and_methods_as_str = HashSet::new();
        for func in crate::extensions::Extensions::all_available().all_funcs() {
            functions_and_methods_as_str.insert(func.name().to_smolstr());
            match func.style() {
                CallStyle::FunctionStyle => {
                    functions.insert(func.name());
                }
                CallStyle::MethodStyle => {
                    debug_assert!(func.name().is_unqualified());
                    methods.insert(func.name().basename());
                }
            };
        }
        ExtStyles {
            functions,
            methods,
            functions_and_methods_as_str,
        }
    }

    /// If this [`UnreservedId`] is a known method name
    pub(crate) fn is_method(id: &UnreservedId) -> bool {
        EXTENSION_STYLES.methods.contains(id)
    }

    /// If this [`Name`] is a known function name
    pub(crate) fn is_function(id: &Name) -> bool {
        EXTENSION_STYLES.functions.contains(id)
    }

    /// If this [`Name`] is a known extension function/method name or not
    pub(crate) fn is_known_extension_func_name(name: &Name) -> bool {
        Self::is_function(name) || (name.0.path.is_empty() && Self::is_method(&name.basename()))
    }

    /// If this [`SmolStr`] is a known extension function/method name or not. Works
    /// with both qualified and unqualified `s`. (As of this writing, there are no
    /// qualified extension function/method names, so qualified `s` always results
    /// in `false`.)
    pub(crate) fn is_known_extension_func_str(s: &SmolStr) -> bool {
        EXTENSION_STYLES.functions_and_methods_as_str.contains(s)
    }

    fn suggest<I, T>(key: &str, choices: I) -> Option<String>
    where
        I: IntoIterator<Item = T>,
        T: ToString,
    {
        const SUGGESTION_EXTENSION_MAX_DISTANCE: usize = 3;
        let choice_strings: Vec<String> = choices.into_iter().map(|c| c.to_string()).collect();
        let suggestion = fuzzy_search_limited(
            key,
            choice_strings.as_slice(),
            Some(SUGGESTION_EXTENSION_MAX_DISTANCE),
        );
        suggestion.map(|m| format!("did you mean `{m}`?"))
    }

    /// When a method call was expected, suggest a method name matching the provided name
    pub(crate) fn suggest_method(name: &UnreservedId) -> Option<String> {
        Self::suggest(name.as_ref(), &EXTENSION_STYLES.methods)
    }

    /// When a function call was expected, suggest a function name matching the provided name
    pub(crate) fn suggest_function(name: &Name) -> Option<String> {
        Self::suggest(&name.to_string(), &EXTENSION_STYLES.functions)
    }
}

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
mod test {
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
