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

use std::collections::BTreeSet;

use crate::ast::{Expr, Name};
use crate::validator::types::Type;

/// Type information for a Cedar extension.
pub struct ExtensionSchema {
    /// Name of the extension
    name: Name,
    /// Type information for extension functions
    function_types: Vec<ExtensionFunctionType>,
    /// Types that support operator overloading
    types_with_operator_overloading: BTreeSet<Name>,
}

impl std::fmt::Debug for ExtensionSchema {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<extension schema {}>", self.name())
    }
}

impl ExtensionSchema {
    /// Create a new `ExtensionSchema`
    pub fn new(
        name: Name,
        function_types: impl IntoIterator<Item = ExtensionFunctionType>,
        types_with_operator_overloading: impl IntoIterator<Item = Name>,
    ) -> Self {
        Self {
            name,
            function_types: function_types.into_iter().collect(),
            types_with_operator_overloading: types_with_operator_overloading.into_iter().collect(),
        }
    }

    /// Get the name of the extension
    pub fn name(&self) -> &Name {
        &self.name
    }

    pub fn function_types(&self) -> impl Iterator<Item = &ExtensionFunctionType> {
        self.function_types.iter()
    }

    /// Get all extension types that support operator overloading
    pub fn types_with_operator_overloading(&self) -> impl Iterator<Item = &Name> {
        self.types_with_operator_overloading.iter()
    }
}

/// The type of a function used to perform custom argument validation on an
/// extension function application. An `ArgumentCheckFn` is passed a slice
/// containing the arguments to the extension function call and returns `Err` if
/// it can statically determine that the arguments are invalid.
pub(crate) type ArgumentCheckFn =
    Box<dyn Fn(&[Expr]) -> Result<(), String> + Sync + Send + 'static>;

/// Type information for a single extension function.
pub struct ExtensionFunctionType {
    /// Function name
    name: Name,
    /// Argument types
    argument_types: Vec<Type>,
    /// Return type
    return_type: Type,
    /// Custom argument validation (optional)
    check_arguments: Option<ArgumentCheckFn>,
}

impl ExtensionFunctionType {
    /// Create a new `ExtensionFunctionType`
    pub fn new(
        name: Name,
        argument_types: Vec<Type>,
        return_type: Type,
        check_arguments: Option<ArgumentCheckFn>,
    ) -> Self {
        Self {
            name,
            argument_types,
            return_type,
            check_arguments,
        }
    }

    /// Get the name of the extension function
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Get the extension function argument types
    pub fn argument_types(&self) -> &Vec<Type> {
        &self.argument_types
    }

    /// Get the extension function return type
    pub fn return_type(&self) -> &Type {
        &self.return_type
    }

    /// Call the `check_arguments` function with the given args
    pub fn check_arguments(&self, args: &[Expr]) -> Result<(), String> {
        if let Some(f) = &self.check_arguments {
            return (f)(args);
        }
        Ok(())
    }

    /// Return true when this extension function has a `check_arguments`
    /// function defined.
    pub fn has_argument_check(&self) -> bool {
        self.check_arguments.is_some()
    }
}

impl std::fmt::Debug for ExtensionFunctionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<extension function type {}>", self.name())
    }
}
