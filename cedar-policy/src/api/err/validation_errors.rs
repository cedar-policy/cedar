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

use miette::Diagnostic;
use ref_cast::RefCast;
use thiserror::Error;

use crate::PolicyId;

// Required for doc link to `ValidationError` without qualifying it with
// `crate`, but not used otherwise, so non-doc builds warned about unused
// imports.
#[cfg(doc)]
use crate::ValidationError;

// Generates a public struct wrapping a core validator error struct. The core
// and external struct will have exactly the same name. This name _must_ be the
// same as the name of the corresponding `ValidationError` variant in `err.rs`
// (`cargo doc` will fail otherwise). This macro generates a basic doc-string
// linking back to the `ValidationError` enum variant where the primary
// documentation should be written.
macro_rules! wrap_core_error {
    ($s:ident) => {
        #[derive(Debug, Clone, Error, Diagnostic)]
        #[error(transparent)]
        #[diagnostic(transparent)]
        #[doc=concat!("Structure containing details about a [`ValidationError::", stringify!($s), "`].")]
        pub struct $s(cedar_policy_core::validator::validation_errors::$s);

        impl $s {
            /// Access the `[PolicyId]` for the policy where this error was found.
            pub fn policy_id(&self) -> &PolicyId {
                PolicyId::ref_cast(&self.0.policy_id)
            }
        }

        #[doc(hidden)]
        impl From<cedar_policy_core::validator::validation_errors::$s> for $s {
            fn from(e: cedar_policy_core::validator::validation_errors::$s) -> Self {
                Self(e)
            }
        }
    };
}

wrap_core_error!(UnrecognizedEntityType);
wrap_core_error!(UnrecognizedActionId);
wrap_core_error!(InvalidActionApplication);
wrap_core_error!(UnexpectedType);
wrap_core_error!(IncompatibleTypes);
wrap_core_error!(UnsafeAttributeAccess);
wrap_core_error!(UnsafeOptionalAttributeAccess);
wrap_core_error!(UnsafeTagAccess);
wrap_core_error!(NoTagsAllowed);
wrap_core_error!(UndefinedFunction);
wrap_core_error!(WrongNumberArguments);
wrap_core_error!(FunctionArgumentValidation);
wrap_core_error!(HierarchyNotRespected);
wrap_core_error!(EntityDerefLevelViolation);
wrap_core_error!(EmptySetForbidden);
wrap_core_error!(NonLitExtConstructor);
wrap_core_error!(InternalInvariantViolation);
wrap_core_error!(InvalidEnumEntity);
