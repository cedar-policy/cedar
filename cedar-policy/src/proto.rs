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

/// Protobuf structures for types in `cedar_policy_core` and `cedar_policy_validator`
pub mod models {
    mod cedar_policy_core {
        #![allow(
            missing_docs,
            clippy::doc_markdown,
            clippy::derive_partial_eq_without_eq,
            clippy::module_name_repetitions
        )]
        include!(concat!(env!("OUT_DIR"), "/cedar_policy_core.rs"));
    }
    mod cedar_policy_validator {
        #![allow(
            missing_docs,
            clippy::doc_markdown,
            clippy::derive_partial_eq_without_eq
        )]
        include!(concat!(env!("OUT_DIR"), "/cedar_policy_validator.rs"));
    }
    pub use cedar_policy_core::*;
    pub use cedar_policy_validator::*;
}

/// Conversions between proto types and `cedar_policy_core::ast` types (other than policy/policyset types)
mod ast;

/// Conversions between proto types and `cedar_policy_core::ast` policy/policyset types
mod policy;

/// Conversions between proto types and `cedar_policy_core::entities` types
mod entities;

/// Conversions between proto types and `cedar_policy_validator` types
mod validator;

/// Conversions between proto types and `cedar_policy::api` types
mod api;

/// `Protobuf` trait and associated utilities
pub mod traits;
