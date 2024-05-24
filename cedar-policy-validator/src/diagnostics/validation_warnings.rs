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

//! Defines warnings returned by the validator.

// Shorthand macro for setting the diagnostic severity to Warning.
// We can use `#[diagnostic(severity(warning))]` once we don't need to use
// `cedar_policy::impl_diagnostic_from_source_loc` anymore.
macro_rules! impl_diagnostic_warning {
    () => {
        fn severity(&self) -> Option<miette::Severity> {
            Some(miette::Severity::Warning)
        }
    };
}

use cedar_policy_core::{ast::PolicyID, impl_diagnostic_from_source_loc_field, parser::Loc};
use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Error, Eq, Hash)]
#[error("for policy `{policy_id}`, string `\"{string}\"` contains mixed scripts")]
pub struct MixedScriptString {
    pub source_loc: Option<Loc>,
    pub policy_id: PolicyID,
    pub string: String,
}

impl Diagnostic for MixedScriptString {
    impl_diagnostic_from_source_loc_field!();
    impl_diagnostic_warning!();
}

#[derive(Debug, Clone, PartialEq, Error, Eq, Hash)]
#[error("for policy `{policy_id}`, string `\"{string}\"` contains BIDI control characters")]
pub struct BidiCharsInString {
    pub source_loc: Option<Loc>,
    pub policy_id: PolicyID,
    pub string: String,
}

impl Diagnostic for BidiCharsInString {
    impl_diagnostic_from_source_loc_field!();
    impl_diagnostic_warning!();
}

#[derive(Debug, Clone, PartialEq, Error, Eq, Hash)]
#[error("for policy `{policy_id}`, identifier `{id}` contains BIDI control characters")]
pub struct BidiCharsInIdentifier {
    pub source_loc: Option<Loc>,
    pub policy_id: PolicyID,
    pub id: String,
}

impl Diagnostic for BidiCharsInIdentifier {
    impl_diagnostic_from_source_loc_field!();
    impl_diagnostic_warning!();
}

#[derive(Debug, Clone, PartialEq, Error, Eq, Hash)]
#[error("for policy `{policy_id}`, identifier `{id}` contains mixed scripts")]
pub struct MixedScriptIdentifier {
    pub source_loc: Option<Loc>,
    pub policy_id: PolicyID,
    pub id: String,
}
impl Diagnostic for MixedScriptIdentifier {
    impl_diagnostic_from_source_loc_field!();
    impl_diagnostic_warning!();
}

#[derive(Debug, Clone, PartialEq, Error, Eq, Hash)]
#[error("for policy `{policy_id}`, identifier `{id}` contains characters that fall outside of the General Security Profile for Identifiers")]
pub struct ConfusableIdentifier {
    pub source_loc: Option<Loc>,
    pub policy_id: PolicyID,
    pub id: String,
}

impl Diagnostic for ConfusableIdentifier {
    impl_diagnostic_from_source_loc_field!();
    impl_diagnostic_warning!();
}

#[derive(Debug, Clone, PartialEq, Error, Eq, Hash)]
#[error("for policy `{policy_id}`, policy is impossible: the policy expression evaluates to false for all valid requests")]
pub struct ImpossiblePolicy {
    pub source_loc: Option<Loc>,
    pub policy_id: PolicyID,
}

impl Diagnostic for ImpossiblePolicy {
    impl_diagnostic_from_source_loc_field!();
    impl_diagnostic_warning!();
}
