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

use crate::{ast::PolicyID, impl_diagnostic_from_source_loc_opt_field, parser::Loc};
use miette::Diagnostic;
use thiserror::Error;

/// Warning for strings containing mixed scripts
#[derive(Debug, Clone, PartialEq, Error, Eq, Hash)]
#[error("for policy `{policy_id}`, string `\"{string}\"` contains mixed scripts")]
pub struct MixedScriptString {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the warning occurred
    pub policy_id: PolicyID,
    /// String containing mixed scripts
    pub string: String,
}

impl Diagnostic for MixedScriptString {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);
    impl_diagnostic_warning!();
}

/// Warning for strings containing BIDI control characters
#[derive(Debug, Clone, PartialEq, Error, Eq, Hash)]
#[error("for policy `{policy_id}`, string `\"{string}\"` contains BIDI control characters")]
pub struct BidiCharsInString {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the warning occurred
    pub policy_id: PolicyID,
    /// String containing BIDI control characters
    pub string: String,
}

impl Diagnostic for BidiCharsInString {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);
    impl_diagnostic_warning!();
}

/// Warning for identifiers containing BIDI control characters
#[derive(Debug, Clone, PartialEq, Error, Eq, Hash)]
#[error("for policy `{policy_id}`, identifier `{id}` contains BIDI control characters")]
pub struct BidiCharsInIdentifier {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the warning occurred
    pub policy_id: PolicyID,
    /// Identifier containing BIDI control characters
    pub id: String,
}

impl Diagnostic for BidiCharsInIdentifier {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);
    impl_diagnostic_warning!();
}

/// Warning for identifiers containing mixed scripts
#[derive(Debug, Clone, PartialEq, Error, Eq, Hash)]
#[error("for policy `{policy_id}`, identifier `{id}` contains mixed scripts")]
pub struct MixedScriptIdentifier {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the warning occurred
    pub policy_id: PolicyID,
    /// Identifier containing mixed scripts
    pub id: String,
}
impl Diagnostic for MixedScriptIdentifier {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);
    impl_diagnostic_warning!();
}

/// Warning for identifiers containing confusable characters
#[derive(Debug, Clone, PartialEq, Error, Eq, Hash)]
#[error(
    "for policy `{policy_id}`, identifier `{}` contains the character `{}` which is not a printable ASCII character and falls outside of the General Security Profile for Identifiers",
    .id.escape_debug(),
    .confusable_character.escape_debug()
)]
pub struct ConfusableIdentifier {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the warning occurred
    pub policy_id: PolicyID,
    /// Identifier containing confusable characters
    pub id: String,
    /// The specific character we're not happy about
    pub confusable_character: char,
}

impl Diagnostic for ConfusableIdentifier {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);
    impl_diagnostic_warning!();
}

/// Warning for policies that are impossible (evaluate to `false` for all valid requests)
#[derive(Debug, Clone, PartialEq, Error, Eq, Hash)]
#[error("for policy `{policy_id}`, policy is impossible: the policy expression evaluates to false for all valid requests")]
pub struct ImpossiblePolicy {
    /// Source location
    pub source_loc: Option<Loc>,
    /// Policy ID where the warning occurred
    pub policy_id: PolicyID,
}

impl Diagnostic for ImpossiblePolicy {
    impl_diagnostic_from_source_loc_opt_field!(source_loc);
    impl_diagnostic_warning!();
}
