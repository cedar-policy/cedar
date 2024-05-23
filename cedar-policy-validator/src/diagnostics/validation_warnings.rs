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
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Diagnostic, Error, Eq, Hash)]
#[error("string `\"{string}\"` contains mixed scripts")]
#[diagnostic(severity(warning))]
pub struct MixedScriptString {
    pub(crate) string: String,
}

#[derive(Debug, Clone, PartialEq, Diagnostic, Error, Eq, Hash)]
#[error("string `\"{string}\"` contains BIDI control characters")]
#[diagnostic(severity(warning))]
pub struct BidiCharsInString {
    pub(crate) string: String,
}

#[derive(Debug, Clone, PartialEq, Diagnostic, Error, Eq, Hash)]
#[error("identifier `{id}` contains BIDI control characters")]
#[diagnostic(severity(warning))]
pub struct BidiCharsInIdentifier {
    pub(crate) id: String,
}

#[derive(Debug, Clone, PartialEq, Diagnostic, Error, Eq, Hash)]
#[error("identifier `{id}` contains mixed scripts")]
#[diagnostic(severity(warning))]
pub struct MixedScriptIdentifier {
    pub(crate) id: String,
}

#[derive(Debug, Clone, PartialEq, Diagnostic, Error, Eq, Hash)]
#[error("identifier `{id}` contains characters that fall outside of the General Security Profile for Identifiers")]
#[diagnostic(severity(warning))]
pub struct ConfusableIdentifier {
    pub(crate) id: String,
}

#[derive(Debug, Clone, PartialEq, Diagnostic, Error, Eq, Hash)]
#[error("policy is impossible: the policy expression evaluates to false for all valid requests")]
#[diagnostic(severity(warning))]
pub struct ImpossiblePolicy {}
