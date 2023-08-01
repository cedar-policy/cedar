/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

use cedar_policy_core::ast::{Pattern, PolicyID, Template};
use thiserror::Error;

use crate::expr_iterator::expr_text;
use crate::expr_iterator::TextKind;
use unicode_security::GeneralSecurityProfile;
use unicode_security::MixedScript;

/// Returned by the standalone `confusable_string_checker` function, which checks a policy set for potentially confusing/obfuscating text.
#[derive(Debug, Clone)]
pub struct ValidationWarning<'a> {
    location: &'a PolicyID,
    kind: ValidationWarningKind,
}

impl<'a> ValidationWarning<'a> {
    pub fn location(&self) -> &'a PolicyID {
        self.location
    }

    pub fn kind(&self) -> &ValidationWarningKind {
        &self.kind
    }

    pub fn to_kind_and_location(self) -> (&'a PolicyID, ValidationWarningKind) {
        (self.location, self.kind)
    }
}

impl std::fmt::Display for ValidationWarning<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "warning: {} in policy with id {}",
            self.kind, self.location
        )
    }
}

#[derive(Debug, Clone, PartialEq, Error, Eq)]
pub enum ValidationWarningKind {
    /// A string contains mixed scripts. Different scripts can contain visually similar characters which may be confused for each other.
    #[error("string \"{0}\" contains mixed scripts")]
    MixedScriptString(String),
    /// A string contains BIDI control characters. These can be used to create crafted pieces of code that obfuscate true control flow.
    #[error("string \"{0}\" contains BIDI control characters")]
    BidiCharsInString(String),
    /// An id contains BIDI control characters. These can be used to create crafted pieces of code that obfuscate true control flow.
    #[error("identifier `{0}` contains BIDI control characters")]
    BidiCharsInIdentifier(String),
    /// An id contains mixed scripts. This can cause characters to be confused for each other.
    #[error("identifier `{0}` contains mixed scripts")]
    MixedScriptIdentifier(String),
    /// An id contains characters that fall outside of the General Security Profile for Identifiers. We recommend adhering to this if possible. See Unicode® Technical Standard #39 for more info.
    #[error("identifier `{0}` contains characters that fall outside of the General Security Profile for Identifiers")]
    ConfusableIdentifier(String),
}

/// Perform identifier and string safety checks.
pub fn confusable_string_checks<'a>(
    p: impl Iterator<Item = &'a Template>,
) -> impl Iterator<Item = ValidationWarning<'a>> {
    let mut warnings = vec![];

    for policy in p {
        let e = policy.condition();
        for str in expr_text(&e) {
            let warning = match str {
                TextKind::String(s) => permissable_str(s),
                TextKind::Identifier(i) => permissable_ident(i),
                TextKind::Pattern(p) => {
                    let pat = Pattern::new(p.iter().copied());
                    let as_str = format!("{pat}");
                    permissable_str(&as_str)
                }
            };

            if let Some(w) = warning {
                warnings.push(ValidationWarning {
                    location: policy.id(),
                    kind: w,
                })
            }
        }
    }

    warnings.into_iter()
}

fn permissable_str(s: &str) -> Option<ValidationWarningKind> {
    if s.chars().any(is_bidi_char) {
        Some(ValidationWarningKind::BidiCharsInString(s.to_string()))
    } else if !s.is_single_script() {
        Some(ValidationWarningKind::MixedScriptString(s.to_string()))
    } else {
        None
    }
}

fn permissable_ident(s: &str) -> Option<ValidationWarningKind> {
    if s.chars().any(is_bidi_char) {
        Some(ValidationWarningKind::BidiCharsInIdentifier(s.to_string()))
    } else if !s.chars().all(|c| c.identifier_allowed()) {
        Some(ValidationWarningKind::ConfusableIdentifier(s.to_string()))
    } else if !s.is_single_script() {
        Some(ValidationWarningKind::MixedScriptIdentifier(s.to_string()))
    } else {
        None
    }
}

fn is_bidi_char(c: char) -> bool {
    BIDI_CHARS.iter().any(|bidi| bidi == &c)
}

/// List of BIDI chars to warn on
/// Source: https://doc.rust-lang.org/nightly/nightly-rustc/rustc_lint/hidden_unicode_codepoints/static.TEXT_DIRECTION_CODEPOINT_IN_LITERAL.html
/// We could instead parse the structure of BIDI overrides and make sure it's well balanced.
/// This is less prone to error, and since it's only a warning can be ignored by a user if need be.
const BIDI_CHARS: [char; 9] = [
    '\u{202A}', '\u{202B}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{202C}',
    '\u{2069}',
];

#[cfg(test)]
mod test {

    use super::*;
    use cedar_policy_core::{ast::PolicySet, parser::parse_policy};

    #[test]
    fn strs() {
        assert!(permissable_str("test").is_none());
        assert!(permissable_str("test\t\t").is_none());
        match permissable_str("say_һello") {
            Some(ValidationWarningKind::MixedScriptString(_)) => (),
            o => panic!("should have produced MixedScriptString: {:?}", o),
        };
    }

    #[test]
    #[allow(clippy::invisible_characters)]
    fn idents() {
        assert!(permissable_ident("test").is_none());
        match permissable_ident("is​Admin") {
            Some(ValidationWarningKind::ConfusableIdentifier(_)) => (),
            o => panic!("should have produced ConfusableIdentifier: {:?}", o),
        };
        match permissable_ident("say_һello") {
            Some(ValidationWarningKind::MixedScriptIdentifier(_)) => (),
            o => panic!("should have produced MixedScriptIdentifier: {:?}", o),
        };
    }

    #[test]
    fn a() {
        let src = r#"
        permit(principal == test::"say_һello", action, resource);
        "#;

        let mut s = PolicySet::new();
        let p = parse_policy(Some("test".to_string()), src).unwrap();
        s.add_static(p).unwrap();
        let warnings =
            confusable_string_checks(s.policies().map(|p| p.template())).collect::<Vec<_>>();
        assert_eq!(warnings.len(), 1);
        let warning = &warnings[0];
        let kind = warning.kind().clone();
        let location = warning.location();
        assert_eq!(
            kind,
            ValidationWarningKind::MixedScriptIdentifier(r#"say_һello"#.to_string())
        );
        assert_eq!(
            format!("{warning}"),
            "warning: identifier `say_һello` contains mixed scripts in policy with id test"
        );
        assert_eq!(location, &PolicyID::from_string("test"));
        assert_eq!(warning.clone().to_kind_and_location(), (location, kind));
    }

    #[test]
    #[allow(clippy::invisible_characters)]
    fn b() {
        let src = r#"
        permit(principal, action, resource) when {
            principal["is​Admin"] == "say_һello"
        };
        "#;
        let mut s = PolicySet::new();
        let p = parse_policy(Some("test".to_string()), src).unwrap();
        s.add_static(p).unwrap();
        let warnings = confusable_string_checks(s.policies().map(|p| p.template()));
        assert_eq!(warnings.count(), 2);
    }

    #[test]
    fn problem_in_pattern() {
        let src = r#"
        permit(principal, action, resource) when {
            principal.name like "*_һello"
        };
        "#;
        let mut s = PolicySet::new();
        let p = parse_policy(Some("test".to_string()), src).unwrap();
        s.add_static(p).unwrap();
        let warnings =
            confusable_string_checks(s.policies().map(|p| p.template())).collect::<Vec<_>>();
        assert_eq!(warnings.len(), 1);
        let warning = &warnings[0];
        let kind = warning.kind().clone();
        let location = warning.location();
        assert_eq!(
            kind,
            ValidationWarningKind::MixedScriptString(r#"*_һello"#.to_string())
        );
        assert_eq!(
            format!("{warning}"),
            "warning: string \"*_һello\" contains mixed scripts in policy with id test"
        );
        assert_eq!(location, &PolicyID::from_string("test"));
        assert_eq!(warning.clone().to_kind_and_location(), (location, kind));
    }

    #[test]
    #[allow(text_direction_codepoint_in_literal)]
    fn trojan_source() {
        let src = r#"
        permit(principal, action, resource) when {
            principal.access_level != "user‮ ⁦&& principal.is_admin⁩ ⁦"
        };
        "#;
        let mut s = PolicySet::new();
        let p = parse_policy(Some("test".to_string()), src).unwrap();
        s.add_static(p).unwrap();
        let warnings =
            confusable_string_checks(s.policies().map(|p| p.template())).collect::<Vec<_>>();
        assert_eq!(warnings.len(), 1);
        let warning = &warnings[0];
        let kind = warning.kind().clone();
        let location = warning.location();
        assert_eq!(
            kind,
            ValidationWarningKind::BidiCharsInString(r#"user‮ ⁦&& principal.is_admin⁩ ⁦"#.to_string())
        );
        assert_eq!(format!("{warning}"), "warning: string \"user‮ ⁦&& principal.is_admin⁩ ⁦\" contains BIDI control characters in policy with id test");
        assert_eq!(location, &PolicyID::from_string("test"));
        assert_eq!(warning.clone().to_kind_and_location(), (location, kind));
    }
}
