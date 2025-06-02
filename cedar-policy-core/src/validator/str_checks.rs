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

use crate::ast::{PolicyID, Template};
use crate::parser::Loc;

use crate::validator::expr_iterator::expr_text;
use crate::validator::expr_iterator::TextKind;
use crate::validator::ValidationWarning;
use unicode_security::GeneralSecurityProfile;
use unicode_security::MixedScript;

/// Perform identifier and string safety checks.
pub fn confusable_string_checks<'a>(
    p: impl Iterator<Item = &'a Template>,
) -> impl Iterator<Item = ValidationWarning> {
    let mut warnings = vec![];

    for policy in p {
        let e = policy.condition();
        for str in expr_text(&e) {
            let warning = match str {
                TextKind::String(span, s) => permissable_str(span, policy.id(), s),
                TextKind::Identifier(span, i) => permissable_ident(span, policy.id(), i),
                TextKind::Pattern(span, pat) => {
                    permissable_str(span, policy.id(), &pat.to_string())
                }
            };

            if let Some(warning) = warning {
                warnings.push(warning)
            }
        }
    }

    warnings.into_iter()
}

fn permissable_str(loc: Option<&Loc>, policy_id: &PolicyID, s: &str) -> Option<ValidationWarning> {
    if s.chars().any(is_bidi_char) {
        Some(ValidationWarning::bidi_chars_strings(
            loc.cloned(),
            policy_id.clone(),
            s.to_string(),
        ))
    } else if !s.is_single_script() {
        Some(ValidationWarning::mixed_script_string(
            loc.cloned(),
            policy_id.clone(),
            s.to_string(),
        ))
    } else {
        None
    }
}

fn permissable_ident(
    loc: Option<&Loc>,
    policy_id: &PolicyID,
    s: &str,
) -> Option<ValidationWarning> {
    if s.chars().any(is_bidi_char) {
        Some(ValidationWarning::bidi_chars_identifier(
            loc.cloned(),
            policy_id.clone(),
            s,
        ))
    } else if let Some(c) = s
        .chars()
        .find(|c| *c != ' ' && !c.is_ascii_graphic() && !c.identifier_allowed())
    {
        Some(ValidationWarning::confusable_identifier(
            loc.cloned(),
            policy_id.clone(),
            s,
            c,
        ))
    } else if !s.is_single_script() {
        Some(ValidationWarning::mixed_script_identifier(
            loc.cloned(),
            policy_id.clone(),
            s,
        ))
    } else {
        None
    }
}

fn is_bidi_char(c: char) -> bool {
    BIDI_CHARS.iter().any(|bidi| bidi == &c)
}

/// List of BIDI chars to warn on.
/// Source: <`https://doc.rust-lang.org/nightly/nightly-rustc/rustc_lint/hidden_unicode_codepoints/static.TEXT_DIRECTION_CODEPOINT_IN_LITERAL.html`>
///
/// We could instead parse the structure of BIDI overrides and make sure it's well balanced.
/// This is less prone to error, and since it's only a warning can be ignored by a user if need be.
const BIDI_CHARS: [char; 9] = [
    '\u{202A}', '\u{202B}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{202C}',
    '\u{2069}',
];

// PANIC SAFETY unit tests
#[allow(clippy::panic)]
// PANIC SAFETY unit tests
#[allow(clippy::indexing_slicing)]
#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        ast::PolicySet,
        parser::{parse_policy, Loc},
        test_utils::{expect_err, ExpectedErrorMessageBuilder},
    };
    use cool_asserts::assert_matches;
    use std::sync::Arc;
    #[test]
    fn strs() {
        assert_eq!(
            permissable_str(None, &PolicyID::from_string("0"), "test"),
            None
        );
        assert_eq!(
            permissable_str(None, &PolicyID::from_string("0"), "test\t\t"),
            None
        );
        assert_eq!(
            permissable_str(None, &PolicyID::from_string("0"), "say_һello"),
            Some(ValidationWarning::mixed_script_string(
                None,
                PolicyID::from_string("0"),
                "say_һello"
            ))
        );
    }

    #[test]
    #[allow(clippy::invisible_characters)]
    fn idents() {
        assert_eq!(
            permissable_ident(None, &PolicyID::from_string("0"), "test"),
            None
        );
        assert_eq!(
            permissable_ident(
                None,
                &PolicyID::from_string("0"),
                "https://www.example.com/test?foo=bar&bar=baz#buz"
            ),
            None
        );
        assert_eq!(
            permissable_ident(
                None,
                &PolicyID::from_string("0"),
                "http://example.com/query{firstName}-{lastName}"
            ),
            None
        );
        assert_eq!(
            permissable_ident(
                None,
                &PolicyID::from_string("0"),
                "example_user+1@example.com"
            ),
            None
        );
        assert_eq!(
            permissable_ident(None, &PolicyID::from_string("0"), "get /pets/{petId}"),
            None
        );

        assert_matches!(permissable_ident(None, &PolicyID::from_string("0"), "is​Admin"), Some(warning) => {
            expect_err(
                "",
                &miette::Report::new(warning),
                &ExpectedErrorMessageBuilder::error(r#"for policy `0`, identifier `is\u{200b}Admin` contains the character `\u{200b}` which is not a printable ASCII character and falls outside of the General Security Profile for Identifiers"#)
                    .build());
        });
        assert_matches!(permissable_ident(None, &PolicyID::from_string("0"), "new\nline"), Some(warning) => {
            expect_err(
                "",
                &miette::Report::new(warning),
                &ExpectedErrorMessageBuilder::error(r#"for policy `0`, identifier `new\nline` contains the character `\n` which is not a printable ASCII character and falls outside of the General Security Profile for Identifiers"#)
                    .build());
        });
        assert_matches!(permissable_ident(None, &PolicyID::from_string("0"), "null\0"), Some(warning) => {
            expect_err(
                "",
                &miette::Report::new(warning),
                &ExpectedErrorMessageBuilder::error(r#"for policy `0`, identifier `null\0` contains the character `\0` which is not a printable ASCII character and falls outside of the General Security Profile for Identifiers"#)
                    .build());
        });
        assert_matches!(permissable_ident(None, &PolicyID::from_string("0"), "delete\x7f"), Some(warning) => {
            expect_err(
                "",
                &miette::Report::new(warning),
                &ExpectedErrorMessageBuilder::error(r#"for policy `0`, identifier `delete\u{7f}` contains the character `\u{7f}` which is not a printable ASCII character and falls outside of the General Security Profile for Identifiers"#)
                    .build());
        });
        assert_matches!(permissable_ident(None, &PolicyID::from_string("0"), "🍌"), Some(warning) => {
            expect_err(
                "",
                &miette::Report::new(warning),
                &ExpectedErrorMessageBuilder::error(r#"for policy `0`, identifier `🍌` contains the character `🍌` which is not a printable ASCII character and falls outside of the General Security Profile for Identifiers"#)
                    .build());
        });
        assert_matches!(permissable_ident(None, &PolicyID::from_string("0"), "say_һello") , Some(warning) => {
            expect_err(
                "",
                &miette::Report::new(warning),
                &ExpectedErrorMessageBuilder::error(r#"for policy `0`, identifier `say_һello` contains mixed scripts"#)
                    .build());
        });
    }

    #[test]
    fn a() {
        let src = r#"
        permit(principal == test::"say_һello", action, resource);
        "#;

        let mut s = PolicySet::new();
        let p = parse_policy(Some(PolicyID::from_string("test")), src).unwrap();
        s.add_static(p).unwrap();
        let warnings =
            confusable_string_checks(s.policies().map(|p| p.template())).collect::<Vec<_>>();
        assert_eq!(warnings.len(), 1);
        let warning = &warnings[0];
        assert_eq!(
            warning,
            &ValidationWarning::mixed_script_identifier(
                None,
                PolicyID::from_string("test"),
                r#"say_һello"#
            )
        );
        assert_eq!(
            format!("{warning}"),
            "for policy `test`, identifier `say_һello` contains mixed scripts"
        );
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
        let p = parse_policy(Some(PolicyID::from_string("test")), src).unwrap();
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
        let p = parse_policy(Some(PolicyID::from_string("test")), src).unwrap();
        s.add_static(p).unwrap();
        let warnings =
            confusable_string_checks(s.policies().map(|p| p.template())).collect::<Vec<_>>();
        assert_eq!(warnings.len(), 1);
        let warning = &warnings[0];
        assert_eq!(
            warning,
            &ValidationWarning::mixed_script_string(
                Some(Loc::new(64..94, Arc::from(src))),
                PolicyID::from_string("test"),
                r#"*_һello"#
            )
        );
        assert_eq!(
            format!("{warning}"),
            "for policy `test`, string `\"*_һello\"` contains mixed scripts"
        );
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
        let p = parse_policy(Some(PolicyID::from_string("test")), src).unwrap();
        s.add_static(p).unwrap();
        let warnings =
            confusable_string_checks(s.policies().map(|p| p.template())).collect::<Vec<_>>();
        assert_eq!(warnings.len(), 1);
        let warning = &warnings[0];
        assert_eq!(
            warning,
            &ValidationWarning::bidi_chars_strings(
                Some(Loc::new(90..131, Arc::from(src))),
                PolicyID::from_string("test"),
                r#"user‮ ⁦&& principal.is_admin⁩ ⁦"#
            )
        );
        assert_eq!(
            format!("{warning}"),
            "for policy `test`, string `\"user‮ ⁦&& principal.is_admin⁩ ⁦\"` contains BIDI control characters"
        );
    }
}
