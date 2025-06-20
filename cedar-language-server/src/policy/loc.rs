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

use cedar_policy_core::parser::Loc;
use miette::{SourceOffset, SourceSpan};

pub(crate) struct SchemaActionLoc<'a>(&'a Loc);

impl<'a> SchemaActionLoc<'a> {
    pub(crate) fn new(loc: &'a Loc) -> Self {
        Self(loc)
    }

    // FIXME: Does not handle `appliesTo` or `context:` appearing in strings or
    // comments. Should be able to maintain this location when parsing the
    // schema and get rid of this whole mess.
    pub(crate) fn context_loc(&self) -> Option<Loc> {
        // Get the full text within this location
        let text = &self.0.src[self.0.span.offset()..self.0.span.offset() + self.0.span.len()];

        // First find if we're inside an appliesTo block
        if let Some(applies_to_pos) = text.find("appliesTo") {
            // Extract everything from "appliesTo" forward
            let applies_to_text = &text[applies_to_pos..];

            // Find "context:" within the appliesTo block
            if let Some(context_pos) = applies_to_text.find("context:") {
                let absolute_context_pos = applies_to_pos + context_pos;
                let after_context = absolute_context_pos + "context:".len();

                // Get an iterator over characters with their byte positions
                let mut chars = text[after_context..].char_indices();
                let first_non_whitespace = loop {
                    let (p, c) = chars.next()?;
                    if !c.is_whitespace() {
                        break (p, c);
                    }
                };
                if first_non_whitespace.1 == '{' {
                    // Anonymous record - find matching closing brace
                    let mut depth = 1;

                    while let Some((_, c)) = chars.next() {
                        match c {
                            '{' => depth += 1,
                            '}' => {
                                depth -= 1;
                                if depth == 0 {
                                    // We found the complete context block
                                    let context_end = after_context + chars.offset();

                                    // Calculate the absolute position in the source
                                    let absolute_start =
                                        self.0.span.offset() + absolute_context_pos;
                                    let length = context_end - absolute_context_pos;

                                    return Some(Loc {
                                        span: SourceSpan::new(
                                            SourceOffset::from(absolute_start),
                                            length,
                                        ),
                                        src: self.0.src.clone(),
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                } else {
                    let start_offset = after_context + first_non_whitespace.0;
                    let mut last_non_whitespace = 0;
                    for (byte_pos, c) in chars {
                        if c == ',' || c == ';' || c == '\n' || c == '}' {
                            break;
                        }
                        if !c.is_whitespace() {
                            last_non_whitespace = byte_pos;
                        }
                    }

                    let absolute_start = self.0.span.offset() + absolute_context_pos;
                    let length = start_offset + last_non_whitespace - absolute_context_pos;
                    return Some(Loc {
                        span: SourceSpan::new(SourceOffset::from(absolute_start), length),
                        src: self.0.src.clone(),
                    });
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;
    use std::sync::Arc;

    use super::*;

    fn make_loc(text: &str) -> Loc {
        Loc {
            span: SourceSpan::new(SourceOffset::from(0), text.len()),
            src: Arc::from(text),
        }
    }

    #[track_caller]
    fn assert_loc_text(loc: &Loc, expected: &str) {
        let actual = &loc.src[loc.span.offset()..loc.span.offset() + loc.span.len()];
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_no_applies_to() {
        let loc = make_loc("action DoSomething");
        let action_loc = SchemaActionLoc::new(&loc);
        assert!(action_loc.context_loc().is_none());
    }

    #[test]
    fn test_no_context() {
        let loc = make_loc(
            "action DoSomething
            appliesTo {
                principal: User,
                resource: Resource
            }",
        );
        let action_loc = SchemaActionLoc::new(&loc);
        assert!(action_loc.context_loc().is_none());
    }

    #[test]
    fn test_named_type_context() {
        let text = "action DoSomething
            appliesTo {
                principal: User,
                resource: Resource,
                context: ContextType
            }";
        let loc = make_loc(text);
        let action_loc = SchemaActionLoc::new(&loc);
        let context_loc = action_loc.context_loc().unwrap();
        assert_loc_text(&context_loc, "context: ContextType");
    }

    #[test]
    fn test_record_type_context() {
        let text = "action DoSomething
            appliesTo {
                principal: User,
                resource: Resource,
                context: {
                    field1: String,
                    field2: Number
                }
            }";
        let loc = make_loc(text);
        let action_loc = SchemaActionLoc::new(&loc);
        let context_loc = action_loc.context_loc().unwrap();
        assert_loc_text(&context_loc, "context: {\n                    field1: String,\n                    field2: Number\n                }");
    }

    #[test]
    fn test_context_with_comments() {
        let text = "action DoSomething
            appliesTo {
                principal: User,
                resource: Resource,
                // A comment before context
                context: ContextType, // Inline comment
            }";
        let loc = make_loc(text);
        let action_loc = SchemaActionLoc::new(&loc);
        let context_loc = action_loc.context_loc().unwrap();
        assert_loc_text(&context_loc, "context: ContextType");
    }

    #[test]
    fn test_multiple_actions() {
        let text = "action Action1, Action2, Action3 in [other]
            appliesTo {
                principal: User,
                resource: Resource,
                context: ContextType
            }";
        let loc = make_loc(text);
        let action_loc = SchemaActionLoc::new(&loc);
        let context_loc = action_loc.context_loc().unwrap();
        assert_loc_text(&context_loc, "context: ContextType");
    }

    #[test]
    fn test_nested_record() {
        let text = "action DoSomething
            appliesTo {
                principal: User,
                resource: Resource,
                context: { outer: { inner: Long }, other: String }
            }";
        let loc = make_loc(text);
        let action_loc = SchemaActionLoc::new(&loc);
        let context_loc = action_loc.context_loc().unwrap();
        assert_loc_text(
            &context_loc,
            "context: { outer: { inner: Long }, other: String }",
        );
    }

    #[test]
    fn test_multiple_nested_record() {
        let text = "action DoSomething
            appliesTo {
                principal: User,
                resource: Resource,
                context: { outer: { inner: Long }, other: { inner: String } }
            }";
        let loc = make_loc(text);
        let action_loc = SchemaActionLoc::new(&loc);
        let context_loc = action_loc.context_loc().unwrap();
        assert_loc_text(
            &context_loc,
            "context: { outer: { inner: Long }, other: { inner: String } }",
        );
    }

    #[test]
    fn test_empty_record() {
        let text = "action DoSomething
            appliesTo {
                principal: User,
                resource: Resource,
                context: {}
            }";
        let loc = make_loc(text);
        let action_loc = SchemaActionLoc::new(&loc);
        let context_loc = action_loc.context_loc().unwrap();
        assert_loc_text(&context_loc, "context: {}");
    }

    #[test]
    fn test_context_with_trailing_comma() {
        let text = "action DoSomething
            appliesTo {
                principal: User,
                resource: Resource,
                context: ContextType,
            }";
        let loc = make_loc(text);
        let action_loc = SchemaActionLoc::new(&loc);
        let context_loc = action_loc.context_loc().unwrap();
        assert_loc_text(&context_loc, "context: ContextType");
    }

    #[test]
    fn test_unicode_type_name() {
        let text = "action DoSomething
            appliesTo {
                principal: User,
                resource: Resource,
                context: 컨텍스트Type
            }";
        let loc = make_loc(text);
        let action_loc = SchemaActionLoc::new(&loc);
        let context_loc = action_loc.context_loc().unwrap();
        assert_loc_text(&context_loc, "context: 컨텍스트Type");
    }

    #[test]
    fn test_combining_characters() {
        let text = "action DoSomething
            appliesTo {
                principal: User,
                resource: Resource,
                context: Contéxt
            }";
        let loc = make_loc(text);
        let action_loc = SchemaActionLoc::new(&loc);
        let context_loc = action_loc.context_loc().unwrap();
        assert_loc_text(&context_loc, "context: Contéxt");
    }

    #[test]
    fn test_unicode_with_brace_bytes() {
        let text = "action DoSomething
            appliesTo {
                principal: User,
                resource: Resource,
                context: { a: \u{017b}Type }
            }";
        let loc = make_loc(text);
        let action_loc = SchemaActionLoc::new(&loc);
        let context_loc = action_loc.context_loc().unwrap();
        assert_loc_text(&context_loc, "context: { a: \u{017b}Type }");

        let text = "action DoSomething
            appliesTo {
                principal: User,
                resource: Resource,
                context: { a: \u{7b01}Type }
            }";
        let loc = make_loc(text);
        let action_loc = SchemaActionLoc::new(&loc);
        let context_loc = action_loc.context_loc().unwrap();
        assert_loc_text(&context_loc, "context: { a: \u{7b01}Type }");

        let text = "action DoSomething
            appliesTo {
                principal: User,
                resource: Resource,
                context: \u{7b01}Type
            }";
        let loc = make_loc(text);
        let action_loc = SchemaActionLoc::new(&loc);
        let context_loc = action_loc.context_loc().unwrap();
        assert_loc_text(&context_loc, "context: \u{7b01}Type");
    }
}
