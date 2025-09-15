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

//! Defines utility functions for manipulating [`tower_lsp_server::lsp_types::Position`] and
//! [`tower_lsp_server::lsp_types::Range`] which both represent a position in a string as a
//! line number and character offset into the line rather than as a byte offset as would be
//! typical for Rust strings

use cedar_policy_core::parser::Loc;
use miette::SourceSpan;
use tower_lsp_server::lsp_types::{Position, Range};

pub(crate) trait ToRange {
    fn to_range(&self) -> Range;
}

impl ToRange for Loc {
    fn to_range(&self) -> Range {
        // Assumes that `span` is in bounds for `src`. This is true if
        // this `Loc` is constructed by our parser, but is easy to
        // violate if constructing a `Loc` manually.
        // PANIC_SAFETY: See above
        #[allow(clippy::unwrap_used)]
        to_range(&self.span, &self.src).unwrap()
    }
}

impl ToRange for Box<Loc> {
    fn to_range(&self) -> Range {
        // Assumes that `span` is in bounds for `src`. This is true if
        // this `Loc` is constructed by our parsers, but is easy to
        // violate if constructing a `Loc` manually.
        // PANIC_SAFETY: See above
        #[allow(clippy::unwrap_used)]
        to_range(&self.span, &self.src).unwrap()
    }
}

pub(crate) fn to_range(source_span: &SourceSpan, src: &str) -> Option<Range> {
    let text = src.get(..source_span.offset())?;
    let start_line = text.chars().filter(|&c| c == '\n').count();
    let start_col = text.chars().rev().take_while(|&c| c != '\n').count();

    let end = source_span.offset() + source_span.len();
    let text = src.get(..end)?;
    let end_line = text.chars().filter(|&c| c == '\n').count();
    let end_col = text.chars().rev().take_while(|&c| c != '\n').count();

    Some(Range {
        start: Position {
            line: start_line as u32,
            character: start_col as u32,
        },
        end: Position {
            line: end_line as u32,
            character: end_col as u32,
        },
    })
}

pub(crate) fn get_char_at_position(position: Position, src: &str) -> Option<char> {
    src.lines()
        .nth(position.line as usize)?
        .chars()
        .nth(position.character as usize)
}

pub(crate) fn position_within_loc<'a, R, I>(position: Position, range: I) -> bool
where
    R: ToRange + 'a,
    I: Into<Option<&'a R>>,
{
    let Some(range) = range.into() else {
        return false;
    };
    let range = range.to_range();
    position.line >= range.start.line
        && position.line <= range.end.line
        && (position.line != range.start.line || position.character >= range.start.character)
        && (position.line != range.end.line || position.character <= range.end.character)
}

pub(crate) fn ranges_intersect(a: &Range, b: &Range) -> bool {
    a.start <= b.end && b.start <= a.end
}

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy_core::parser::Loc;
    use miette::SourceSpan;
    use tower_lsp_server::lsp_types::{Position, Range};

    fn create_loc(src: &str, offset: usize, len: usize) -> Loc {
        Loc {
            span: SourceSpan::new(offset.into(), len),
            src: src.to_string().into(),
        }
    }

    mod to_range {
        use super::*;

        #[test]
        fn single_line_span() {
            let src = "hello world";
            let span = SourceSpan::new(6.into(), 5);
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position {
                        line: 0,
                        character: 6
                    },
                    end: Position {
                        line: 0,
                        character: 11
                    },
                }
            );
        }

        #[test]
        fn multiline_span_within_line() {
            let src = "line1\nline2\nline3";
            let span = SourceSpan::new(6.into(), 5); // "line2"
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position {
                        line: 1,
                        character: 0
                    },
                    end: Position {
                        line: 1,
                        character: 5
                    },
                }
            );
        }

        #[test]
        fn span_across_lines() {
            let src = "line1\nline2\nline3";
            let span = SourceSpan::new(3.into(), 8); // "e1\nline2"
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position {
                        line: 0,
                        character: 3
                    },
                    end: Position {
                        line: 1,
                        character: 5
                    },
                }
            );
        }

        #[test]
        fn empty_span() {
            let src = "hello world";
            let span = SourceSpan::new(5.into(), 0);
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position {
                        line: 0,
                        character: 5
                    },
                    end: Position {
                        line: 0,
                        character: 5
                    },
                }
            );
        }

        #[test]
        fn entire_string() {
            let src = "line1\nline2\nline3";
            let span = SourceSpan::new(0.into(), src.len());
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position {
                        line: 0,
                        character: 0
                    },
                    end: Position {
                        line: 2,
                        character: 5
                    },
                }
            );
        }

        #[test]
        fn empty_string() {
            let src = "";
            let span = SourceSpan::new(0.into(), 0);
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position {
                        line: 0,
                        character: 0
                    },
                    end: Position {
                        line: 0,
                        character: 0
                    },
                }
            );
        }

        #[test]
        fn zero_length_at_string_end() {
            let src = "hello world";
            let span = SourceSpan::new(11.into(), 0);
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position {
                        line: 0,
                        character: 11
                    },
                    end: Position {
                        line: 0,
                        character: 11
                    },
                }
            );
        }

        #[test]
        fn zero_length_at_line_end() {
            let src = "hello\nworld";
            let span = SourceSpan::new(5.into(), 0); // at newline
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position {
                        line: 0,
                        character: 5
                    },
                    end: Position {
                        line: 0,
                        character: 5
                    },
                }
            );
        }

        #[test]
        fn span_is_newline() {
            let src = "line1\nline2";
            let span = SourceSpan::new(5.into(), 1); // the newline character
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position {
                        line: 0,
                        character: 5
                    },
                    end: Position {
                        line: 1,
                        character: 0
                    },
                }
            );
        }

        #[test]
        fn multibyte_characters() {
            let src = "🚀 héllo 世界";
            let span = SourceSpan::new(5.into(), 6); // "héllo" (é is 2 bytes)
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position {
                        line: 0,
                        character: 2
                    },
                    end: Position {
                        line: 0,
                        character: 7
                    },
                }
            );
        }

        #[test]
        fn unicode_across_lines() {
            let src = "🚀\n世界";
            let span = SourceSpan::new(5.into(), 6);
            let range = to_range(&span, src).unwrap();

            assert_eq!(
                range,
                Range {
                    start: Position {
                        line: 1,
                        character: 0
                    },
                    end: Position {
                        line: 1,
                        character: 2
                    },
                }
            );
        }

        #[test]
        fn offset_out_of_bounds() {
            let src = "hello";
            let span = SourceSpan::new(10.into(), 0);
            assert_eq!(to_range(&span, src), None);
            let span = SourceSpan::new(3.into(), 5);
            assert_eq!(to_range(&span, src), None);
        }
    }

    mod get_char_at_position {
        use super::*;

        #[test]
        fn valid_positions() {
            let src = "hello\nworld";

            assert_eq!(
                get_char_at_position(
                    Position {
                        line: 0,
                        character: 0
                    },
                    src
                ),
                Some('h')
            );
            assert_eq!(
                get_char_at_position(
                    Position {
                        line: 0,
                        character: 4
                    },
                    src
                ),
                Some('o')
            );
            assert_eq!(
                get_char_at_position(
                    Position {
                        line: 1,
                        character: 0
                    },
                    src
                ),
                Some('w')
            );
            assert_eq!(
                get_char_at_position(
                    Position {
                        line: 1,
                        character: 4
                    },
                    src
                ),
                Some('d')
            );
        }

        #[test]
        fn invalid_positions() {
            let src = "hello\nworld";

            assert_eq!(
                get_char_at_position(
                    Position {
                        line: 2,
                        character: 0
                    },
                    src
                ),
                None
            );

            assert_eq!(
                get_char_at_position(
                    Position {
                        line: 0,
                        character: 10
                    },
                    src
                ),
                None
            );
            assert_eq!(
                get_char_at_position(
                    Position {
                        line: 1,
                        character: 10
                    },
                    src
                ),
                None
            );
        }

        #[test]
        fn empty() {
            assert_eq!(
                get_char_at_position(
                    Position {
                        line: 0,
                        character: 0
                    },
                    ""
                ),
                None
            );

            let src = "hello\n\nworld";
            assert_eq!(
                get_char_at_position(
                    Position {
                        line: 1,
                        character: 0
                    },
                    src
                ),
                None
            );
        }

        #[test]
        fn unicode_characters() {
            let src = "héllo\nwörld";
            assert_eq!(
                get_char_at_position(
                    Position {
                        line: 0,
                        character: 1
                    },
                    src
                ),
                Some('é')
            );
            assert_eq!(
                get_char_at_position(
                    Position {
                        line: 1,
                        character: 1
                    },
                    src
                ),
                Some('ö')
            );
        }
    }

    mod position_within_loc {
        use super::*;

        #[test]
        fn single_line_range() {
            let src = "hello world";
            let loc = create_loc(src, 6, 5);

            assert!(position_within_loc(
                Position {
                    line: 0,
                    character: 6
                },
                Some(&loc)
            ));
            assert!(position_within_loc(
                Position {
                    line: 0,
                    character: 8
                },
                Some(&loc)
            ));
            assert!(position_within_loc(
                Position {
                    line: 0,
                    character: 10
                },
                Some(&loc)
            ));

            assert!(!position_within_loc(
                Position {
                    line: 0,
                    character: 5
                },
                Some(&loc)
            ));
            assert!(!position_within_loc(
                Position {
                    line: 1,
                    character: 8
                },
                Some(&loc)
            ));
        }

        #[test]
        fn multiline_range() {
            let src = "line1\nline2\nline3";
            let loc = create_loc(src, 3, 8);

            assert!(position_within_loc(
                Position {
                    line: 0,
                    character: 3
                },
                Some(&loc)
            ));
            assert!(position_within_loc(
                Position {
                    line: 1,
                    character: 2
                },
                Some(&loc)
            ));
            assert!(position_within_loc(
                Position {
                    line: 1,
                    character: 5
                },
                Some(&loc)
            ));

            assert!(!position_within_loc(
                Position {
                    line: 0,
                    character: 2
                },
                Some(&loc)
            ));
            assert!(!position_within_loc(
                Position {
                    line: 1,
                    character: 6
                },
                Some(&loc)
            ));
            assert!(!position_within_loc(
                Position {
                    line: 2,
                    character: 0
                },
                Some(&loc)
            ));
        }
    }

    mod ranges_intersect {
        use super::*;

        #[test]
        fn overlapping_ranges() {
            let range_a = Range {
                start: Position {
                    line: 0,
                    character: 5,
                },
                end: Position {
                    line: 0,
                    character: 10,
                },
            };
            let range_b = Range {
                start: Position {
                    line: 0,
                    character: 8,
                },
                end: Position {
                    line: 0,
                    character: 15,
                },
            };

            assert!(ranges_intersect(&range_a, &range_b));
            assert!(ranges_intersect(&range_b, &range_a));
        }

        #[test]
        fn separate_ranges() {
            let range_a = Range {
                start: Position {
                    line: 0,
                    character: 5,
                },
                end: Position {
                    line: 0,
                    character: 10,
                },
            };
            let range_b = Range {
                start: Position {
                    line: 0,
                    character: 15,
                },
                end: Position {
                    line: 0,
                    character: 20,
                },
            };

            assert!(!ranges_intersect(&range_a, &range_b));
            assert!(!ranges_intersect(&range_b, &range_a));
        }

        #[test]
        fn multiline_ranges() {
            let range_a = Range {
                start: Position {
                    line: 0,
                    character: 5,
                },
                end: Position {
                    line: 1,
                    character: 10,
                },
            };
            let range_b = Range {
                start: Position {
                    line: 1,
                    character: 5,
                },
                end: Position {
                    line: 2,
                    character: 5,
                },
            };

            assert!(ranges_intersect(&range_a, &range_b));

            let range_c = Range {
                start: Position {
                    line: 2,
                    character: 5,
                },
                end: Position {
                    line: 2,
                    character: 10,
                },
            };
            assert!(!ranges_intersect(&range_a, &range_c));
        }
    }
}
