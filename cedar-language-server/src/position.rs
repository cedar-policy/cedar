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
    Some(Range {
        start: offset_to_position(src, source_span.offset())?,
        end: offset_to_position(src, source_span.offset() + source_span.len())?,
    })
}

pub(crate) fn offset_to_position(text: &str, offset: usize) -> Option<Position> {
    let text = text.get(..offset)?;
    let line = text.chars().filter(|&c| c == '\n').count();
    let char = text.chars().rev().take_while(|&c| c != '\n').count();
    Some(Position::new(line as u32, char as u32))
}

/// Get the byte offset of a position (line and column) in a string,
/// accounting for the actual position of newlines in the string.
pub(crate) fn position_byte_offset(src: &str, pos: Position) -> Option<usize> {
    let mut line_offset = 0;
    for (line_num, line) in src.lines().enumerate() {
        if line_num == pos.line as usize {
            if let Some((char_offset_in_line, _)) = line.char_indices().nth(pos.character as usize)
            {
                return Some(line_offset + char_offset_in_line);
            } else if pos.character as usize == line.chars().count() {
                return Some(line_offset + line.len());
            }
        } else {
            // `+ 1` to skip past new line
            line_offset += line.len() + 1;
        }
    }
    None
}

pub(crate) fn get_char_at_position(position: Position, src: &str) -> Option<char> {
    let offset = position_byte_offset(src, position)?;
    Some(src[offset..].chars().next().unwrap())
}

pub(crate) fn get_text_before_position(text: &str, position: Position) -> Option<&str> {
    let offset = position_byte_offset(text, position)?;
    Some(&text[..offset])
}

pub(crate) fn is_position_in_range(position: Position, range: &Range) -> bool {
    position >= range.start && position <= range.end
}

pub(crate) fn position_within_loc<'a, R, I>(position: Position, range: I) -> bool
where
    R: ToRange + 'a,
    I: Into<Option<&'a R>>,
{
    let Some(range) = range.into() else {
        return false;
    };
    is_position_in_range(position, &range.to_range())
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

    mod offset_to_position {
        use super::*;

        #[test]
        fn empty_string() {
            assert_eq!(offset_to_position("", 0).unwrap(), Position::new(0, 0));
        }

        #[test]
        fn single_line_all_ascii() {
            let text = "hello world";
            assert_eq!(offset_to_position(text, 0).unwrap(), Position::new(0, 0));
            assert_eq!(offset_to_position(text, 6).unwrap(), Position::new(0, 6));
            assert_eq!(
                offset_to_position(text, text.len()).unwrap(),
                Position::new(0, text.len() as u32)
            );
            assert_eq!(offset_to_position(text, 20), None);
        }

        #[test]
        fn multi_line_all_ascii() {
            let text = "line1\nline2\nline3";
            assert_eq!(offset_to_position(text, 0).unwrap(), Position::new(0, 0));
            assert_eq!(offset_to_position(text, 3).unwrap(), Position::new(0, 3));
            assert_eq!(offset_to_position(text, 5).unwrap(), Position::new(0, 5));
            assert_eq!(offset_to_position(text, 6).unwrap(), Position::new(1, 0));
            assert_eq!(offset_to_position(text, 14).unwrap(), Position::new(2, 2));
            assert_eq!(offset_to_position(text, 17).unwrap(), Position::new(2, 5));
        }

        #[test]
        fn empty_lines() {
            let text = "\n\n\n";
            assert_eq!(offset_to_position(text, 0).unwrap(), Position::new(0, 0));
            assert_eq!(offset_to_position(text, 1).unwrap(), Position::new(1, 0));
            assert_eq!(offset_to_position(text, 2).unwrap(), Position::new(2, 0));
            assert_eq!(offset_to_position(text, 3).unwrap(), Position::new(3, 0));
            assert_eq!(offset_to_position(text, 4), None);
        }

        #[test]
        fn unicode_characters() {
            let text = "_🚀_";
            assert_eq!(offset_to_position(text, 0).unwrap(), Position::new(0, 0));
            assert_eq!(offset_to_position(text, 1).unwrap(), Position::new(0, 1));
            assert_eq!(offset_to_position(text, 5).unwrap(), Position::new(0, 2));
            assert_eq!(offset_to_position(text, 7), None);
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
                    start: Position::new(0, 6),
                    end: Position::new(0, 11),
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
                    start: Position::new(1, 0),
                    end: Position::new(1, 5),
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
                    start: Position::new(0, 3),
                    end: Position::new(1, 5),
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
                    start: Position::new(0, 5),
                    end: Position::new(0, 5),
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
                    start: Position::new(0, 0),
                    end: Position::new(2, 5),
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
                    start: Position::new(0, 0),
                    end: Position::new(0, 0),
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
                    start: Position::new(0, 11),
                    end: Position::new(0, 11),
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
                    start: Position::new(0, 5),
                    end: Position::new(0, 5),
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
                    start: Position::new(0, 5),
                    end: Position::new(1, 0),
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
                    start: Position::new(0, 2),
                    end: Position::new(0, 7),
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
                    start: Position::new(1, 0),
                    end: Position::new(1, 2),
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
            assert_eq!(get_char_at_position(Position::new(0, 0), src), Some('h'));
            assert_eq!(get_char_at_position(Position::new(0, 4), src), Some('o'));
            assert_eq!(get_char_at_position(Position::new(0, 5), src), Some('\n'));
            assert_eq!(get_char_at_position(Position::new(1, 0), src), Some('w'));
            assert_eq!(get_char_at_position(Position::new(1, 4), src), Some('d'));
        }

        #[test]
        fn invalid_positions() {
            let src = "hello\nworld";
            assert_eq!(get_char_at_position(Position::new(2, 0), src), None);
            assert_eq!(get_char_at_position(Position::new(0, 10), src), None);
            assert_eq!(get_char_at_position(Position::new(1, 10), src), None);
        }

        #[test]
        fn empty() {
            assert_eq!(get_char_at_position(Position::new(0, 0), ""), None);
            assert_eq!(get_char_at_position(Position::new(0, 1), ""), None);
            assert_eq!(get_char_at_position(Position::new(1, 0), ""), None);
        }

        #[test]
        fn newlines() {
            assert_eq!(
                get_char_at_position(Position::new(1, 0), "hello\n\nworld"),
                Some('\n')
            );
            assert_eq!(
                get_char_at_position(Position::new(0, 0), "\r\n"),
                Some('\r')
            );
            assert_eq!(get_char_at_position(Position::new(0, 0), "\r"), Some('\r'));
            assert_eq!(get_char_at_position(Position::new(0, 0), "\n"), Some('\n'));
            assert_eq!(
                get_char_at_position(Position::new(0, 0), "\n\n"),
                Some('\n')
            );
            assert_eq!(
                get_char_at_position(Position::new(1, 0), "\n\n"),
                Some('\n')
            );
            assert_eq!(
                get_char_at_position(Position::new(1, 0), "\n\r\n"),
                Some('\r')
            );
        }

        #[test]
        fn unicode_characters() {
            let src = "héllo\nwörld";
            assert_eq!(get_char_at_position(Position::new(0, 1), src), Some('é'));
            assert_eq!(get_char_at_position(Position::new(0, 2), src), Some('l'));
            assert_eq!(get_char_at_position(Position::new(1, 1), src), Some('ö'));
            assert_eq!(get_char_at_position(Position::new(1, 2), src), Some('r'));
        }
    }

    mod position_within_loc {
        use super::*;

        #[test]
        fn single_line_range() {
            let src = "hello world";
            let loc = create_loc(src, 6, 5);

            assert!(position_within_loc(Position::new(0, 6), Some(&loc)));
            assert!(position_within_loc(Position::new(0, 8), Some(&loc)));
            assert!(position_within_loc(Position::new(0, 10), Some(&loc)));

            assert!(!position_within_loc(Position::new(0, 5), Some(&loc)));
            assert!(!position_within_loc(Position::new(1, 8), Some(&loc)));
        }

        #[test]
        fn multiline_range() {
            let src = "line1\nline2\nline3";
            let loc = create_loc(src, 3, 8);

            assert!(position_within_loc(Position::new(0, 3), Some(&loc)));
            assert!(position_within_loc(Position::new(1, 2), Some(&loc)));
            assert!(position_within_loc(Position::new(1, 5), Some(&loc)));

            assert!(!position_within_loc(Position::new(0, 2), Some(&loc)));
            assert!(!position_within_loc(Position::new(1, 6), Some(&loc)));
            assert!(!position_within_loc(Position::new(2, 0), Some(&loc)));
        }
    }

    mod ranges_intersect {
        use super::*;

        #[test]
        fn overlapping_ranges() {
            let range_a = Range {
                start: Position::new(0, 5),
                end: Position::new(0, 10),
            };
            let range_b = Range {
                start: Position::new(0, 8),
                end: Position::new(0, 15),
            };

            assert!(ranges_intersect(&range_a, &range_b));
            assert!(ranges_intersect(&range_b, &range_a));
        }

        #[test]
        fn separate_ranges() {
            let range_a = Range {
                start: Position::new(0, 5),
                end: Position::new(0, 10),
            };
            let range_b = Range {
                start: Position::new(0, 15),
                end: Position::new(0, 20),
            };

            assert!(!ranges_intersect(&range_a, &range_b));
            assert!(!ranges_intersect(&range_b, &range_a));
        }

        #[test]
        fn multiline_ranges() {
            let range_a = Range {
                start: Position::new(0, 5),
                end: Position::new(1, 10),
            };
            let range_b = Range {
                start: Position::new(1, 5),
                end: Position::new(2, 5),
            };

            assert!(ranges_intersect(&range_a, &range_b));

            let range_c = Range {
                start: Position::new(2, 5),
                end: Position::new(2, 10),
            };
            assert!(!ranges_intersect(&range_a, &range_c));
        }
    }

    mod get_text_before_position {
        use super::*;

        #[test]
        fn single_line() {
            let text = "hello world";
            assert_eq!(
                get_text_before_position(text, Position::new(0, 0)).unwrap(),
                ""
            );
            assert_eq!(
                get_text_before_position(text, Position::new(0, 5)).unwrap(),
                "hello"
            );
            assert_eq!(
                get_text_before_position(text, Position::new(0, 11)).unwrap(),
                "hello world"
            );
        }

        #[test]
        fn multi_line() {
            let text = "line1\nline2\nline3";
            assert_eq!(
                get_text_before_position(text, Position::new(0, 0)).unwrap(),
                ""
            );
            assert_eq!(
                get_text_before_position(text, Position::new(0, 3)).unwrap(),
                "lin"
            );
            assert_eq!(
                get_text_before_position(text, Position::new(0, 5)).unwrap(),
                "line1"
            );
            assert_eq!(
                get_text_before_position(text, Position::new(1, 5)).unwrap(),
                "line1\nline2"
            );
        }

        #[test]
        fn empty_lines() {
            let text = "\n\n\n";
            assert_eq!(
                get_text_before_position(text, Position::new(1, 0)).unwrap(),
                "\n"
            );
            assert_eq!(
                get_text_before_position(text, Position::new(2, 0)).unwrap(),
                "\n\n"
            );
        }

        #[test]
        fn unicode_characters() {
            let text = "🚀H";
            assert_eq!(
                get_text_before_position(text, Position::new(0, 0)).unwrap(),
                ""
            );
            assert_eq!(
                get_text_before_position(text, Position::new(0, 1)).unwrap(),
                "🚀"
            );
            assert_eq!(
                get_text_before_position(text, Position::new(0, 2)).unwrap(),
                "🚀H"
            );
        }
    }
}
