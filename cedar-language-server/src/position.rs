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
        to_range(&self.span, &self.src)
    }
}

impl ToRange for Box<Loc> {
    fn to_range(&self) -> Range {
        to_range(&self.span, &self.src)
    }
}

pub(crate) fn to_range(source_span: &SourceSpan, src: &str) -> Range {
    let text = &src[..source_span.offset()];
    let start_line = text.chars().filter(|&c| c == '\n').count();
    let start_col = text.chars().rev().take_while(|&c| c != '\n').count();

    let end = source_span.offset() + source_span.len();
    let text = &src[..end];
    let end_line = text.chars().filter(|&c| c == '\n').count();
    let end_col = text.chars().rev().take_while(|&c| c != '\n').count();

    Range {
        start: Position {
            line: start_line as u32,
            character: start_col as u32,
        },
        end: Position {
            line: end_line as u32,
            character: end_col as u32,
        },
    }
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
