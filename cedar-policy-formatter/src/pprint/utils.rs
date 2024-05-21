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

use itertools::Itertools;
use pretty::RcDoc;
use regex::Regex;

use super::token::{Comment, WrappedToken};

// Add brackets
pub fn add_brackets<'a>(d: RcDoc<'a>, leftp: RcDoc<'a>, rightp: RcDoc<'a>) -> RcDoc<'a> {
    leftp.append(d.nest(1)).append(rightp)
}

/// Convert a leading comment to an `RcDoc`, adding leading and trailing newlines.
pub fn get_leading_comment_doc_from_str<'a>(leading_comment: &str) -> RcDoc<'a> {
    if leading_comment.is_empty() {
        RcDoc::nil()
    } else {
        RcDoc::hardline()
            .append(create_multiline_doc(leading_comment))
            .append(RcDoc::hardline())
    }
}

/// Convert multiline text into an `RcDoc`. Both `RcDoc::as_string` and
/// `RcDoc::text` allow newlines in the text (although the official
/// documentation says they don't), but the resulting text will maintain its
/// original indentation instead of the new "pretty" indentation.
fn create_multiline_doc<'a>(str: &str) -> RcDoc<'a> {
    RcDoc::intersperse(
        str.trim().split('\n').map(|c| RcDoc::text(c.to_owned())),
        RcDoc::hardline(),
    )
}

/// Convert a trailing comment to an `RcDoc`, adding a trailing newline.
/// There is no need to use `create_multiline_doc` because a trailing comment
/// cannot contain newlines.
pub fn get_trailing_comment_doc_from_str<'a>(
    trailing_comment: &str,
    next_doc: RcDoc<'a>,
) -> RcDoc<'a> {
    if trailing_comment.is_empty() {
        next_doc
    } else {
        RcDoc::space()
            .append(RcDoc::text(trailing_comment.trim().to_owned()))
            .append(RcDoc::hardline())
    }
}

fn get_token_at_start(
    span: miette::SourceSpan,
    tokens: &mut [WrappedToken],
) -> Option<&mut WrappedToken> {
    tokens
        .as_mut()
        .iter_mut()
        .find(|t| t.span.start == span.offset())
}

pub fn get_comment_at_start(
    span: miette::SourceSpan,
    tokens: &mut [WrappedToken],
) -> Option<Comment> {
    Some(get_token_at_start(span, tokens)?.consume_comment())
}

pub fn get_leading_comment_at_start(
    span: miette::SourceSpan,
    tokens: &mut [WrappedToken],
) -> Option<String> {
    Some(get_token_at_start(span, tokens)?.consume_leading_comment())
}

fn get_token_after_end(
    span: miette::SourceSpan,
    tokens: &mut [WrappedToken],
) -> Option<&mut WrappedToken> {
    let end = span.offset() + span.len();
    tokens.iter_mut().find_or_first(|t| t.span.start >= end)
}

fn get_token_at_end(
    span: miette::SourceSpan,
    tokens: &mut [WrappedToken],
) -> Option<&mut WrappedToken> {
    let end = span.offset() + span.len();
    tokens.iter_mut().find(|t| t.span.end == end)
}

pub fn get_comment_at_end(
    span: miette::SourceSpan,
    tokens: &mut [WrappedToken],
) -> Option<Comment> {
    Some(get_token_at_end(span, tokens)?.consume_comment())
}

pub fn get_comment_after_end(
    span: miette::SourceSpan,
    tokens: &mut [WrappedToken],
) -> Option<Comment> {
    Some(get_token_after_end(span, tokens)?.consume_comment())
}

pub fn get_comment_in_range(span: miette::SourceSpan, tokens: &mut [WrappedToken]) -> Vec<Comment> {
    tokens
        .iter_mut()
        .skip_while(|t| t.span.start < span.offset())
        .take_while(|t| t.span.end <= span.offset() + span.len())
        .map(|t| t.consume_comment())
        .collect()
}

/// Wrap an `RcDoc` with comments. If there is a leading comment, then this
/// will introduce a newline bat the start of the `RcDoc`. If there is a
/// trailing comment, then it will introduce a newline at the end.
pub fn add_comment<'a>(d: RcDoc<'a>, comment: Comment, next_doc: RcDoc<'a>) -> RcDoc<'a> {
    let leading_comment = comment.leading_comment;
    let trailing_comment = comment.trailing_comment;
    let leading_comment_doc = get_leading_comment_doc_from_str(&leading_comment);
    let trailing_comment_doc = get_trailing_comment_doc_from_str(&trailing_comment, next_doc);
    leading_comment_doc.append(d).append(trailing_comment_doc)
}

/// Remove empty lines from the input string, ignoring the first and last lines.
/// (Because of how this function is used in `remove_empty_lines`, the first and
/// last lines may include important spacing information.) This will remove empty
/// lines  _everywhere_, including in places where that may not be desired
/// (e.g., in string literals).
fn remove_empty_interior_lines(s: &str) -> String {
    let mut new_s = String::new();
    if s.starts_with('\n') {
        new_s.push_str("\n");
    }
    new_s.push_str(
        s.split_inclusive('\n')
            // in the case where `s` does not end in a newline, `!ss.contains('\n')`
            // preserves whitespace on the last line
            .filter(|ss| !ss.trim().is_empty() || !ss.contains('\n'))
            .collect::<Vec<_>>()
            .join("")
            .as_str(),
    );
    new_s
}

/// Remove empty lines, safely handling newlines that occur in quotations.
pub fn remove_empty_lines(text: &str) -> String {
    // PANIC SAFETY: this regex pattern is valid
    #[allow(clippy::unwrap_used)]
    let comment_regex = Regex::new(r"//[^\n]*").unwrap();
    // PANIC SAFETY: this regex pattern is valid
    #[allow(clippy::unwrap_used)]
    let string_regex = Regex::new(r#""(\\.|[^"\\])*"[^\n]*"#).unwrap();

    let mut index = 0;
    let mut final_text = String::new();

    while index < text.len() {
        // Check for the next comment and string. The general strategy is to
        // call `remove_empty_interior_lines` on all the text _outside_ of
        // strings. Comments should be skipped to avoid interpreting a quote in
        // a comment as a string.
        let comment_match = comment_regex.find_at(text, index);
        let string_match = string_regex.find_at(text, index);
        match (comment_match, string_match) {
            (Some(m1), Some(m2)) => {
                // Handle the earlier match
                let m = std::cmp::min_by_key(m1, m2, |m| m.start());
                // PANIC SAFETY: Slicing `text` is safe since `index <= m.start()` and both are within the bounds of `text`.
                #[allow(clippy::indexing_slicing)]
                final_text.push_str(&remove_empty_interior_lines(&text[index..m.start()]));
                final_text.push_str(m.as_str());
                index = m.end();
            }
            (Some(m), None) | (None, Some(m)) => {
                // PANIC SAFETY: Slicing `text` is safe since `index <= m.start()` and both are within the bounds of `text`.
                #[allow(clippy::indexing_slicing)]
                final_text.push_str(&remove_empty_interior_lines(&text[index..m.start()]));
                final_text.push_str(m.as_str());
                index = m.end();
            }
            (None, None) => {
                // PANIC SAFETY: Slicing `text` is safe since `index` is within the bounds of `text`.
                #[allow(clippy::indexing_slicing)]
                final_text.push_str(&remove_empty_interior_lines(&text[index..]));
                break;
            }
        }
    }
    // Trim the final result to account for dangling newlines
    final_text.trim().to_string()
}
