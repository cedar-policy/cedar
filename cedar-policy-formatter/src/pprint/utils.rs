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

use itertools::Itertools;
use pretty::RcDoc;

use super::token::{Comment, WrappedToken};

// Add brackets
pub fn add_brackets<'a>(d: RcDoc<'a>, leftp: RcDoc<'a>, rightp: RcDoc<'a>) -> RcDoc<'a> {
    leftp.append(d.nest(1)).append(rightp)
}

pub fn get_leading_comment_doc_from_str<'a>(leading_comment: &str) -> RcDoc<'a> {
    if leading_comment.is_empty() {
        RcDoc::nil()
    } else {
        let cs: RcDoc<'_> = RcDoc::intersperse(
            leading_comment
                .trim()
                .split('\n')
                .map(|c| RcDoc::text(c.to_owned())),
            RcDoc::hardline(),
        );
        RcDoc::hardline().append(cs).append(RcDoc::hardline())
    }
}

pub fn get_trailing_comment_doc_from_str<'a>(trailing_comment: &str) -> RcDoc<'a> {
    if trailing_comment.is_empty() {
        RcDoc::nil()
    } else {
        RcDoc::space()
            .append(RcDoc::text(trailing_comment.trim().to_owned()))
            .append(RcDoc::hardline())
    }
}

fn get_token_at_start(start: usize, tokens: &mut [WrappedToken]) -> Option<&mut WrappedToken> {
    tokens.as_mut().iter_mut().find(|t| t.span.start == start)
}

pub fn get_comment_at_start(start: usize, tokens: &mut [WrappedToken]) -> Option<Comment> {
    Some(get_token_at_start(start, tokens)?.consume_comment())
}

pub fn get_leading_comment_at_start(start: usize, tokens: &mut [WrappedToken]) -> Option<String> {
    Some(get_token_at_start(start, tokens)?.consume_leading_comment())
}

fn get_token_after_end(end: usize, tokens: &mut [WrappedToken]) -> Option<&mut WrappedToken> {
    tokens.iter_mut().find_or_first(|t| t.span.start >= end)
}

fn get_token_at_end(end: usize, tokens: &mut [WrappedToken]) -> Option<&mut WrappedToken> {
    tokens.iter_mut().find(|t| t.span.end == end)
}

pub fn get_comment_at_end(end: usize, tokens: &mut [WrappedToken]) -> Option<Comment> {
    Some(get_token_at_end(end, tokens)?.consume_comment())
}

pub fn get_comment_after_end(end: usize, tokens: &mut [WrappedToken]) -> Option<Comment> {
    Some(get_token_after_end(end, tokens)?.consume_comment())
}

pub fn get_comment_in_range(start: usize, end: usize, tokens: &mut [WrappedToken]) -> Vec<Comment> {
    tokens
        .iter_mut()
        .skip_while(|t| t.span.start < start)
        .take_while(|t| t.span.end <= end)
        .map(|t| t.consume_comment())
        .collect()
}

// Wrap doc with comment
pub fn add_comment<'a>(d: RcDoc<'a>, comment: Comment, next_doc: RcDoc<'a>) -> RcDoc<'a> {
    let leading_comment = comment.leading_comment;
    let trailing_comment = comment.trailing_comment;
    let leading_comment_doc = get_leading_comment_doc_from_str(&leading_comment);
    let trailing_comment_doc: RcDoc<'_> = if trailing_comment.is_empty() {
        d.append(next_doc)
    } else {
        d.append(RcDoc::space())
            .append(RcDoc::text(trailing_comment.trim().to_owned()))
            .append(RcDoc::hardline())
    };

    leading_comment_doc.append(trailing_comment_doc.clone())
}

pub fn remove_empty_lines(s: &str) -> String {
    s.lines()
        .filter(|ss| !ss.trim().is_empty())
        .map(|s| s.to_owned())
        .collect::<Vec<String>>()
        .join("\n")
}
