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

use super::token::{Comment, Token, WrappedToken};
use logos::Logos;

// Attach comments to tokens
fn add_comments(token_stream: &mut [WrappedToken], input: &str) -> Option<()> {
    let mut i = 0;
    if token_stream.is_empty() {
        return None;
    }
    let first_token = token_stream.first_mut()?;
    let first_range = &first_token.span;
    if first_range.start > 0 {
        first_token.add_leading_comment(input.get(..first_range.start)?);
    }

    while i + 1 < token_stream.len() {
        let (curr_tokens, next_tokens) = token_stream.split_at_mut(i + 1);
        let curr_token = curr_tokens.last_mut()?;
        let next_token = next_tokens.first_mut()?;
        let curr_range = &curr_token.span;
        let next_range = &next_token.span;
        if curr_range.end == next_range.start {
            i += 1;
            continue;
        }
        let gap = input.get(curr_range.end..next_range.start)?;
        match gap.split_once('\n') {
            Some((f, r)) => {
                curr_token.add_trailing_comment(f);
                next_token.add_leading_comment(r);
            }
            None => {
                curr_token.add_trailing_comment(gap);
            }
        }
        i += 1;
    }
    Some(())
}

pub fn get_token_stream(input: &str) -> Option<Vec<WrappedToken>> {
    let mut wrapped_tokens: Vec<WrappedToken> = Token::lexer(input)
        .spanned()
        .map(|(t, s)| WrappedToken::new(t, Comment::default(), s))
        .collect();
    add_comments(&mut wrapped_tokens, input);
    Some(wrapped_tokens)
}
