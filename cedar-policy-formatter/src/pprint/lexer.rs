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

use crate::token::get_comment;

use super::token::{Comment, Token, WrappedToken};
use logos::Logos;

/// Tokenize the input, associating with each token a leading and trailing
/// comment if they are present. Also returns a string containing any comments
/// that may be present at the end of input after all tokens are consumed.
pub fn get_token_stream(
    input: &str,
) -> Option<(Vec<WrappedToken<'_>>, impl Iterator<Item = &str>)> {
    let mut tokens = Token::lexer(input).spanned();

    let Some(mut current_token) = tokens.next() else {
        // There are no tokens in the input, so any text that might be in the
        // input is the end-of-file comment.
        return Some((Vec::new(), get_comment(input)));
    };
    // The "leading comment" will be the text which appears between a token and
    // the prior token after a line break. Any text before the line break will
    // be the trailing comment for the prior token. There's no prior token for
    // the first token, so it gets all the text.
    let mut current_leading_comment = input.get(..current_token.1.start)?;

    // Loop over the remaining tokens, splitting the text between each pair of
    // tokens in leading and trailing comments.
    let mut wrapped_tokens = Vec::new();
    for next_token in tokens {
        let text_between_tokens = input.get(current_token.1.end..next_token.1.start)?;
        let (current_trailing_comment, next_leading_comment) = text_between_tokens
            .split_once('\n')
            .unwrap_or((text_between_tokens, ""));

        wrapped_tokens.push(WrappedToken::new(
            current_token.0.ok()?,
            current_token.1,
            Comment::new(current_leading_comment, current_trailing_comment),
        ));

        current_token = next_token;
        current_leading_comment = next_leading_comment;
    }

    // Get the text remaining after all tokens. Split this between the trailing
    // comment for the last token and the end-of-file comment.
    let text_after_last_token = input.get(current_token.1.end..)?;
    let (current_trailing_comment, end_of_file_comment) = text_after_last_token
        .split_once('\n')
        .unwrap_or((text_after_last_token, ""));

    wrapped_tokens.push(WrappedToken::new(
        current_token.0.ok()?,
        current_token.1,
        Comment::new(current_leading_comment, current_trailing_comment),
    ));

    Some((wrapped_tokens, get_comment(end_of_file_comment)))
}
