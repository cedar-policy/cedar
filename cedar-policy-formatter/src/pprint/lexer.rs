use super::token::{Comment, Token, WrappedToken};
use logos::Logos;

// Attach comments to tokens
fn add_comments(token_stream: &mut [WrappedToken], input: &str) {
    let mut i = 0;
    if token_stream.is_empty() {
        return;
    }
    let first_token = token_stream.first_mut().unwrap();
    let first_range = &first_token.span;
    if first_range.start > 0 {
        first_token.add_leading_comment(&input[..first_range.start]);
    }

    while i + 1 < token_stream.len() {
        let (curr_tokens, next_tokens) = token_stream.split_at_mut(i + 1);
        let curr_token = curr_tokens.last_mut().unwrap();
        let next_token = next_tokens.first_mut().unwrap();
        let curr_range = &curr_token.span;
        let next_range = &next_token.span;
        if curr_range.end == next_range.start {
            i += 1;
            continue;
        }
        let gap = &input[curr_range.end..next_range.start];
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
}

pub fn get_token_stream(input: &str) -> Vec<WrappedToken> {
    let mut wrapped_tokens: Vec<WrappedToken> = Token::lexer(input)
        .spanned()
        .map(|(t, s)| WrappedToken::new(t, Comment::default(), s))
        .collect();
    add_comments(&mut wrapped_tokens, input);
    wrapped_tokens
}
