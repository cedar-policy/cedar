use std::collections::HashMap;

use combine::Parser;
use smol_str::SmolStr;

use crate::SchemaFragment;

use self::{
    err::ParseErrors,
    lexer::get_tokens,
    parser::{parse_namespaces, TokenStream},
};

mod err;
mod lexer;
mod parser;

/// Main entry: Parse a schema fragment
pub fn parse_schema_fragment_from_str(input: &str) -> Result<SchemaFragment, ParseErrors> {
    let tokens = get_tokens(input)?;
    let (namespaces, _) = parse_namespaces().parse(TokenStream {
        token_spans: &tokens,
    })?;
    let mut map = HashMap::new();
    for (id, ns) in namespaces {
        if map.contains_key(&id) {
            return Err(ParseErrors::Other(SmolStr::new(format!(
                "duplicate namespace id: {}",
                id
            ))));
        }
        map.insert(id, ns);
    }
    Ok(SchemaFragment(map))
}
