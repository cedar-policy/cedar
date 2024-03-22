use cedar_policy_core::ast::{Eid, EntityUID, Name};
use cedar_policy_core::parser::err::ParseErrors;
use cedar_policy_core::FromNormalizedStr;
use itertools::Itertools;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse::Parse, punctuated::Punctuated, Token};
use syn::{parse_macro_input, Ident, LitStr};

#[derive(Clone)]
struct Input {
    path: Vec<Ident>,
    id: LitStr,
}

impl Parse for Input {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let path = Punctuated::<Ident, Token![::]>::parse_separated_nonempty(input)?;
        let _: Token![,] = input.parse()?;
        let id: LitStr = input.parse()?;
        Ok(Self {
            path: path.into_iter().collect(),
            id,
        })
    }
}

impl TryFrom<Input> for EntityUID {
    type Error = ParseErrors;
    fn try_from(value: Input) -> Result<Self, Self::Error> {
        let name = Name::from_normalized_str(&value.path.into_iter().join("::"))?;
        let eid = Eid::new(value.id.value());
        Ok(Self::from_components(name, eid))
    }
}

#[proc_macro]
pub fn euid(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as Input);
    let euid: EntityUID = match input.try_into() {
        Ok(euid) => euid,
        Err(_) => panic!("invalid euid"),
    };
    let euid_str = euid.to_string();
    quote! { #euid_str.parse().unwrap() }.into()
}

#[test]
fn tests() {
    let t = trybuild::TestCases::new();
    t.pass("tests/pass.rs");
    //t.compile_fail("tests/fail.rs");
}
