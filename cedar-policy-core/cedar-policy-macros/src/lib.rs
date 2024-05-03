use cedar_policy_core::ast::{Eid, EntityUID, Id, Name};
use cedar_policy_core::FromNormalizedStr;
use proc_macro::TokenStream;
use proc_macro_error::{abort, proc_macro_error};
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

#[proc_macro_error]
#[proc_macro]
pub fn euid(input_stream: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input_stream as Input);
    // We only need to check if entity type components (i.e., `Id`s) are valid
    // or not because `eid` is a valid string after successful execution of the
    // statement above
    let mut ids: Vec<Id> = Vec::new();
    for id in input.path {
        match Id::from_normalized_str(&id.to_string()) {
            Ok(id) => {
                ids.push(id);
            }
            // We abort after the first parsing error is encountered
            // This is not ideal because users may want to see all errors
            // reported
            // For instance, we should report both `Москва` and `東京` are
            // invalid identifiers in `euid!(Москва::foo::東京)`.
            Err(_) => abort!(id.span(), "invalid identifier: {}", id),
        }
    }
    // PANIC SAFETY: using `parse_separated_nonempty` above ensures that there is at least one id
    #[allow(clippy::unwrap_used)]
    let (basename, path) = ids.split_last().unwrap();
    let euid: EntityUID = EntityUID::from_components(
        Name::new(basename.clone(), path.into_iter().cloned(), None),
        Eid::new(input.id.value()),
        None,
    );
    let euid_str = euid.to_string();
    // PANIC SAFETY: `#euid_str` should parse
    // Note that this comment is used to pass panic checks
    // Users still need to annotate macro call sites to get rid of
    // `clippy::unwrap_used`
    quote! {
        crate::EntityUid::from_str(#euid_str).unwrap()
    }
    .into()
}
