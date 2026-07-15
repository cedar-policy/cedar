//! `cedar-lean-symc`: transpile a Cedar policy-set (as text) into the equivalent
//! **Cedar Lean AST** source.
//!
//! The output is Lean source that reconstructs each policy as a value of the
//! `Cedar.Spec.Policy` (or `Cedar.Spec.Template`) datatype defined in the
//! `cedar-lean` package. This lets a Cedar policy written in concrete syntax be
//! dropped directly into the Lean development (e.g. for proofs or unit tests)
//! without hand-translation.
//!
//! ```
//! let lean = cedar_lean_symc::policyset_to_lean(
//!     "permit(principal, action, resource) when { resource.isPublic };",
//! )
//! .unwrap();
//! assert!(lean.contains("def policy0 : Policy :="));
//! ```

mod emit;
mod error;
mod property;

pub use error::{Error, Result};
pub use property::Property;

use cedar_policy_core::parser;

/// Parse a Cedar policy-set from `text` and emit the equivalent Cedar Lean AST
/// as a string of Lean source (one `def` per policy / template).
pub fn policyset_to_lean(text: &str) -> Result<String> {
    let pset = parser::parse_policyset(text).map_err(Box::new)?;
    emit::emit_policyset(&pset)
}

/// Emit the Cedar Lean AST for an already-parsed [`cedar_policy_core::ast::PolicySet`].
pub fn policyset_ast_to_lean(pset: &cedar_policy_core::ast::PolicySet) -> Result<String> {
    emit::emit_policyset(pset)
}

/// Like [`policyset_to_lean`], but also appends a stubbed Lean theorem for each
/// requested [`Property`] of the emitted `policies`.
///
/// Errors if any requested property is binary (compares two sets); use
/// [`policysets_to_lean_with_properties`] for those.
pub fn policyset_to_lean_with_properties(text: &str, props: &[Property]) -> Result<String> {
    if let Some(p) = props.iter().find(|p| p.is_binary()) {
        return Err(Error::Unsupported(format!(
            "property {p:?} compares two policy sets; a second policy set is required"
        )));
    }
    let mut out = policyset_to_lean(text)?;
    out.push_str(&property::emit_properties(props));
    Ok(out)
}

/// Emit two policy sets — `def policies` and `def policiesB` — followed by a
/// stubbed theorem for each requested [`Property`] (which may compare the two).
pub fn policysets_to_lean_with_properties(
    text: &str,
    text_b: &str,
    props: &[Property],
) -> Result<String> {
    let pset = parser::parse_policyset(text).map_err(Box::new)?;
    let pset_b = parser::parse_policyset(text_b).map_err(Box::new)?;

    let names_b = emit::Names {
        policy_prefix: "policyB",
        template_prefix: "templateB",
        list: "policiesB",
    };

    let mut out = String::from(emit::PREAMBLE);
    out.push_str(&emit::emit_defs(&pset, &emit::Names::default())?);
    out.push('\n');
    out.push_str(&emit::emit_defs(&pset_b, &names_b)?);
    out.push_str(&property::emit_properties(props));
    Ok(out)
}
