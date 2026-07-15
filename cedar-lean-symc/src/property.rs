//! Properties of a policy-set, emitted as `theorem … := by sorry` statements
//! about the emitted `def policies` (and, for two-set properties, `policiesB`).

/// A property assertable about the emitted policy set(s).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Property {
    /// Every request is allowed.
    AlwaysAllows,
    /// Two policy sets reach the same decision on every request.
    Equivalent,
}

impl Property {
    /// Parse a property name as accepted on the CLI.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "always-allows" => Some(Property::AlwaysAllows),
            "equivalent" => Some(Property::Equivalent),
            _ => None,
        }
    }

    /// Whether this property compares two policy sets (`policies` vs `policiesB`).
    pub fn is_binary(self) -> bool {
        matches!(self, Property::Equivalent)
    }

    /// `∀` lives in the proposition, not as theorem binders, so the negation is
    /// a plain `¬ (∀ …)`.
    fn theorem(self) -> &'static str {
        match self {
            Property::AlwaysAllows => {
                "theorem policies_always_allows :\n    \
                 ∀ (req : Request) (es : Entities),\n      \
                 (isAuthorized req es policies).decision = .allow := by\n  sorry"
            }
            Property::Equivalent => {
                "theorem policies_equivalent :\n    \
                 ∀ (req : Request) (es : Entities),\n      \
                 (isAuthorized req es policies).decision\n        \
                 = (isAuthorized req es policiesB).decision := by\n  sorry"
            }
        }
    }
}

/// Emit the given properties as Lean theorems, in order.
pub fn emit_properties(props: &[Property]) -> String {
    let mut out = String::new();
    for p in props {
        out.push('\n');
        out.push_str(p.theorem());
        out.push('\n');
    }
    out
}
