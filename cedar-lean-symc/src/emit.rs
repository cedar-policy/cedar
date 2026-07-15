//! Emit Cedar Lean specification AST source from a Cedar Rust AST.
//!
//! The target is the abstract syntax defined in the `cedar-lean` package under
//! `Cedar/Spec/{Policy,Expr,Value,...}.lean`. Given a parsed [`ast::PolicySet`],
//! we walk the Rust AST and print the equivalent Lean term for each policy /
//! template.
//!
//! The mapping is intentionally 1:1 with the Lean `Cedar.Spec` datatypes:
//!
//! | Rust                                    | Lean (`Cedar.Spec`)                |
//! |-----------------------------------------|------------------------------------|
//! | `Effect::Permit` / `Forbid`             | `.permit` / `.forbid`              |
//! | `PrincipalOrResourceConstraint::*`      | `Scope.{any,eq,mem,is,isMem}`      |
//! | `ActionConstraint::{Any,Eq,In}`         | `.actionScope` / `.actionInAny`    |
//! | `ExprKind::*`                           | `Expr.*`                           |
//! | static policy                           | `Cedar.Spec.Policy`                |
//! | template (has slots)                    | `Cedar.Spec.Template`              |

use cedar_policy_core::ast::{
    self, ActionConstraint, BinaryOp, EntityReference, EntityType, EntityUID, Expr, ExprKind,
    Literal, Name, PatternElem, PrincipalOrResourceConstraint, SlotId, UnaryOp, Var,
};

use crate::error::{Error, Result};

/// Slot id string used by the Cedar Lean AST for the `?principal` slot.
const PRINCIPAL_SLOT: &str = "?principal";
/// Slot id string used by the Cedar Lean AST for the `?resource` slot.
const RESOURCE_SLOT: &str = "?resource";

/// Whether a scope constraint is being emitted as a concrete [`Scope`] (static
/// policy) or as a [`ScopeTemplate`] which permits template slots.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeMode {
    /// Emit `Cedar.Spec.Scope` (slots are an error).
    Concrete,
    /// Emit `Cedar.Spec.ScopeTemplate` (slots become `.slot "?..."`).
    Template,
}

/// The `import`/`open` preamble every emitted file begins with.
pub const PREAMBLE: &str = "import Cedar.Spec\n\nopen Cedar.Spec\n\n";

/// Emit a full single-policy-set file: preamble followed by the `def`s and the
/// `def policies : Policies` list.
pub fn emit_policyset(pset: &ast::PolicySet) -> Result<String> {
    Ok(format!("{PREAMBLE}{}", emit_defs(pset, &Names::default())?))
}

/// Identifier names for one policy-set's emitted `def`s, so multiple sets can
/// coexist in one file without collisions.
pub struct Names {
    /// Prefix for individual static-policy `def`s (e.g. `policy` → `policy0`).
    pub policy_prefix: &'static str,
    /// Prefix for individual template `def`s.
    pub template_prefix: &'static str,
    /// Name of the aggregate `Policies` list.
    pub list: &'static str,
}

impl Default for Names {
    fn default() -> Self {
        Names {
            policy_prefix: "policy",
            template_prefix: "template",
            list: "policies",
        }
    }
}

/// Emit the `def`s for a policy-set (no preamble): static policies as `Policy`,
/// templates as `Template`, then `def <list> : Policies := [...]`. Sorted by id.
pub fn emit_defs(pset: &ast::PolicySet, names: &Names) -> Result<String> {
    let mut out = String::new();

    // `templates()` yields only slot-bearing policies; `static_policies()` the
    // rest.
    let mut templates: Vec<&ast::Template> = pset.templates().collect();
    templates.sort_by(|a, b| a.id().as_ref().cmp(b.id().as_ref()));

    let mut statics: Vec<&ast::Policy> = pset.static_policies().collect();
    statics.sort_by(|a, b| a.id().as_ref().cmp(b.id().as_ref()));

    // Def names are positional (`<prefix><index>`) so two sets in one file never
    // collide; the real policy id is still emitted in the `Policy.id` field.
    let mut policy_idents: Vec<String> = Vec::with_capacity(statics.len());
    for (i, p) in statics.iter().enumerate() {
        let ident = format!("{}{i}", names.policy_prefix);
        out.push_str(&emit_static_policy(p, &ident)?);
        out.push_str("\n\n");
        policy_idents.push(ident);
    }
    for (i, t) in templates.iter().enumerate() {
        let ident = format!("{}{i}", names.template_prefix);
        out.push_str(&emit_template(t, &ident)?);
        out.push_str("\n\n");
    }

    // `Policies = List Policy`, so this collects only the static policies;
    // templates must be linked before they become `Policy` values.
    out.push_str(&format!(
        "def {} : Policies := [{}]\n",
        names.list,
        policy_idents.join(", ")
    ));

    Ok(out)
}

fn emit_static_policy(p: &ast::Policy, ident: &str) -> Result<String> {
    let id = p.id().as_ref();
    Ok(format!(
        "def {ident} : Policy :=\n  {body}",
        body = policy_body(
            Some(id),
            p.effect(),
            principal_scope(p.principal_constraint().as_inner(), ScopeMode::Concrete)?,
            action_scope(p.action_constraint())?,
            resource_scope(p.resource_constraint().as_inner(), ScopeMode::Concrete)?,
            p.non_scope_constraints(),
        )?,
    ))
}

fn emit_template(t: &ast::Template, ident: &str) -> Result<String> {
    // `Cedar.Spec.Template` has no `id` field, so pass `None` to `policy_body`.
    Ok(format!(
        "def {ident} : Template :=\n  {body}",
        body = policy_body(
            None,
            t.effect(),
            principal_scope(t.principal_constraint().as_inner(), ScopeMode::Template)?,
            action_scope(t.action_constraint())?,
            resource_scope(t.resource_constraint().as_inner(), ScopeMode::Template)?,
            t.non_scope_constraints(),
        )?,
    ))
}

/// Anonymous-constructor body shared by `Policy` and `Template`; `id` is
/// `Some` only for `Policy`, which has the leading `id` field.
fn policy_body(
    id: Option<&str>,
    effect: ast::Effect,
    principal_scope: String,
    action_scope: String,
    resource_scope: String,
    conditions: Option<&Expr>,
) -> Result<String> {
    let mut fields: Vec<String> = Vec::new();
    if let Some(id) = id {
        fields.push(lean_str(id));
    }
    fields.push(effect_str(effect).to_string());
    fields.push(principal_scope);
    fields.push(action_scope);
    fields.push(resource_scope);
    fields.push(conditions_str(conditions)?);
    Ok(format!("⟨ {} ⟩", fields.join(",\n    ")))
}

/// `Cedar.Spec.Effect`.
fn effect_str(effect: ast::Effect) -> &'static str {
    match effect {
        ast::Effect::Permit => ".permit",
        ast::Effect::Forbid => ".forbid",
    }
}

/// `Cedar.Spec.PrincipalScope` / `PrincipalScopeTemplate`.
fn principal_scope(c: &PrincipalOrResourceConstraint, mode: ScopeMode) -> Result<String> {
    Ok(format!(
        ".principalScope ({})",
        scope(c, mode, SlotId::principal())?
    ))
}

/// `Cedar.Spec.ResourceScope` / `ResourceScopeTemplate`.
fn resource_scope(c: &PrincipalOrResourceConstraint, mode: ScopeMode) -> Result<String> {
    Ok(format!(
        ".resourceScope ({})",
        scope(c, mode, SlotId::resource())?
    ))
}

/// `Cedar.Spec.Scope` / `ScopeTemplate`. `slot` is the slot a `Slot` reference
/// implies here (`?principal` in a principal scope, `?resource` in a resource).
fn scope(
    c: &PrincipalOrResourceConstraint,
    mode: ScopeMode,
    slot: SlotId,
) -> Result<String> {
    Ok(match c {
        PrincipalOrResourceConstraint::Any => ".any".to_string(),
        PrincipalOrResourceConstraint::Eq(r) => {
            format!(".eq ({})", entity_ref(r, mode, slot)?)
        }
        PrincipalOrResourceConstraint::In(r) => {
            format!(".mem ({})", entity_ref(r, mode, slot)?)
        }
        PrincipalOrResourceConstraint::Is(ety) => {
            format!(".is ({})", entity_type(ety)?)
        }
        PrincipalOrResourceConstraint::IsIn(ety, r) => {
            format!(".isMem ({}) ({})", entity_type(ety)?, entity_ref(r, mode, slot)?)
        }
    })
}

/// A scope entity reference. In `Template` mode it is wrapped in the
/// `EntityUIDOrSlot` constructors; in `Concrete` mode a slot is an error.
fn entity_ref(r: &EntityReference, mode: ScopeMode, slot: SlotId) -> Result<String> {
    match (r, mode) {
        (EntityReference::EUID(uid), ScopeMode::Concrete) => entity_uid(uid),
        (EntityReference::EUID(uid), ScopeMode::Template) => {
            Ok(format!(".entityUID ({})", entity_uid(uid)?))
        }
        (EntityReference::Slot(_), ScopeMode::Template) => {
            let name = if slot.is_principal() {
                PRINCIPAL_SLOT
            } else {
                RESOURCE_SLOT
            };
            Ok(format!(".slot {}", lean_str(name)))
        }
        (EntityReference::Slot(_), ScopeMode::Concrete) => Err(Error::Unsupported(
            "template slot found in a static policy scope".to_string(),
        )),
    }
}

/// `Cedar.Spec.ActionScope`.
fn action_scope(c: &ActionConstraint) -> Result<String> {
    Ok(match c {
        ActionConstraint::Any => ".actionScope .any".to_string(),
        ActionConstraint::Eq(uid) => format!(".actionScope (.eq ({}))", entity_uid(uid)?),
        // Cedar's `action in ...` (single euid or a list) is uniformly modeled
        // in the Lean AST as `actionInAny` over a list of euids.
        ActionConstraint::In(uids) => {
            let elems = uids
                .iter()
                .map(|u| entity_uid(u))
                .collect::<Result<Vec<_>>>()?
                .join(", ");
            format!(".actionInAny [{elems}]")
        }
        #[allow(unreachable_patterns)]
        _ => {
            return Err(Error::Unsupported(
                "unrepresentable action constraint (error node)".to_string(),
            ))
        }
    })
}

/// `Cedar.Spec.Conditions`. The Cedar parser already folds every `when`/`unless`
/// clause into one non-scope expression (`unless e` → `!e`), so we emit at most
/// one `⟨.when, _⟩` — equivalent to the Lean `Conditions.toExpr` fold.
fn conditions_str(conditions: Option<&Expr>) -> Result<String> {
    match conditions {
        None => Ok("[]".to_string()),
        Some(e) => Ok(format!("[⟨.when, {}⟩]", expr(e)?)),
    }
}

/// `Cedar.Spec.Expr`.
fn expr(e: &Expr) -> Result<String> {
    Ok(match e.expr_kind() {
        ExprKind::Lit(l) => format!(".lit ({})", literal(l)?),
        ExprKind::Var(v) => format!(".var {}", var(*v)),
        ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => format!(
            ".ite ({}) ({}) ({})",
            expr(test_expr)?,
            expr(then_expr)?,
            expr(else_expr)?
        ),
        ExprKind::And { left, right } => {
            format!(".and ({}) ({})", expr(left)?, expr(right)?)
        }
        ExprKind::Or { left, right } => {
            format!(".or ({}) ({})", expr(left)?, expr(right)?)
        }
        ExprKind::UnaryApp { op, arg } => {
            format!(".unaryApp ({}) ({})", unary_op(*op), expr(arg)?)
        }
        ExprKind::BinaryApp { op, arg1, arg2 } => format!(
            ".binaryApp ({}) ({}) ({})",
            binary_op(*op),
            expr(arg1)?,
            expr(arg2)?
        ),
        ExprKind::GetAttr { expr: e, attr } => {
            format!(".getAttr ({}) {}", expr(e)?, lean_str(attr))
        }
        ExprKind::HasAttr { expr: e, attr } => {
            format!(".hasAttr ({}) {}", expr(e)?, lean_str(attr))
        }
        // `like`/`is` carry data, so they are unary ops in the Lean AST.
        ExprKind::Like { expr: e, pattern } => format!(
            ".unaryApp (.like [{}]) ({})",
            pattern
                .iter()
                .map(pat_elem)
                .collect::<Vec<_>>()
                .join(", "),
            expr(e)?
        ),
        ExprKind::Is { expr: e, entity_type: ety } => {
            format!(".unaryApp (.is ({})) ({})", entity_type(ety)?, expr(e)?)
        }
        ExprKind::Set(elems) => {
            let elems = elems
                .iter()
                .map(expr)
                .collect::<Result<Vec<_>>>()?
                .join(", ");
            format!(".set [{elems}]")
        }
        ExprKind::Record(fields) => {
            // `Record` is a `BTreeMap`, so iteration is already sorted by attr.
            let entries = fields
                .iter()
                .map(|(a, v)| Ok(format!("({}, {})", lean_str(a), expr(v)?)))
                .collect::<Result<Vec<_>>>()?
                .join(", ");
            format!(".record [{entries}]")
        }
        ExprKind::ExtensionFunctionApp { fn_name, args } => {
            let args = args
                .iter()
                .map(expr)
                .collect::<Result<Vec<_>>>()?
                .join(", ");
            format!(".call ({}) [{args}]", ext_fun(fn_name)?)
        }
        ExprKind::Slot(_) => {
            return Err(Error::Unsupported(
                "template slot used outside of a policy scope is not representable in Cedar.Spec.Expr"
                    .to_string(),
            ))
        }
        ExprKind::Unknown(_) => {
            return Err(Error::Unsupported(
                "partial-evaluation `unknown` is not part of the Cedar.Spec AST".to_string(),
            ))
        }
        // The `tolerant-ast` `Error` variant is not built by the default parser.
        #[allow(unreachable_patterns)]
        _ => {
            return Err(Error::Unsupported(
                "unrepresentable expression (error node)".to_string(),
            ))
        }
    })
}

/// `Cedar.Spec.Var`.
fn var(v: Var) -> &'static str {
    match v {
        Var::Principal => ".principal",
        Var::Action => ".action",
        Var::Resource => ".resource",
        Var::Context => ".context",
    }
}

/// `Cedar.Spec.UnaryOp`.
fn unary_op(op: UnaryOp) -> &'static str {
    match op {
        UnaryOp::Not => ".not",
        UnaryOp::Neg => ".neg",
        UnaryOp::IsEmpty => ".isEmpty",
    }
    // `like`/`is` are data-carrying and handled in `expr`, not here.
}

/// `Cedar.Spec.BinaryOp`.
fn binary_op(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Eq => ".eq",
        BinaryOp::In => ".mem",
        BinaryOp::HasTag => ".hasTag",
        BinaryOp::GetTag => ".getTag",
        BinaryOp::Less => ".less",
        BinaryOp::LessEq => ".lessEq",
        BinaryOp::Add => ".add",
        BinaryOp::Sub => ".sub",
        BinaryOp::Mul => ".mul",
        BinaryOp::Contains => ".contains",
        BinaryOp::ContainsAll => ".containsAll",
        BinaryOp::ContainsAny => ".containsAny",
    }
}

/// `Cedar.Spec.Prim`.
fn literal(l: &Literal) -> Result<String> {
    Ok(match l {
        Literal::Bool(b) => format!(".bool {b}"),
        // A raw literal suffices: `Int64`'s `OfNat`/`Neg` coercions accept it,
        // avoiding the proof `Int64.ofIntChecked` would demand.
        Literal::Long(i) => format!(".int {}", lean_int(*i)),
        Literal::String(s) => format!(".string {}", lean_str(s)),
        Literal::EntityUID(uid) => format!(".entityUID ({})", entity_uid(uid)?),
    })
}

/// `Cedar.Spec.EntityUID` — `⟨ty, eid⟩`.
fn entity_uid(uid: &EntityUID) -> Result<String> {
    Ok(format!(
        "⟨{}, {}⟩",
        entity_type(uid.entity_type())?,
        lean_str(uid.eid().as_ref())
    ))
}

/// `Cedar.Spec.EntityType` (an alias for `Name`).
fn entity_type(ety: &EntityType) -> Result<String> {
    match ety {
        EntityType::EntityType(name) => Ok(name_lit(name)),
        #[allow(unreachable_patterns)]
        _ => Err(Error::Unsupported(
            "unrepresentable entity type (error node)".to_string(),
        )),
    }
}

/// `Cedar.Spec.Name` — `⟨id, [path...]⟩` where `id` is the basename and `path`
/// is the namespace components in order.
fn name_lit(name: &Name) -> String {
    let id = name.basename_as_ref().as_ref();
    // `namespace_components` lives on `InternalName`; `Name: AsRef<InternalName>`.
    let path = name
        .as_ref()
        .namespace_components()
        .map(|c| lean_str(c.as_ref()))
        .collect::<Vec<_>>()
        .join(", ");
    format!("⟨{}, [{}]⟩", lean_str(id), path)
}

/// `Cedar.Spec.ExtFun`.
///
/// Cedar extension-function names map 1:1 onto the Lean `ExtFun` constructors.
fn ext_fun(name: &Name) -> Result<String> {
    let s = name.to_string();
    let ctor = match s.as_str() {
        "decimal" => ".decimal",
        "lessThan" => ".lessThan",
        "lessThanOrEqual" => ".lessThanOrEqual",
        "greaterThan" => ".greaterThan",
        "greaterThanOrEqual" => ".greaterThanOrEqual",
        "ip" => ".ip",
        "isIpv4" => ".isIpv4",
        "isIpv6" => ".isIpv6",
        "isLoopback" => ".isLoopback",
        "isMulticast" => ".isMulticast",
        "isInRange" => ".isInRange",
        "datetime" => ".datetime",
        "duration" => ".duration",
        "offset" => ".offset",
        "durationSince" => ".durationSince",
        "toDate" => ".toDate",
        "toTime" => ".toTime",
        "toMilliseconds" => ".toMilliseconds",
        "toSeconds" => ".toSeconds",
        "toMinutes" => ".toMinutes",
        "toHours" => ".toHours",
        "toDays" => ".toDays",
        other => {
            return Err(Error::Unsupported(format!(
                "unknown extension function `{other}` (no Cedar.Spec.ExtFun constructor)"
            )))
        }
    };
    Ok(ctor.to_string())
}

/// A single `Cedar.Spec.PatElem` for a `like` pattern.
fn pat_elem(e: &PatternElem) -> String {
    match e {
        PatternElem::Wildcard => ".star".to_string(),
        PatternElem::Char(c) => format!(".justChar {}", lean_char(*c)),
    }
}

// ----- lexical helpers -----

/// Render an integer as a Lean term. Negative values are wrapped in parens so
/// they compose correctly as an argument (e.g. `.int (-5)`).
fn lean_int(i: i64) -> String {
    if i < 0 {
        format!("({i})")
    } else {
        i.to_string()
    }
}

/// Render a Rust string as a Lean string literal, escaping as needed.
fn lean_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        push_escaped(&mut out, c);
    }
    out.push('"');
    out
}

/// Render a Rust `char` as a Lean character literal.
fn lean_char(c: char) -> String {
    let mut out = String::new();
    out.push('\'');
    if c == '\'' {
        out.push_str("\\'");
    } else {
        push_escaped(&mut out, c);
    }
    out.push('\'');
    out
}

/// Escape a single character for inclusion in a Lean string/char literal.
/// Lean uses the same core escapes as Rust for these cases.
fn push_escaped(out: &mut String, c: char) {
    match c {
        '"' => out.push_str("\\\""),
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
        c => out.push(c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lean_int_wraps_negatives_in_parens() {
        assert_eq!(lean_int(0), "0");
        assert_eq!(lean_int(42), "42");
        assert_eq!(lean_int(-5), "(-5)");
        assert_eq!(lean_int(i64::MIN), "(-9223372036854775808)");
        assert_eq!(lean_int(i64::MAX), "9223372036854775807");
    }

    #[test]
    fn lean_str_escapes_specials() {
        assert_eq!(lean_str("plain"), r#""plain""#);
        assert_eq!(lean_str("a\"b"), r#""a\"b""#);
        assert_eq!(lean_str("a\\b"), r#""a\\b""#);
        assert_eq!(lean_str("tab\tnl\ncr\r"), r#""tab\tnl\ncr\r""#);
        // BEL (0x07) is a control char emitted as a `\u` escape.
        assert_eq!(lean_str("\u{7}"), "\"\\u0007\"");
        // Unicode above the control range passes through unescaped.
        assert_eq!(lean_str("café😀"), "\"café😀\"");
    }

    #[test]
    fn lean_char_escapes_specials() {
        assert_eq!(lean_char('a'), "'a'");
        assert_eq!(lean_char('\''), r"'\''");
        assert_eq!(lean_char('\\'), r"'\\'");
        assert_eq!(lean_char('\n'), r"'\n'");
        assert_eq!(lean_char('\u{7}'), "'\\u0007'");
    }
}
