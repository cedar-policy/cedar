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

//! Front-end neutral rendering of facts and residuals.
//!
//! Output is a list of [`Line`]s made of [`Span`]s that carry a semantic
//! [`Style`] plus the [`SlotId`] they display (`slot`) or depend on
//! (`marks`). Front ends map styles to colors and use `slot`/`marks` for
//! selection, highlighting, and click targets.

use cedar_policy::pst::{self, BinaryOp, Expr, UnaryOp, Var};
use cedar_policy_core::ast::{EntityUID, Literal, PolicyID, Value, ValueKind};
use cedar_policy_core::validator::types::Type;
use smol_str::SmolStr;
use std::collections::BTreeMap;

use crate::analysis::{atom, TypeEnv};
use crate::eval::{effect_str, Evaluation, Status};
use crate::facts::{record_type, AttrFact, EntityFacts, Facts, SlotId};
use crate::project::Project;
use crate::values::{self, can_have_parents, namespace_of, record_key};

/// Semantic token styles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Style {
    Plain,
    /// `permit`, `when`, `instance`, `in`, ...
    Keyword,
    /// Entity type names (`PhotoApp::User::`).
    EntityType,
    /// String literals and entity ids.
    Str,
    /// Variables, attribute and field names.
    Ident,
    /// Booleans, numbers, extension values.
    Literal,
    /// `// String`
    Comment,
    /// An unknown that blocks progress, e.g. an entity id or its parents.
    UnknownStrong,
    /// An unknown attribute value.
    UnknownWeak,
    /// De-emphasized text.
    Muted,
}

/// Stable lowercase name for a style, e.g. for CSS classes.
pub fn style_name(s: Style) -> &'static str {
    match s {
        Style::Plain => "plain",
        Style::Keyword => "keyword",
        Style::EntityType => "type",
        Style::Str => "str",
        Style::Ident => "ident",
        Style::Literal => "lit",
        Style::Comment => "comment",
        Style::UnknownStrong => "unknown-strong",
        Style::UnknownWeak => "unknown-weak",
        Style::Muted => "muted",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub text: String,
    pub style: Style,
    /// The fact this span displays (and edits).
    pub slot: Option<SlotId>,
    /// Facts this span depends on (residual atoms).
    pub marks: Vec<SlotId>,
}

impl Span {
    pub fn new(text: impl Into<String>, style: Style) -> Self {
        Self {
            text: text.into(),
            style,
            slot: None,
            marks: vec![],
        }
    }

    pub fn width(&self) -> usize {
        self.text.chars().count()
    }
}

/// Marker for a policy entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMark {
    Residual,
    Satisfied,
    NotSatisfied,
    Error,
}

impl PolicyMark {
    pub fn symbol(self) -> &'static str {
        match self {
            PolicyMark::Residual => "◆",
            PolicyMark::Satisfied => "✓",
            PolicyMark::NotSatisfied => "×",
            PolicyMark::Error => "!",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gutter {
    None,
    /// No gutter column at all: the text starts where gutter marks go.
    Bare,
    /// This line shows a fact that a relevant policy still needs.
    Needed,
    Policy(PolicyMark),
}

#[derive(Debug, Clone)]
pub struct Line {
    pub gutter: Gutter,
    pub spans: Vec<Span>,
    /// Render the whole line de-emphasized.
    pub dim: bool,
    /// The policy this line is the header of.
    pub policy: Option<PolicyID>,
}

impl Line {
    pub fn new(spans: Vec<Span>) -> Self {
        Self {
            gutter: Gutter::None,
            spans,
            dim: false,
            policy: None,
        }
    }

    pub fn text(&self) -> String {
        self.spans.iter().map(|s| s.text.as_str()).collect()
    }
}

fn sp(text: impl Into<String>, style: Style) -> Span {
    Span::new(text, style)
}

fn with_slot(mut spans: Vec<Span>, slot: &SlotId) -> Vec<Span> {
    for s in &mut spans {
        s.slot = Some(slot.clone());
    }
    spans
}

/// Spans for an entity uid, optionally dropping a namespace prefix.
pub fn uid_spans(uid: &EntityUID, strip_ns: Option<&str>) -> Vec<Span> {
    let ty = uid.entity_type().to_string();
    let ty = match strip_ns {
        Some(ns) => ty
            .strip_prefix(&format!("{ns}::"))
            .map(str::to_string)
            .unwrap_or(ty),
        None => ty,
    };
    vec![
        sp(format!("{ty}::"), Style::EntityType),
        sp(format!("\"{}\"", uid.eid().escaped()), Style::Str),
    ]
}

/// Spans for a value in Cedar syntax.
pub fn value_spans(v: &Value) -> Vec<Span> {
    let mut out = Vec::new();
    push_value(v, &mut out);
    out
}

fn push_value(v: &Value, out: &mut Vec<Span>) {
    match &v.value {
        ValueKind::Lit(Literal::String(s)) => {
            out.push(sp(format!("\"{}\"", s.escape_debug()), Style::Str))
        }
        ValueKind::Lit(Literal::EntityUID(u)) => out.extend(uid_spans(u, None)),
        ValueKind::Lit(l) => out.push(sp(l.to_string(), Style::Literal)),
        ValueKind::Set(s) => {
            out.push(sp("[", Style::Plain));
            let mut items: Vec<&Value> = s.iter().collect();
            items.sort_by_key(|v| values::value_to_string(v));
            for (i, e) in items.into_iter().enumerate() {
                if i > 0 {
                    out.push(sp(", ", Style::Plain));
                }
                push_value(e, out);
            }
            out.push(sp("]", Style::Plain));
        }
        ValueKind::Record(r) => {
            out.push(sp("{", Style::Plain));
            for (i, (k, e)) in r.iter().enumerate() {
                if i > 0 {
                    out.push(sp(", ", Style::Plain));
                }
                out.push(sp(record_key(k), Style::Ident));
                out.push(sp(": ", Style::Plain));
                push_value(e, out);
            }
            out.push(sp("}", Style::Plain));
        }
        ValueKind::ExtensionValue(_) => out.push(sp(v.to_string(), Style::Literal)),
    }
}

// ---------------------------------------------------------------------------
// Facts

const IND: &str = "  ";

fn attr_value_spans(f: &AttrFact) -> Vec<Span> {
    match f {
        AttrFact::Value(v) => value_spans(v),
        AttrFact::Unknown => vec![sp("?", Style::UnknownWeak)],
        AttrFact::UnknownExistence => vec![sp("unknown", Style::UnknownWeak)],
        AttrFact::Absent => vec![sp("absent", Style::UnknownWeak)],
        AttrFact::Record(_) => vec![sp("{..}", Style::Plain)],
    }
}

/// Render the attribute block of a record (context or entity attributes).
fn record_lines(
    m: &BTreeMap<SmolStr, AttrFact>,
    ty: &Type,
    depth: usize,
    mk_slot: &dyn Fn(Vec<SmolStr>) -> SlotId,
    prefix: &mut Vec<SmolStr>,
    eval: Option<&Evaluation>,
    out: &mut Vec<Line>,
) {
    let Type::Record { attrs, .. } = ty else {
        return;
    };
    let indent = IND.repeat(depth);
    for (k, f) in m {
        let Some(aty) = attrs.get_attr(k) else {
            continue;
        };
        prefix.push(k.clone());
        let slot = mk_slot(prefix.clone());
        let mut spans = vec![
            sp(indent.clone(), Style::Plain),
            sp(record_key(k), Style::Ident),
        ];
        if !aty.is_required {
            spans.push(sp("?", Style::Muted));
        }
        spans.push(sp(": ", Style::Plain));
        match f {
            AttrFact::Record(sub) => {
                let mut open = vec![sp("{", Style::Plain)];
                if !aty.is_required {
                    open = with_slot(open, &slot);
                }
                spans.extend(open);
                out.push(finish_fact_line(spans, eval));
                record_lines(sub, &aty.attr_type, depth + 1, mk_slot, prefix, eval, out);
                out.push(Line::new(vec![sp(format!("{indent}}},"), Style::Plain)]));
            }
            _ => {
                spans.extend(with_slot(attr_value_spans(f), &slot));
                spans.push(sp(",", Style::Plain));
                spans.push(sp(
                    format!("  // {}", values::type_name(&aty.attr_type)),
                    Style::Comment,
                ));
                out.push(finish_fact_line(spans, eval));
            }
        }
        prefix.pop();
    }
}

fn finish_fact_line(spans: Vec<Span>, eval: Option<&Evaluation>) -> Line {
    let needed = eval.is_some_and(|e| {
        spans
            .iter()
            .filter_map(|s| s.slot.as_ref())
            .any(|s| e.is_needed(s))
    });
    let mut l = Line::new(spans);
    if needed {
        l.gutter = Gutter::Needed;
    }
    l
}

/// Render the facts pane.
pub fn render_facts(project: &Project, facts: &Facts, eval: Option<&Evaluation>) -> Vec<Line> {
    let schema = project.vschema();
    let mut out = Vec::new();
    out.push(Line::new(vec![
        sp("request", Style::Keyword),
        sp(" {", Style::Plain),
    ]));

    let puid = |u: &crate::facts::PartialUid| -> Vec<Span> {
        match u.uid() {
            Some(uid) => uid_spans(&uid, None),
            None => vec![
                sp(format!("{}::", u.ty), Style::EntityType),
                sp("?", Style::UnknownStrong),
            ],
        }
    };
    let field = |name: &str, value: Vec<Span>, slot: SlotId| -> Line {
        let mut spans = vec![
            sp(IND, Style::Plain),
            sp(name, Style::Plain),
            sp(format!(":{}", " ".repeat(10 - name.len())), Style::Plain),
        ];
        spans.extend(with_slot(value, &slot));
        spans.push(sp(",", Style::Plain));
        finish_fact_line(spans, eval)
    };
    out.push(field(
        "principal",
        puid(&facts.principal),
        SlotId::Principal,
    ));
    out.push(field(
        "action",
        uid_spans(&facts.action, None),
        SlotId::Action,
    ));
    out.push(field("resource", puid(&facts.resource), SlotId::Resource));

    if let Some(ty) = schema.context_type(&facts.action) {
        out.push(Line::new(vec![
            sp(IND, Style::Plain),
            sp("context", Style::Plain),
            sp(": {", Style::Plain),
        ]));
        record_lines(
            &facts.context,
            ty,
            2,
            &|p| SlotId::Context(p),
            &mut vec![],
            eval,
            &mut out,
        );
        out.push(Line::new(vec![sp(format!("{IND}}}"), Style::Plain)]));
    }
    out.push(Line::new(vec![sp("};", Style::Plain)]));
    out.push(Line::new(vec![]));

    if facts.entities.is_empty() {
        out.push(Line::new(vec![sp(
            "// no entities referenced yet",
            Style::Comment,
        )]));
        return out;
    }

    let mut by_ns: BTreeMap<Option<String>, Vec<(&EntityUID, &EntityFacts)>> = BTreeMap::new();
    for (uid, ent) in &facts.entities {
        by_ns
            .entry(namespace_of(uid.entity_type()))
            .or_default()
            .push((uid, ent));
    }
    for (ns, mut ents) in by_ns {
        ents.sort_by_key(|(u, _)| (u.entity_type().to_string(), u.eid().escaped()));
        let depth = if ns.is_some() { 1 } else { 0 };
        if let Some(ns) = &ns {
            out.push(Line::new(vec![
                sp("namespace", Style::Keyword),
                sp(" ", Style::Plain),
                sp(ns.clone(), Style::Ident),
                sp(" {", Style::Plain),
            ]));
        }
        for (uid, ent) in ents {
            let indent = IND.repeat(depth);
            let mut head = vec![
                sp(indent.clone(), Style::Plain),
                sp("instance", Style::Keyword),
                sp(" ", Style::Plain),
            ];
            head.extend(uid_spans(uid, ns.as_deref()));
            if can_have_parents(uid.entity_type(), schema) {
                head.push(sp(" ", Style::Plain));
                head.push(sp("in", Style::Keyword));
                head.push(sp(" ", Style::Plain));
                let pspans = match &ent.parents {
                    None => vec![sp("?", Style::UnknownStrong)],
                    Some(ps) => {
                        let mut v = vec![sp("[", Style::Plain)];
                        for (i, p) in ps.iter().enumerate() {
                            if i > 0 {
                                v.push(sp(", ", Style::Plain));
                            }
                            v.extend(uid_spans(p, None));
                        }
                        v.push(sp("]", Style::Plain));
                        v
                    }
                };
                head.extend(with_slot(pspans, &SlotId::Parents(uid.clone())));
            }
            let et = schema.get_entity_type(uid.entity_type());
            let has_tags = et.is_some_and(|t| t.tag_type().is_some());
            let tail = |spans: &mut Vec<Span>| {
                if has_tags {
                    spans.push(sp(" ", Style::Plain));
                    spans.push(sp("tags", Style::Keyword));
                    spans.push(sp(" ", Style::Plain));
                    let tspans = match &ent.tags {
                        None => vec![sp("?", Style::UnknownStrong)],
                        Some(t) => {
                            let mut v = vec![sp("{", Style::Plain)];
                            for (i, (k, f)) in t.iter().enumerate() {
                                if i > 0 {
                                    v.push(sp(", ", Style::Plain));
                                }
                                v.push(sp(format!("\"{}\"", k.escape_debug()), Style::Str));
                                v.push(sp(": ", Style::Plain));
                                v.extend(attr_value_spans(f));
                            }
                            v.push(sp(", ..}", Style::Plain));
                            v
                        }
                    };
                    spans.extend(with_slot(tspans, &SlotId::Tags(uid.clone())));
                }
                spans.push(sp(";", Style::Plain));
            };
            if ent.attrs.is_empty() {
                head.push(sp(" {}", Style::Plain));
                tail(&mut head);
                out.push(finish_fact_line(head, eval));
                continue;
            }
            head.push(sp(" {", Style::Plain));
            out.push(finish_fact_line(head, eval));
            if let Some(et) = et {
                let ty = record_type(et.attributes());
                record_lines(
                    &ent.attrs,
                    &ty,
                    depth + 1,
                    &|p| SlotId::Attr(uid.clone(), p),
                    &mut vec![],
                    eval,
                    &mut out,
                );
            }
            let mut close = vec![sp(format!("{indent}}}"), Style::Plain)];
            tail(&mut close);
            out.push(finish_fact_line(close, eval));
        }
        if ns.is_some() {
            out.push(Line::new(vec![sp("}", Style::Plain)]));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Residual expressions

/// A token in a breakable expression.
#[derive(Debug, Clone)]
pub enum Tok {
    Span(Span),
    /// A space that may become a line break.
    Break,
}

const P_IF: u8 = 0;
const P_OR: u8 = 1;
const P_AND: u8 = 2;
const P_REL: u8 = 3;
const P_ADD: u8 = 4;
const P_MUL: u8 = 5;
const P_UNARY: u8 = 6;
const P_MEMBER: u8 = 7;
const P_PRIMARY: u8 = 8;

/// Precedence of an expression, for parenthesization.
fn prec(e: &Expr) -> u8 {
    match e {
        Expr::Literal(pst::Literal::Long(n)) if *n < 0 => P_UNARY,
        Expr::IfThenElse { .. } => P_IF,
        Expr::BinaryOp { op, .. } => match op {
            BinaryOp::Or => P_OR,
            BinaryOp::And => P_AND,
            BinaryOp::Eq
            | BinaryOp::NotEq
            | BinaryOp::Less
            | BinaryOp::LessEq
            | BinaryOp::Greater
            | BinaryOp::GreaterEq
            | BinaryOp::In => P_REL,
            BinaryOp::Add | BinaryOp::Sub => P_ADD,
            BinaryOp::Mul => P_MUL,
            _ => P_MEMBER,
        },
        Expr::HasAttr { .. } | Expr::Like { .. } | Expr::Is { .. } => P_REL,
        Expr::UnaryOp { op, .. } => match op {
            UnaryOp::Not | UnaryOp::Neg => P_UNARY,
            // Extension constructors are function calls: `ip("...")`.
            UnaryOp::Ip | UnaryOp::Decimal | UnaryOp::Datetime | UnaryOp::Duration => P_PRIMARY,
            _ => P_MEMBER,
        },
        Expr::GetAttr { .. } => P_MEMBER,
        _ => P_PRIMARY,
    }
}

struct Printer<'a> {
    toks: Vec<Tok>,
    marks: Vec<SlotId>,
    env: TypeEnv<'a>,
}

impl Printer<'_> {
    fn emit(&mut self, text: impl Into<String>, style: Style) {
        self.toks.push(Tok::Span(Span {
            text: text.into(),
            style,
            slot: None,
            marks: self.marks.clone(),
        }));
    }

    fn brk(&mut self) {
        self.toks.push(Tok::Break);
    }

    fn binop(&mut self, l: &Expr, lp: u8, op: &str, r: &Expr, rp: u8) {
        self.expr(l, lp);
        let style = if op.chars().all(char::is_alphabetic) {
            Style::Keyword
        } else {
            Style::Plain
        };
        self.emit(format!(" {op}"), style);
        self.brk();
        self.expr(r, rp);
    }

    /// `recv.name(args)`
    fn method(&mut self, recv: &Expr, name: &str, args: &[&Expr]) {
        self.expr(recv, P_MEMBER);
        self.emit(format!(".{name}("), Style::Plain);
        for (i, a) in args.iter().enumerate() {
            if i > 0 {
                self.emit(", ", Style::Plain);
            }
            self.expr(a, P_IF);
        }
        self.emit(")", Style::Plain);
    }

    fn attr(&mut self, a: &SmolStr) {
        if record_key(a) == a.as_str() {
            self.emit(".", Style::Plain);
            self.emit(a.to_string(), Style::Ident);
        } else {
            self.emit("[", Style::Plain);
            self.emit(format!("\"{}\"", a.escape_debug()), Style::Str);
            self.emit("]", Style::Plain);
        }
    }

    fn expr(&mut self, e: &Expr, min: u8) {
        let paren = prec(e) < min;
        if paren {
            self.emit("(", Style::Plain);
        }
        let marked = atom(e, self.env).map(|n| n.slot);
        if let Some(s) = &marked {
            self.marks.push(s.clone());
        }
        self.expr_inner(e);
        if marked.is_some() {
            self.marks.pop();
        }
        if paren {
            self.emit(")", Style::Plain);
        }
    }

    fn expr_inner(&mut self, e: &Expr) {
        match e {
            Expr::Literal(l) => match l {
                pst::Literal::Bool(b) => self.emit(b.to_string(), Style::Literal),
                pst::Literal::Long(n) => self.emit(n.to_string(), Style::Literal),
                pst::Literal::String(s) => {
                    self.emit(format!("\"{}\"", s.escape_debug()), Style::Str)
                }
                pst::Literal::EntityUID(u) => match crate::analysis::ast_uid(u) {
                    Some(uid) => {
                        for s in uid_spans(&uid, None) {
                            self.emit(s.text, s.style);
                        }
                    }
                    None => self.emit(u.to_string(), Style::Str),
                },
                _ => self.emit(e.to_string(), Style::Literal),
            },
            Expr::Var(v) => self.emit(
                match v {
                    Var::Principal => "principal",
                    Var::Action => "action",
                    Var::Resource => "resource",
                    Var::Context => "context",
                },
                Style::Ident,
            ),
            Expr::ResidualError => self.emit("error", Style::Muted),
            Expr::IfThenElse {
                cond,
                then_expr,
                else_expr,
            } => {
                self.emit("if ", Style::Keyword);
                self.expr(cond, P_IF);
                self.emit(" then", Style::Keyword);
                self.brk();
                self.expr(then_expr, P_IF);
                self.emit(" else", Style::Keyword);
                self.brk();
                self.expr(else_expr, P_IF);
            }
            Expr::UnaryOp { op, expr } => match op {
                UnaryOp::Not => {
                    self.emit("!", Style::Plain);
                    self.expr(expr, P_UNARY);
                }
                UnaryOp::Neg => {
                    self.emit("-", Style::Plain);
                    self.expr(expr, P_UNARY);
                }
                UnaryOp::Ip | UnaryOp::Decimal | UnaryOp::Datetime | UnaryOp::Duration => {
                    self.emit(format!("{op}("), Style::Plain);
                    self.expr(expr, P_IF);
                    self.emit(")", Style::Plain);
                }
                _ => self.method(expr, &op.to_string(), &[]),
            },
            Expr::BinaryOp { op, left, right } => match op {
                BinaryOp::Or => self.binop(left, P_OR, "||", right, P_AND),
                BinaryOp::And => self.binop(left, P_AND, "&&", right, P_REL),
                BinaryOp::Eq => self.binop(left, P_ADD, "==", right, P_ADD),
                BinaryOp::NotEq => self.binop(left, P_ADD, "!=", right, P_ADD),
                BinaryOp::Less => self.binop(left, P_ADD, "<", right, P_ADD),
                BinaryOp::LessEq => self.binop(left, P_ADD, "<=", right, P_ADD),
                BinaryOp::Greater => self.binop(left, P_ADD, ">", right, P_ADD),
                BinaryOp::GreaterEq => self.binop(left, P_ADD, ">=", right, P_ADD),
                BinaryOp::In => self.binop(left, P_ADD, "in", right, P_ADD),
                BinaryOp::Add => self.binop(left, P_ADD, "+", right, P_MUL),
                BinaryOp::Sub => self.binop(left, P_ADD, "-", right, P_MUL),
                BinaryOp::Mul => self.binop(left, P_MUL, "*", right, P_UNARY),
                // Everything else is a method call: `contains`, `getTag`, `isInRange`, ...
                _ => self.method(left, &op.to_string(), &[right]),
            },
            Expr::GetAttr { expr, attr } => {
                self.expr(expr, P_MEMBER);
                self.attr(attr);
            }
            Expr::HasAttr { expr, attrs } => {
                self.expr(expr, P_ADD);
                self.emit(" has ", Style::Keyword);
                let path: Vec<String> = attrs.iter().map(|a| record_key(a)).collect();
                self.emit(path.join("."), Style::Ident);
            }
            Expr::Like { expr, pattern } => {
                self.expr(expr, P_ADD);
                self.emit(" like ", Style::Keyword);
                let pat: String = pattern
                    .iter()
                    .map(|p| match p {
                        pst::PatternElem::Wildcard => "*".to_string(),
                        pst::PatternElem::Char('*') => "\\*".to_string(),
                        pst::PatternElem::Char(c) => c.escape_debug().to_string(),
                    })
                    .collect();
                self.emit(format!("\"{pat}\""), Style::Str);
            }
            Expr::Is {
                expr,
                entity_type,
                in_expr,
            } => {
                self.expr(expr, P_ADD);
                self.emit(" is ", Style::Keyword);
                self.emit(entity_type.to_string(), Style::EntityType);
                if let Some(i) = in_expr {
                    self.emit(" in ", Style::Keyword);
                    self.expr(i, P_ADD);
                }
            }
            Expr::Set(elems) => {
                self.emit("[", Style::Plain);
                for (i, x) in elems.iter().enumerate() {
                    if i > 0 {
                        self.emit(",", Style::Plain);
                        self.brk();
                    }
                    self.expr(x, P_IF);
                }
                self.emit("]", Style::Plain);
            }
            Expr::Record(fields) => {
                self.emit("{", Style::Plain);
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        self.emit(",", Style::Plain);
                        self.brk();
                    }
                    self.emit(record_key(k), Style::Ident);
                    self.emit(": ", Style::Plain);
                    self.expr(v, P_IF);
                }
                self.emit("}", Style::Plain);
            }
            // Slots, unknowns, and anything newer: fall back to Cedar syntax.
            other => self.emit(other.to_string(), Style::Plain),
        }
    }
}

/// Tokens for a residual expression, with each token marked by the facts
/// it depends on.
pub fn residual_tokens(e: &Expr, env: TypeEnv<'_>) -> Vec<Tok> {
    let mut p = Printer {
        toks: vec![],
        marks: vec![],
        env,
    };
    p.expr(e, P_IF);
    p.toks
}

/// Greedy line filling: lines after the first are indented by `cont_indent`.
pub fn layout(toks: Vec<Tok>, width: usize, cont_indent: usize) -> Vec<Vec<Span>> {
    // Split into unbreakable segments.
    let mut segs: Vec<Vec<Span>> = vec![];
    let mut seg: Vec<Span> = vec![];
    for t in toks {
        match t {
            Tok::Span(s) => seg.push(s),
            Tok::Break => segs.push(std::mem::take(&mut seg)),
        }
    }
    segs.push(seg);
    let seg_w = |s: &Vec<Span>| s.iter().map(Span::width).sum::<usize>();
    let mut lines: Vec<Vec<Span>> = vec![];
    let mut cur: Vec<Span> = vec![];
    let mut cur_w = 0;
    for (i, seg) in segs.into_iter().enumerate() {
        let w = seg_w(&seg);
        if i == 0 {
            cur_w = w;
            cur = seg;
        } else if cur_w + 1 + w > width && cur_w > cont_indent {
            lines.push(std::mem::take(&mut cur));
            cur.push(sp(" ".repeat(cont_indent), Style::Plain));
            cur_w = cont_indent + w;
            cur.extend(seg);
        } else {
            cur.push(sp(" ", Style::Plain));
            cur_w += 1 + w;
            cur.extend(seg);
        }
    }
    lines.push(cur);
    lines
}

/// Render the residuals pane for a given text width.
pub fn render_residuals(env: TypeEnv<'_>, eval: &Evaluation, width: usize) -> Vec<Line> {
    let width = width.saturating_sub(2).max(20);
    let mut out = Vec::new();
    let entry = |p: &crate::eval::PolicyEval, dim: bool, out: &mut Vec<Line>| {
        let mark = match p.status {
            Status::Residual => PolicyMark::Residual,
            Status::True => PolicyMark::Satisfied,
            Status::False => PolicyMark::NotSatisfied,
            Status::Error => PolicyMark::Error,
        };
        let mut head = Line::new(vec![
            sp(effect_str(p.effect), Style::Keyword),
            sp(" ", Style::Plain),
            sp(format!("«{}»", p.id), Style::Plain),
        ]);
        head.gutter = Gutter::Policy(mark);
        head.policy = Some(p.id.clone());
        head.dim = dim;
        out.push(head);
        let body: Vec<Vec<Span>> = match p.status {
            Status::Residual => {
                let mut toks = vec![
                    Tok::Span(sp("when", Style::Keyword)),
                    Tok::Span(sp(" {", Style::Plain)),
                    Tok::Break,
                ];
                toks.extend(residual_tokens(&p.residual, env));
                toks.push(Tok::Span(sp(" };", Style::Plain)));
                layout(toks, width, 2)
            }
            Status::True => vec![vec![sp("satisfied", Style::Muted)]],
            Status::False => vec![vec![sp("not satisfied", Style::Muted)]],
            Status::Error => vec![vec![sp("errors, so it does not apply", Style::Muted)]],
        };
        for spans in body {
            let mut l = Line::new(spans);
            l.dim = dim;
            out.push(l);
        }
    };
    let (rel, irr): (Vec<_>, Vec<_>) = eval.policies.iter().partition(|p| p.relevant);
    for (i, p) in rel.iter().enumerate() {
        if i > 0 {
            out.push(Line::new(vec![]));
        }
        entry(p, false, &mut out);
    }
    if !irr.is_empty() {
        if !rel.is_empty() {
            out.push(Line::new(vec![]));
        }
        let mut sep = Line::new(vec![sp(
            "── no longer affects the outcome ──",
            Style::Muted,
        )]);
        sep.dim = true;
        sep.gutter = Gutter::Bare;
        out.push(sep);
        for p in irr {
            out.push(Line::new(vec![]));
            entry(p, true, &mut out);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Source highlighting

const KEYWORDS: &[&str] = &[
    "permit",
    "forbid",
    "when",
    "unless",
    "principal",
    "action",
    "resource",
    "context",
    "in",
    "has",
    "like",
    "is",
    "if",
    "then",
    "else",
    "true",
    "false",
    "namespace",
    "entity",
    "type",
    "appliesTo",
    "tags",
    "enum",
];

/// Lightweight syntax highlighting for Cedar policy and schema source.
pub fn highlight_source(src: &str) -> Vec<Line> {
    src.lines().map(highlight_line).collect()
}

fn highlight_line(line: &str) -> Line {
    let mut spans: Vec<Span> = Vec::new();
    let mut push = |text: &str, style: Style| match spans.last_mut() {
        Some(last) if style == Style::Plain && last.style == Style::Plain => {
            last.text.push_str(text)
        }
        _ => spans.push(sp(text, style)),
    };
    let mut chars = line.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        let rest = line.get(start..).unwrap_or_default();
        if rest.starts_with("//") {
            push(rest, Style::Comment);
            break;
        }
        let mut end = start + c.len_utf8();
        if c == '"' {
            let mut escaped = false;
            end = line.len();
            for (i, c) in chars.by_ref() {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    end = i + 1;
                    break;
                }
            }
            push(line.get(start..end).unwrap_or_default(), Style::Str);
        } else if c.is_alphabetic() || c == '_' || c == '@' {
            while let Some((i, c)) = chars.next_if(|(_, c)| c.is_alphanumeric() || *c == '_') {
                end = i + c.len_utf8();
            }
            let word = line.get(start..end).unwrap_or_default();
            let style = if word.starts_with('@') {
                Style::Comment
            } else if KEYWORDS.contains(&word) {
                Style::Keyword
            } else if word.starts_with(char::is_uppercase) {
                Style::EntityType
            } else {
                Style::Ident
            };
            push(word, style);
        } else {
            push(line.get(start..end).unwrap_or_default(), Style::Plain);
        }
    }
    Line::new(spans)
}
