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

//! Conversions from CST to AST
//!
//! This module contains functions to convert ASTNodes containing CST items into
//! AST items. It works with the parser CST output, where all nodes are optional.
//!
//! An important aspect of the transformation is to provide as many errors as
//! possible to expedite development cycles. To the purpose, an error parameter
//! must be passed to each function, to collect the potentially multiple errors.
//! `Option::None` is used to signify that errors were present, and any new
//! messages will be appended to the error parameter. Messages are not added when
//! they are assumed to have already been added, like when a sub-conversion fails
//! or the CST node was `None`, signifying a parse failure with associated message.

// Throughout this module parameters to functions are references to CSTs or
// owned AST items. This allows the most flexibility and least copying of data.
// CSTs are almost entirely rewritten to ASTs, so we keep those values intact
// and only clone the identifiers inside. ASTs here are temporary values until
// the data passes out of the module, so we deconstruct them freely in the few
// cases where there is a secondary conversion. This prevents any further
// cloning.

use super::err::ParseError;
use super::node::{ASTNode, SourceInfo};
use super::unescape::{to_pattern, to_unescaped_string};
use super::{cst, err};
use crate::ast::{
    self, ActionConstraint, CallStyle, EntityReference, EntityType, EntityUID, PatternElem,
    PolicySetError, PrincipalConstraint, PrincipalOrResourceConstraint, ResourceConstraint,
};
use itertools::Either;
use smol_str::SmolStr;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::mem;
use std::sync::Arc;

// shortcut for error parameter
type Errs<'a> = &'a mut Vec<err::ParseError>;

// for storing extension function names per callstyle
struct ExtStyles<'a> {
    functions: HashSet<&'a ast::Name>,
    methods: HashSet<&'a str>,
}

// Store extension function call styles
lazy_static::lazy_static! {
    static ref EXTENSION_STYLES: ExtStyles<'static> = load_styles();
}
fn load_styles() -> ExtStyles<'static> {
    let mut functions = HashSet::new();
    let mut methods = HashSet::new();
    for func in crate::extensions::Extensions::all_available().all_funcs() {
        match func.style() {
            CallStyle::FunctionStyle => functions.insert(func.name()),
            CallStyle::MethodStyle => methods.insert(func.name().basename().as_ref()),
        };
    }
    ExtStyles { functions, methods }
}

impl ASTNode<Option<cst::Policies>> {
    /// Iterate over the `Policy` nodes in this `cst::Policies`, with
    /// corresponding generated `PolicyID`s
    pub fn with_generated_policyids(
        &self,
    ) -> Option<impl Iterator<Item = (ast::PolicyID, &ASTNode<Option<cst::Policy>>)>> {
        let maybe_policies = self.as_inner();
        // return right away if there's no data, parse provided error
        let policies = maybe_policies?;

        Some(
            policies
                .0
                .iter()
                .enumerate()
                .map(|(count, node)| (ast::PolicyID::from_string(format!("policy{count}")), node)),
        )
    }

    /// convert `cst::Policies` to `ast::PolicySet`
    pub fn to_policyset(&self, errs: Errs<'_>) -> Option<ast::PolicySet> {
        let mut pset = ast::PolicySet::new();
        let mut complete_set = true;
        for (policy_id, policy) in self.with_generated_policyids()? {
            // policy may have convert error
            match policy.to_policy_or_template(policy_id, errs) {
                Some(Either::Right(template)) => {
                    if let Err(e) = pset.add_template(template) {
                        match e {
                            PolicySetError::Occupied => errs.push(ParseError::ToAST(
                                "A template with this ID already exists within the policy set"
                                    .to_string(),
                            )),
                        };

                        complete_set = false
                    }
                }
                Some(Either::Left(inline_policy)) => {
                    if let Err(e) = pset.add_static(inline_policy) {
                        match e {
                            PolicySetError::Occupied => errs.push(ParseError::ToAST(
                                "A policy with this ID already exists within the policy set"
                                    .to_string(),
                            )),
                        };

                        complete_set = false
                    }
                }
                None => complete_set = false,
            };
        }

        // fail on any error
        if complete_set {
            Some(pset)
        } else {
            None
        }
    }
}

impl ASTNode<Option<cst::Policy>> {
    /// Convert `cst::Policy` to an AST `InlinePolicy` or `Template`
    pub fn to_policy_or_template(
        &self,
        id: ast::PolicyID,
        errs: Errs<'_>,
    ) -> Option<Either<ast::StaticPolicy, ast::Template>> {
        let t = self.to_policy_template(id, errs)?;
        if t.slots().count() == 0 {
            // This should always succeed if the slot count is zero
            ast::StaticPolicy::try_from(t).ok().map(Either::Left)
        } else {
            Some(Either::Right(t))
        }
    }

    /// Convert `cst::Policy` to an AST `InlinePolicy`. (Will fail if the CST is for a template)
    pub fn to_policy(&self, id: ast::PolicyID, errs: Errs<'_>) -> Option<ast::StaticPolicy> {
        let tp = self.to_policy_template(id, errs)?;
        match ast::StaticPolicy::try_from(tp) {
            Ok(p) => Some(p),
            Err(e) => {
                errs.push(err::ParseError::ToAST(format!("{e}")));
                None
            }
        }
    }

    /// Convert `cst::Policy` to `ast::Template`. Works for inline policies as
    /// well, which will become templates with 0 slots
    pub fn to_policy_template(&self, id: ast::PolicyID, errs: Errs<'_>) -> Option<ast::Template> {
        let (src, maybe_policy) = self.as_inner_pair();
        // return right away if there's no data, parse provided error
        let policy = maybe_policy?;

        let mut failure = false;

        // convert effect
        let maybe_effect = policy.effect.to_effect(errs);

        // convert annotatons
        let annotations: BTreeMap<_, _> = policy
            .annotations
            .iter()
            .filter_map(|a| a.to_kv_pair(errs))
            .collect();
        if annotations.len() != policy.annotations.len() {
            failure = true;
            errs.push(err::ParseError::ToAST(
                "This policy uses poorly formed or duplicate annotations".to_string(),
            ));
        }

        // convert head
        let (maybe_principal, maybe_action, maybe_resource) = policy.extract_head(errs);

        // convert conditions
        let conds: Vec<_> = policy
            .conds
            .iter()
            .filter_map(|c| c.to_expr(errs))
            .collect();

        for e in conds.iter() {
            for slot in e.slots() {
                errs.push(ParseError::ToAST(format!("Template slots are currently unsupported in policy condition clauses, found slot {slot}")));
            }
        }

        if conds.len() != policy.conds.len() {
            failure = true
        }

        // all data and errors are generated, so fail or construct result
        if failure || !errs.is_empty() {
            return None;
        };
        let effect = maybe_effect?;
        let principal = maybe_principal?;
        let action = maybe_action?;
        let resource = maybe_resource?;

        Some(construct_template_policy(
            id,
            annotations,
            effect,
            principal,
            action,
            resource,
            conds,
            src.clone(),
        ))
    }
}

impl cst::Policy {
    /// get the head constraints from the `cst::Policy`
    pub fn extract_head(
        &self,
        errs: Errs<'_>,
    ) -> (
        Option<PrincipalConstraint>,
        Option<ActionConstraint>,
        Option<ResourceConstraint>,
    ) {
        let mut vars = self.variables.iter();
        let principal = if let Some(head1) = vars.next() {
            head1.to_principal_constraint(errs)
        } else {
            errs.push(err::ParseError::ToAST(
                "This policy requires the `principal` variable in the head".to_string(),
            ));
            None
        };
        let action = if let Some(head2) = vars.next() {
            head2.to_action_constraint(errs)
        } else {
            errs.push(err::ParseError::ToAST(
                "This policy requires the `action` variable in the head".to_string(),
            ));
            None
        };
        let resource = if let Some(head3) = vars.next() {
            head3.to_resource_constraint(errs)
        } else {
            errs.push(err::ParseError::ToAST(
                "This policy requires the `resource` variable in the head".to_string(),
            ));
            None
        };
        if vars.next().is_some() {
            errs.push(err::ParseError::ToAST(
                "This policy has extra variables in the head".to_string(),
            ));
        }
        (principal, action, resource)
    }
}

impl ASTNode<Option<cst::Annotation>> {
    /// Get the (k, v) pair for the annotation. Critically, this checks validity
    /// for the strings and does unescaping
    pub fn to_kv_pair(&self, errs: Errs<'_>) -> Option<(ast::Id, SmolStr)> {
        let maybe_anno = self.as_inner();
        // return right away if there's no data, parse provided error
        let anno = maybe_anno?;

        let maybe_key = anno.key.to_valid_ident(errs);
        let maybe_value = anno.value.as_valid_string(errs);
        let maybe_value = match maybe_value.map(|s| to_unescaped_string(s)).transpose() {
            Ok(maybe_value) => maybe_value,
            Err(unescape_errs) => {
                errs.extend(
                    unescape_errs
                        .into_iter()
                        .map(|e| ParseError::ToAST(e.to_string())),
                );
                None
            }
        };

        match (maybe_key, maybe_value) {
            (Some(k), Some(v)) => Some((k, v)),
            _ => None,
        }
    }
}

impl ASTNode<Option<cst::Ident>> {
    /// Convert `cst::Ident` to `ast::Id`. Fails for reserved or invalid identifiers
    pub fn to_valid_ident(&self, errs: Errs<'_>) -> Option<ast::Id> {
        let maybe_ident = self.as_inner();
        // return right away if there's no data, parse provided error
        let ident = maybe_ident?;

        match ident {
            cst::Ident::If
            | cst::Ident::True
            | cst::Ident::False
            | cst::Ident::Then
            | cst::Ident::Else
            | cst::Ident::In
            | cst::Ident::Has
            | cst::Ident::Like => {
                errs.push(err::ParseError::ToAST(format!(
                    "This identifier is reserved and cannot be used: {ident}"
                )));
                None
            }
            cst::Ident::Invalid(i) => {
                errs.push(err::ParseError::ToAST(format!(
                    "not a valid identifier: {i}"
                )));
                None
            }
            _ => Some(construct_id(format!("{ident}"))),
        }
    }

    /// effect
    pub(crate) fn to_effect(&self, errs: Errs<'_>) -> Option<ast::Effect> {
        let maybe_effect = self.as_inner();
        // return right away if there's no data, parse provided error
        let effect = maybe_effect?;

        match effect {
            cst::Ident::Permit => Some(ast::Effect::Permit),
            cst::Ident::Forbid => Some(ast::Effect::Forbid),
            _ => {
                errs.push(err::ParseError::ToAST(format!(
                    "not a valid policy effect: {effect}"
                )));
                None
            }
        }
    }
    pub(crate) fn to_cond_is_when(&self, errs: Errs<'_>) -> Option<bool> {
        let maybe_cond = self.as_inner();
        // return right away if there's no data, parse provided error
        let cond = maybe_cond?;

        match cond {
            cst::Ident::When => Some(true),
            cst::Ident::Unless => Some(false),
            _ => {
                errs.push(err::ParseError::ToAST(format!(
                    "not a valid policy condition: {cond}"
                )));
                None
            }
        }
    }

    fn to_var(&self, errs: Errs<'_>) -> Option<ast::Var> {
        let maybe_ident = self.as_inner();
        match maybe_ident {
            Some(cst::Ident::Principal) => Some(ast::Var::Principal),
            Some(cst::Ident::Action) => Some(ast::Var::Action),
            Some(cst::Ident::Resource) => Some(ast::Var::Resource),
            Some(ident) => {
                errs.push(err::ParseError::ToAST(format!(
                    "expected an identifier, got {ident}"
                )));
                None
            }
            None => {
                errs.push(err::ParseError::ToAST("expected an identifier".to_string()));
                None
            }
        }
    }
}

impl ast::Id {
    fn to_meth(
        &self,
        e: ast::Expr,
        mut args: Vec<ast::Expr>,
        errs: Errs<'_>,
        l: SourceInfo,
    ) -> Option<ast::Expr> {
        let mut adj_args = args.iter_mut().peekable();
        match (self.as_ref(), adj_args.next(), adj_args.peek()) {
            ("contains", Some(a), None) => {
                // move the value out of the argument, replacing it with a dummy,
                // after this we can no longer use the original args
                let arg = mem::replace(a, ast::Expr::val(false));
                Some(construct_method_contains(e, arg, l))
            }
            ("containsAll", Some(a), None) => {
                let arg = mem::replace(a, ast::Expr::val(false));
                Some(construct_method_contains_all(e, arg, l))
            }
            ("containsAny", Some(a), None) => {
                let arg = mem::replace(a, ast::Expr::val(false));
                Some(construct_method_contains_any(e, arg, l))
            }
            (name, _, _) => {
                if EXTENSION_STYLES.methods.contains(&name) {
                    args.insert(0, e);
                    // INVARIANT (MethodStyleArgs), we call insert above, so args is non-empty
                    Some(construct_ext_meth(name.to_string(), args, l))
                } else {
                    errs.push(err::ParseError::ToAST(format!(
                        "expected method name, found {}",
                        name
                    )));
                    None
                }
            }
        }
    }
}

#[derive(Debug)]
enum PrincipalOrResource {
    Principal(PrincipalConstraint),
    Resource(ResourceConstraint),
}

impl ASTNode<Option<cst::VariableDef>> {
    fn to_principal_constraint(&self, errs: Errs<'_>) -> Option<PrincipalConstraint> {
        match self.to_principal_or_resource_constraint(errs)? {
            PrincipalOrResource::Principal(p) => Some(p),
            PrincipalOrResource::Resource(_) => {
                errs.push(err::ParseError::ToAST(
                    "expected principal constraint, found resource constraint".to_string(),
                ));
                None
            }
        }
    }

    fn to_resource_constraint(&self, errs: Errs<'_>) -> Option<ResourceConstraint> {
        match self.to_principal_or_resource_constraint(errs)? {
            PrincipalOrResource::Principal(_) => {
                errs.push(err::ParseError::ToAST(
                    "expected resource constraint, found principal constraint".to_string(),
                ));
                None
            }
            PrincipalOrResource::Resource(r) => Some(r),
        }
    }

    fn to_principal_or_resource_constraint(&self, errs: Errs<'_>) -> Option<PrincipalOrResource> {
        let maybe_vardef = self.as_inner();
        // return right away if there's no data, parse provided error
        let vardef = maybe_vardef?;

        let var = vardef.variable.to_var(errs)?;

        match vardef.variable.to_var(errs) {
            Some(v) if v == var => Some(()),
            Some(other) => {
                errs.push(err::ParseError::ToAST(format!(
                    "expected {var} found {other}"
                )));
                None
            }
            None => None,
        }?;

        if let Some(typename) = vardef.name.as_ref() {
            typename.to_type_constraint(errs)?;
        }

        let c = if let Some((op, rel_expr)) = &vardef.ineq {
            let eref = rel_expr.to_ref_or_slot(errs, var)?;
            match op {
                cst::RelOp::Eq => Some(PrincipalOrResourceConstraint::Eq(eref)),
                cst::RelOp::In => Some(PrincipalOrResourceConstraint::In(eref)),
                _ => {
                    errs.push(err::ParseError::ToAST(
                        "policy head constraints must be `in` or `==`".to_string(),
                    ));
                    None
                }
            }
        } else {
            Some(PrincipalOrResourceConstraint::Any)
        }?;
        match var {
            ast::Var::Principal => {
                Some(PrincipalOrResource::Principal(PrincipalConstraint::new(c)))
            }
            ast::Var::Action => {
                errs.push(err::ParseError::ToAST("unexpected `action`".to_string()));
                None
            }
            ast::Var::Resource => Some(PrincipalOrResource::Resource(ResourceConstraint::new(c))),
            ast::Var::Context => {
                errs.push(err::ParseError::ToAST("unexpected `context`".to_string()));
                None
            }
        }
    }

    fn to_action_constraint(&self, errs: Errs<'_>) -> Option<ast::ActionConstraint> {
        let maybe_vardef = self.as_inner();
        let vardef = maybe_vardef?;

        match vardef.variable.to_var(errs) {
            Some(ast::Var::Action) => Some(()),
            Some(other) => {
                errs.push(err::ParseError::ToAST(format!(
                    "expected {}, found {other}",
                    ast::Var::Action
                )));
                None
            }
            None => None,
        }?;

        if let Some(typename) = vardef.name.as_ref() {
            typename.to_type_constraint(errs)?;
        }

        let action_constraint = if let Some((op, rel_expr)) = &vardef.ineq {
            let refs = rel_expr.to_refs(errs, ast::Var::Action)?;
            match (op, refs) {
                (cst::RelOp::In, OneOrMultipleRefs::Multiple(euids)) => {
                    Some(ActionConstraint::is_in(euids))
                }
                (cst::RelOp::In, OneOrMultipleRefs::Single(euid)) => {
                    Some(ActionConstraint::is_in([euid]))
                }
                (cst::RelOp::Eq, OneOrMultipleRefs::Single(euid)) => {
                    Some(ActionConstraint::is_eq(euid))
                }
                (cst::RelOp::Eq, OneOrMultipleRefs::Multiple(_)) => {
                    errs.push(err::ParseError::ToAST(
                        "constraints for `==` must be a single literal euid".to_string(),
                    ));
                    None
                }
                _ => {
                    errs.push(err::ParseError::ToAST(
                        "policy head constraints must be `in` or `==`".to_string(),
                    ));
                    None
                }
            }
        } else {
            Some(ActionConstraint::Any)
        }?;

        match action_constraint_contains_only_action_types(action_constraint) {
            Ok(a) => Some(a),
            Err(mut id_errs) => {
                errs.append(&mut id_errs);
                None
            }
        }
    }
}

fn action_type_error_msg(euid: &EntityUID) -> ParseError {
    let msg = format!("Expected an EntityUID with the type `Action`. Got: {euid}");
    ParseError::ToAST(msg)
}

/// Check that all of the EUIDs in an action constraint have the type `Action`, under an arbitrary namespace
fn action_constraint_contains_only_action_types(
    a: ActionConstraint,
) -> Result<ActionConstraint, Vec<ParseError>> {
    match a {
        ActionConstraint::Any => Ok(a),
        ActionConstraint::In(ref euids) => {
            let non_actions = euids
                .iter()
                .filter(|euid| !euid_has_action_type(euid))
                .collect::<Vec<_>>();
            if non_actions.is_empty() {
                Ok(a)
            } else {
                Err(non_actions
                    .into_iter()
                    .map(|euid| action_type_error_msg(euid.as_ref()))
                    .collect())
            }
        }
        ActionConstraint::Eq(ref euid) => {
            if euid_has_action_type(euid) {
                Ok(a)
            } else {
                Err(vec![action_type_error_msg(euid)])
            }
        }
    }
}

/// Check if an EUID has the type `Action` under an arbitrary namespace
fn euid_has_action_type(euid: &EntityUID) -> bool {
    if let EntityType::Concrete(name) = euid.entity_type() {
        name.id.as_ref() == "Action"
    } else {
        false
    }
}

impl ASTNode<Option<cst::Cond>> {
    /// to expr
    fn to_expr(&self, errs: Errs<'_>) -> Option<ast::Expr> {
        let (src, maybe_cond) = self.as_inner_pair();
        // return right away if there's no data, parse provided error
        let cond = maybe_cond?;

        let maybe_is_when = cond.cond.to_cond_is_when(errs);

        let maybe_expr = match &cond.expr {
            Some(expr) => expr.to_expr(errs),
            None => {
                errs.push(err::ParseError::ToAST(match cond.cond.as_ref().node {
                    Some(ident) => format!("{} clause should not be empty", &ident),
                    None => "bad use of {}".to_string(), // neither a keyword like `when`, nor a body
                }));
                None
            }
        };

        match (maybe_is_when, maybe_expr) {
            (Some(true), Some(e)) => Some(e),
            (Some(false), Some(e)) => Some(construct_expr_not(e, src.clone())),
            _ => None,
        }
    }
}

impl ASTNode<Option<cst::Str>> {
    pub(crate) fn as_valid_string(&self, errs: Errs<'_>) -> Option<&SmolStr> {
        let id = self.as_inner();
        // return right away if there's no data, parse provided error
        let id = id?;

        match id {
            cst::Str::String(s) => Some(s),
            // at time of comment, all strings are valid
            cst::Str::Invalid(s) => {
                errs.push(err::ParseError::ToAST(format!(
                    "this is an invalid string: {s}"
                )));
                None
            }
        }
    }
}

/// Result type of conversion when we expect an Expr, Var, Name, or String.
///
/// During conversion it is useful to keep track of expression that may be used
/// as function names, record names, or record attributes. This prevents parsing these
/// terms to a general Expr expression and then immediately unwrapping them.
pub(crate) enum ExprOrSpecial<'a> {
    /// Any expression except a variable, name, or string literal
    Expr(ast::Expr),
    /// Variables, which act as expressions or names
    Var(ast::Var, SourceInfo),
    /// Name that isn't an expr and couldn't be converted to var
    Name(ast::Name),
    /// String literal, not yet unescaped
    /// Must be processed with to_unescaped_string or to_pattern before inclusion in the AST
    StrLit(&'a SmolStr, SourceInfo),
}

impl ExprOrSpecial<'_> {
    fn into_expr(self, errs: Errs<'_>) -> Option<ast::Expr> {
        match self {
            Self::Expr(e) => Some(e),
            Self::Var(v, l) => Some(construct_expr_var(v, l)),
            Self::Name(n) => {
                errs.push(err::ParseError::ToAST(format!(
                    "Arbitrary variables are not supported; did you mean to enclose {n} in quotes to make a string?",
                )));
                None
            }
            Self::StrLit(s, l) => match to_unescaped_string(s) {
                Ok(s) => Some(construct_expr_string(s, l)),
                Err(escape_errs) => {
                    errs.extend(
                        escape_errs
                            .into_iter()
                            .map(|e| ParseError::ToAST(e.to_string())),
                    );
                    None
                }
            },
        }
    }

    /// Variables, names (with no prefixes), and string literals can all be used as record attributes
    pub(crate) fn into_valid_attr(self, errs: Errs<'_>) -> Option<SmolStr> {
        match self {
            Self::Var(var, _) => Some(construct_string_from_var(var)),
            Self::Name(name) => name.into_valid_attr(errs),
            Self::StrLit(s, _) => match to_unescaped_string(s) {
                Ok(s) => Some(s),
                Err(escape_errs) => {
                    errs.extend(
                        escape_errs
                            .into_iter()
                            .map(|e| ParseError::ToAST(e.to_string())),
                    );
                    None
                }
            },
            Self::Expr(e) => {
                errs.push(err::ParseError::ToAST(format!("not a valid string: {e}")));
                None
            }
        }
    }

    fn into_pattern(self, errs: Errs<'_>) -> Option<Vec<PatternElem>> {
        match self {
            Self::StrLit(s, _) => match to_pattern(s) {
                Ok(pat) => Some(pat),
                Err(escape_errs) => {
                    errs.extend(
                        escape_errs
                            .into_iter()
                            .map(|e| ParseError::ToAST(e.to_string())),
                    );
                    None
                }
            },
            Self::Var(var, _) => {
                errs.push(err::ParseError::ToAST(format!(
                    "not a string literal: {var}"
                )));
                None
            }
            Self::Name(name) => {
                errs.push(err::ParseError::ToAST(format!(
                    "not a string literal: {name}"
                )));
                None
            }
            Self::Expr(e) => {
                errs.push(err::ParseError::ToAST(format!("not a string literal: {e}")));
                None
            }
        }
    }
    /// to string literal
    fn into_string_literal(self, errs: Errs<'_>) -> Option<SmolStr> {
        match self {
            Self::StrLit(s, _) => match to_unescaped_string(s) {
                Ok(s) => Some(s),
                Err(escape_errs) => {
                    errs.extend(
                        escape_errs
                            .into_iter()
                            .map(|e| ParseError::ToAST(e.to_string())),
                    );
                    None
                }
            },
            Self::Var(var, _) => {
                errs.push(err::ParseError::ToAST(format!(
                    "not a string literal: {var}"
                )));
                None
            }
            Self::Name(name) => {
                errs.push(err::ParseError::ToAST(format!(
                    "not a string literal: {name}"
                )));
                None
            }
            Self::Expr(e) => {
                errs.push(err::ParseError::ToAST(format!("not a string literal: {e}")));
                None
            }
        }
    }
}

impl ASTNode<Option<cst::Expr>> {
    /// to ref
    fn to_ref(&self, var: ast::Var, errs: Errs<'_>) -> Option<EntityUID> {
        self.to_ref_or_refs::<SingleEntity>(errs, var).map(|x| x.0)
    }

    fn to_ref_or_slot(&self, errs: Errs<'_>, var: ast::Var) -> Option<EntityReference> {
        self.to_ref_or_refs::<EntityReference>(errs, var)
    }

    fn to_refs(&self, errs: Errs<'_>, var: ast::Var) -> Option<OneOrMultipleRefs> {
        self.to_ref_or_refs::<OneOrMultipleRefs>(errs, var)
    }

    fn to_ref_or_refs<T: RefKind>(&self, errs: Errs<'_>, var: ast::Var) -> Option<T> {
        let maybe_expr = self.as_inner();
        let expr = &*maybe_expr?.expr;
        match expr {
            cst::ExprData::Or(o) => o.to_ref_or_refs::<T>(errs, var),
            cst::ExprData::If(_, _, _) => {
                errs.push(err::ParseError::ToAST(format!(
                    "expected {}, found an if statement",
                    T::err_string()
                )));
                None
            }
        }
    }

    /// convert `cst::Expr` to `ast::Expr`
    pub fn to_expr(&self, errs: Errs<'_>) -> Option<ast::Expr> {
        self.to_expr_or_special(errs)?.into_expr(errs)
    }
    pub(crate) fn to_expr_or_special(&self, errs: Errs<'_>) -> Option<ExprOrSpecial<'_>> {
        let (src, maybe_expr) = self.as_inner_pair();
        // return right away if there's no data, parse provided error
        let expr = &*maybe_expr?.expr;

        match expr {
            cst::ExprData::Or(or) => or.to_expr_or_special(errs),
            cst::ExprData::If(i, t, e) => {
                let maybe_guard = i.to_expr(errs);
                let maybe_then = t.to_expr(errs);
                let maybe_else = e.to_expr(errs);

                match (maybe_guard, maybe_then, maybe_else) {
                    (Some(i), Some(t), Some(e)) => {
                        Some(ExprOrSpecial::Expr(construct_expr_if(i, t, e, src.clone())))
                    }
                    _ => None,
                }
            }
        }
    }
}

/// Type level marker for parsing sets of entity uids or single uids
/// This presents having either a large level of code duplication
/// or runtime data.
trait RefKind: Sized {
    fn err_string() -> &'static str;
    fn create_single_ref(e: EntityUID, errs: Errs<'_>) -> Option<Self>;
    fn create_multiple_refs(es: Vec<EntityUID>, errs: Errs<'_>) -> Option<Self>;
    fn create_slot(errs: Errs<'_>) -> Option<Self>;
}

struct SingleEntity(pub EntityUID);

impl RefKind for SingleEntity {
    fn err_string() -> &'static str {
        "entity uid"
    }

    fn create_single_ref(e: EntityUID, _errs: Errs<'_>) -> Option<Self> {
        Some(SingleEntity(e))
    }

    fn create_multiple_refs(_es: Vec<EntityUID>, errs: Errs<'_>) -> Option<Self> {
        errs.push(err::ParseError::ToAST(
            "expected single entity uid, got a set of entity uids".to_string(),
        ));
        None
    }

    fn create_slot(errs: Errs<'_>) -> Option<Self> {
        errs.push(err::ParseError::ToAST(
            "expected a single entity uid, got a template slot".to_string(),
        ));
        None
    }
}

impl RefKind for EntityReference {
    fn err_string() -> &'static str {
        "entity uid or template slot"
    }

    fn create_slot(_: Errs<'_>) -> Option<Self> {
        Some(EntityReference::Slot)
    }

    fn create_single_ref(e: EntityUID, _errs: Errs<'_>) -> Option<Self> {
        Some(EntityReference::euid(e))
    }

    fn create_multiple_refs(_es: Vec<EntityUID>, errs: Errs<'_>) -> Option<Self> {
        errs.push(err::ParseError::ToAST(
            "expected single entity uid or template slot, got a set of entity uids".to_string(),
        ));
        None
    }
}

/// Simple utility enum for parsing lists/individual entityuids
#[derive(Debug)]
enum OneOrMultipleRefs {
    Single(EntityUID),
    Multiple(Vec<EntityUID>),
}

impl RefKind for OneOrMultipleRefs {
    fn err_string() -> &'static str {
        "entity uid, set of entity uids, or template slot"
    }

    fn create_slot(errs: Errs<'_>) -> Option<Self> {
        errs.push(err::ParseError::ToAST("Unexpected slot".to_string()));
        None
    }

    fn create_single_ref(e: EntityUID, _errs: Errs<'_>) -> Option<Self> {
        Some(OneOrMultipleRefs::Single(e))
    }

    fn create_multiple_refs(es: Vec<EntityUID>, _errs: Errs<'_>) -> Option<Self> {
        Some(OneOrMultipleRefs::Multiple(es))
    }
}

impl ASTNode<Option<cst::Or>> {
    fn to_expr_or_special(&self, errs: Errs<'_>) -> Option<ExprOrSpecial<'_>> {
        let (src, maybe_or) = self.as_inner_pair();
        // return right away if there's no data, parse provided error
        let or = maybe_or?;

        let maybe_first = or.initial.to_expr_or_special(errs);
        let mut more = or.extended.iter().filter_map(|i| i.to_expr(errs));
        // getting the second here avoids the possibility of a singleton construction
        let maybe_second = more.next();
        // collect() preforms all the conversions, generating any errors
        let rest: Vec<_> = more.collect();

        match (maybe_first, maybe_second, rest.len(), or.extended.len()) {
            (f, None, _, 0) => f,
            (Some(f), Some(s), r, e) if 1 + r == e => f
                .into_expr(errs)
                .map(|e| ExprOrSpecial::Expr(construct_expr_or(e, s, rest, src.clone()))),
            _ => None,
        }
    }

    fn to_ref_or_refs<T: RefKind>(&self, errs: Errs<'_>, var: ast::Var) -> Option<T> {
        let maybe_or = self.as_inner();
        let or = maybe_or?;
        match or.extended.len() {
            0 => or.initial.to_ref_or_refs::<T>(errs, var),
            _n => {
                errs.push(err::ParseError::ToAST(format!(
                    "expected {}, found ||",
                    T::err_string()
                )));
                None
            }
        }
    }
}

impl ASTNode<Option<cst::And>> {
    fn to_ref_or_refs<T: RefKind>(&self, errs: Errs<'_>, var: ast::Var) -> Option<T> {
        let maybe_and = self.as_inner();
        let and = maybe_and?;
        match and.extended.len() {
            0 => and.initial.to_ref_or_refs::<T>(errs, var),
            _n => {
                errs.push(err::ParseError::ToAST(format!(
                    "expected {}, found &&",
                    T::err_string()
                )));
                None
            }
        }
    }

    fn to_expr(&self, errs: Errs<'_>) -> Option<ast::Expr> {
        self.to_expr_or_special(errs)?.into_expr(errs)
    }
    fn to_expr_or_special(&self, errs: Errs<'_>) -> Option<ExprOrSpecial<'_>> {
        let (src, maybe_and) = self.as_inner_pair();
        // return right away if there's no data, parse provided error
        let and = maybe_and?;

        let maybe_first = and.initial.to_expr_or_special(errs);
        let mut more = and.extended.iter().filter_map(|i| i.to_expr(errs));
        // getting the second here avoids the possibility of a singleton construction
        let maybe_second = more.next();
        // collect() preforms all the conversions, generating any errors
        let rest: Vec<_> = more.collect();

        match (maybe_first, maybe_second, rest.len(), and.extended.len()) {
            (f, None, _, 0) => f,
            (Some(f), Some(s), r, e) if 1 + r == e => f
                .into_expr(errs)
                .map(|e| ExprOrSpecial::Expr(construct_expr_and(e, s, rest, src.clone()))),
            _ => None,
        }
    }
}

impl ASTNode<Option<cst::Relation>> {
    fn to_ref_or_refs<T: RefKind>(&self, errs: Errs<'_>, var: ast::Var) -> Option<T> {
        let maybe_rel = self.as_inner();
        match maybe_rel? {
            cst::Relation::Common { initial, extended } => match extended.len() {
                0 => initial.to_ref_or_refs::<T>(errs, var),
                _n => {
                    errs.push(err::ParseError::ToAST(format!(
                        "expected {}, found binary operation",
                        T::err_string()
                    )));
                    None
                }
            },
            cst::Relation::Has { .. } => {
                errs.push(err::ParseError::ToAST(format!(
                    "expected {}, found `has` relation",
                    T::err_string()
                )));
                None
            }
            cst::Relation::Like { .. } => {
                errs.push(err::ParseError::ToAST(format!(
                    "expected {}, found `like` relation",
                    T::err_string()
                )));
                None
            }
        }
    }

    fn to_expr(&self, errs: Errs<'_>) -> Option<ast::Expr> {
        self.to_expr_or_special(errs)?.into_expr(errs)
    }
    fn to_expr_or_special(&self, errs: Errs<'_>) -> Option<ExprOrSpecial<'_>> {
        let (src, maybe_rel) = self.as_inner_pair();
        // return right away if there's no data, parse provided error
        let rel = maybe_rel?;

        match rel {
            cst::Relation::Common { initial, extended } => {
                let maybe_first = initial.to_expr_or_special(errs);
                let mut more = extended
                    .iter()
                    .filter_map(|(op, i)| i.to_expr(errs).map(|e| (op, e)));
                // getting the second here avoids the possibility of a singleton construction
                let maybe_second = more.next();
                // collect() preforms all the conversions, generating any errors
                let _rest: Vec<_> = more.collect();

                match (maybe_first, maybe_second, extended.len()) {
                    (_, _, l) if l > 1 => {
                        errs.push(err::ParseError::ToAST(
                            "Multiple relational operators (>, ==, in, etc.) without parentheses"
                                .to_string(),
                        ));
                        None
                    }
                    // error reported and result filtered out
                    (_, None, 1) => None,
                    (f, None, 0) => f,
                    (Some(f), Some((op, s)), _) => f
                        .into_expr(errs)
                        .map(|e| ExprOrSpecial::Expr(construct_expr_rel(e, *op, s, src.clone()))),
                    _ => None,
                }
            }
            cst::Relation::Has { target, field } => {
                match (
                    target.to_expr(errs),
                    field.to_expr_or_special(errs)?.into_valid_attr(errs),
                ) {
                    (Some(t), Some(s)) => {
                        Some(ExprOrSpecial::Expr(construct_expr_has(t, s, src.clone())))
                    }
                    _ => None,
                }
            }
            cst::Relation::Like { target, pattern } => {
                match (
                    target.to_expr(errs),
                    pattern.to_expr_or_special(errs)?.into_pattern(errs),
                ) {
                    (Some(t), Some(s)) => {
                        Some(ExprOrSpecial::Expr(construct_expr_like(t, s, src.clone())))
                    }
                    _ => None,
                }
            }
        }
    }
}

impl ASTNode<Option<cst::Add>> {
    fn to_ref_or_refs<T: RefKind>(&self, errs: Errs<'_>, var: ast::Var) -> Option<T> {
        let maybe_add = self.as_inner();
        let add = maybe_add?;
        match add.extended.len() {
            0 => add.initial.to_ref_or_refs::<T>(errs, var),
            _n => {
                errs.push(err::ParseError::ToAST(format!(
                    "expected {}, found arithmetic",
                    T::err_string()
                )));
                None
            }
        }
    }

    fn to_expr(&self, errs: Errs<'_>) -> Option<ast::Expr> {
        self.to_expr_or_special(errs)?.into_expr(errs)
    }
    fn to_expr_or_special(&self, errs: Errs<'_>) -> Option<ExprOrSpecial<'_>> {
        let (src, maybe_add) = self.as_inner_pair();
        // return right away if there's no data, parse provided error
        let add = maybe_add?;

        let maybe_first = add.initial.to_expr_or_special(errs);
        // collect() performs all the conversions, generating any errors
        let more: Vec<(cst::AddOp, _)> = add
            .extended
            .iter()
            .filter_map(|&(op, ref i)| i.to_expr(errs).map(|e| (op, e)))
            .collect();
        if !more.is_empty() {
            Some(ExprOrSpecial::Expr(construct_expr_add(
                maybe_first?.into_expr(errs)?,
                more,
                src.clone(),
            )))
        } else {
            maybe_first
        }
    }
}

impl ASTNode<Option<cst::Mult>> {
    fn to_ref_or_refs<T: RefKind>(&self, errs: Errs<'_>, var: ast::Var) -> Option<T> {
        let maybe_mult = self.as_inner();
        let mult = maybe_mult?;
        match mult.extended.len() {
            0 => mult.initial.to_ref_or_refs::<T>(errs, var),
            _n => {
                errs.push(err::ParseError::ToAST(format!(
                    "expected {}, found arithmetic",
                    T::err_string()
                )));
                None
            }
        }
    }

    fn to_expr(&self, errs: Errs<'_>) -> Option<ast::Expr> {
        self.to_expr_or_special(errs)?.into_expr(errs)
    }
    fn to_expr_or_special(&self, errs: Errs<'_>) -> Option<ExprOrSpecial<'_>> {
        let (src, maybe_mult) = self.as_inner_pair();
        // return right away if there's no data, parse provided error
        let mult = maybe_mult?;

        let maybe_first = mult.initial.to_expr_or_special(errs);
        // collect() preforms all the conversions, generating any errors
        let more: Vec<(cst::MultOp, _)> = mult
            .extended
            .iter()
            .filter_map(|&(op, ref i)| i.to_expr(errs).map(|e| (op, e)))
            .collect();

        if !more.is_empty() {
            let first = maybe_first?.into_expr(errs)?;
            // enforce that division and remainder/modulo are not supported
            for (op, _) in &more {
                match op {
                    cst::MultOp::Times => {}
                    cst::MultOp::Divide => {
                        errs.push(ParseError::ToAST("division is not supported".to_string()));
                        return None;
                    }
                    cst::MultOp::Mod => {
                        errs.push(ParseError::ToAST(
                            "remainder/modulo is not supported".to_string(),
                        ));
                        return None;
                    }
                }
            }
            // split all the operands into constantints and nonconstantints.
            // also, remove the opcodes -- from here on we assume they're all
            // `Times`, having checked above that this is the case
            let (constantints, nonconstantints): (Vec<ast::Expr>, Vec<ast::Expr>) =
                std::iter::once(first)
                    .chain(more.into_iter().map(|(_, e)| e))
                    .partition(|e| {
                        matches!(e.expr_kind(), ast::ExprKind::Lit(ast::Literal::Long(_)))
                    });
            let constantints = constantints
                .into_iter()
                .map(|e| match e.expr_kind() {
                    ast::ExprKind::Lit(ast::Literal::Long(i)) => *i,
                    // PANIC SAFETY Checked the match above via the call to `partition`
                    #[allow(clippy::unreachable)]
                    _ => unreachable!(
                        "checked it matched ast::ExprKind::Lit(ast::Literal::Long(_)) above"
                    ),
                })
                .collect::<Vec<i64>>();
            if nonconstantints.len() > 1 {
                // at most one of the operands in `a * b * c * d * ...` can be a nonconstantint
                errs.push(err::ParseError::ToAST(
                    "Multiplication must be by a constant int".to_string(), // you could see this error for division by a nonconstant as well, but this error message seems like the appropriate one, it will be the common case
                ));
                None
            } else if nonconstantints.is_empty() {
                // PANIC SAFETY If nonconstantints is empty then constantints must have at least one value
                #[allow(clippy::indexing_slicing)]
                Some(ExprOrSpecial::Expr(construct_expr_mul(
                    construct_expr_num(constantints[0], src.clone()),
                    constantints[1..].iter().copied(),
                    src.clone(),
                )))
            } else {
                // PANIC SAFETY Checked above that `nonconstantints` has at least one element
                #[allow(clippy::expect_used)]
                let nonconstantint: ast::Expr = nonconstantints
                    .into_iter()
                    .next()
                    .expect("already checked that it's not empty");
                Some(ExprOrSpecial::Expr(construct_expr_mul(
                    nonconstantint,
                    constantints,
                    src.clone(),
                )))
            }
        } else {
            maybe_first
        }
    }
}

impl ASTNode<Option<cst::Unary>> {
    fn to_ref_or_refs<T: RefKind>(&self, errs: Errs<'_>, var: ast::Var) -> Option<T> {
        let maybe_unary = self.as_inner();
        let unary = maybe_unary?;
        match &unary.op {
            Some(_op) => {
                errs.push(err::ParseError::ToAST(
                    "expected entity uid found unary operation".to_string(),
                ));
                None
            }
            None => unary.item.to_ref_or_refs::<T>(errs, var),
        }
    }

    fn to_expr(&self, errs: Errs<'_>) -> Option<ast::Expr> {
        self.to_expr_or_special(errs)?.into_expr(errs)
    }
    fn to_expr_or_special(&self, errs: Errs<'_>) -> Option<ExprOrSpecial<'_>> {
        let (src, maybe_unary) = self.as_inner_pair();
        // return right away if there's no data, parse provided error
        let unary = maybe_unary?;

        // A thunk to delay the evaluation of `item`
        let mut maybe_item = || unary.item.to_expr_or_special(errs);

        match unary.op {
            None => maybe_item(),
            Some(cst::NegOp::Bang(0)) => maybe_item(),
            Some(cst::NegOp::Dash(0)) => maybe_item(),
            Some(cst::NegOp::Bang(n)) => {
                let item = maybe_item().and_then(|i| i.into_expr(errs));
                if n % 2 == 0 {
                    item.map(|i| {
                        ExprOrSpecial::Expr(construct_expr_not(
                            construct_expr_not(i, src.clone()),
                            src.clone(),
                        ))
                    })
                } else {
                    // safe to collapse to !
                    item.map(|i| ExprOrSpecial::Expr(construct_expr_not(i, src.clone())))
                }
            }
            Some(cst::NegOp::Dash(c)) => {
                // Test if there is a negative numeric literal.
                // A negative numeric literal should match regex pattern
                // `-\d+` which is parsed into a `Unary(_, Member(Primary(Literal(Num(_))), []))`.
                // Given a successful match, the number of negation operations
                // decreases by one.
                let (last, rc) = if let Some(cst::Literal::Num(n)) = unary.item.to_lit() {
                    match n.cmp(&(i64::MAX as u64 + 1)) {
                        Ordering::Equal => (
                            Some(construct_expr_num(i64::MIN, unary.item.info.clone())),
                            c - 1,
                        ),
                        Ordering::Less => (
                            Some(construct_expr_num(-(*n as i64), unary.item.info.clone())),
                            c - 1,
                        ),
                        Ordering::Greater => {
                            errs.push(err::ParseError::ToAST(
                                "Integer constant is too large!".to_string(),
                            ));
                            (None, 0)
                        }
                    }
                } else {
                    // If the operand is not a CST literal, convert it into
                    // an expression.
                    (maybe_item().and_then(|i| i.into_expr(errs)), c)
                };
                // Fold the expression into a series of negation operations.
                (0..rc)
                    .fold(last, |r, _| r.map(|e| (construct_expr_neg(e, src.clone()))))
                    .map(ExprOrSpecial::Expr)
            }
            Some(cst::NegOp::OverBang) => {
                errs.push(err::ParseError::ToAST("Too many '!'s".to_string()));
                None
            }
            Some(cst::NegOp::OverDash) => {
                errs.push(err::ParseError::ToAST("Too many '-'s".to_string()));
                None
            }
        }
    }
}

/// Temporary converted data, mirroring `cst::MemAccess`
enum AstAccessor {
    Field(ast::Id),
    Call(Vec<ast::Expr>),
    Index(SmolStr),
}

impl ASTNode<Option<cst::Member>> {
    // Try to convert `cst::Member` into a `cst::Literal`, i.e.
    // match `Member(Primary(Literal(_), []))`.
    // It does not match the `Expr` arm of `Primary`, which means expressions
    // like `(1)` are not considered as literals on the CST level.
    fn to_lit(&self) -> Option<&cst::Literal> {
        let m = self.as_ref().node.as_ref()?;
        if !m.access.is_empty() {
            return None;
        }
        match m.item.as_ref().node.as_ref()? {
            cst::Primary::Literal(l) => l.as_ref().node.as_ref(),
            _ => None,
        }
    }

    fn to_ref_or_refs<T: RefKind>(&self, errs: Errs<'_>, var: ast::Var) -> Option<T> {
        let maybe_mem = self.as_inner();
        let mem = maybe_mem?;
        match mem.access.len() {
            0 => mem.item.to_ref_or_refs::<T>(errs, var),
            _n => {
                errs.push(err::ParseError::ToAST(
                    "expected entity uid, found member access".to_string(),
                ));
                None
            }
        }
    }

    fn to_expr_or_special(&self, errs: Errs<'_>) -> Option<ExprOrSpecial<'_>> {
        let (src, maybe_mem) = self.as_inner_pair();
        // return right away if there's no data, parse provided error
        let mem = maybe_mem?;

        let maybe_prim = mem.item.to_expr_or_special(errs);

        // collect() allows all conversions to run and generate errors
        let mut accessors: Vec<_> = mem.access.iter().map(|a| a.to_access(errs)).collect();

        // we use `head` as our failure indicator going forward
        let mut head = maybe_prim;
        // we need at least three available items, for example:
        // var .call (args) -  which becomes one expr
        // so we use slice matching
        let mut tail = &mut accessors[..];

        // Starting off with a failure and filtering items from the accessor list
        // can cause false error messages. We consider this acceptable for now because
        // they only occur along side a real error.
        // TODO: eliminate the false errors (likely with `Option`s inside `AstAccessor`)
        //
        // This algorithm is essentially an iterator over the accessor slice, but the
        // pattern match should be easier to read, since we have to check multiple elements
        // at once. We use `mem::replace` to "deconstruct" the slice as we go, filling it
        // with empty data and taking ownership of its contents.
        loop {
            use AstAccessor::*;
            use ExprOrSpecial::*;
            match (&mut head, tail) {
                // no accessors left - we're done
                (_, []) => break head,
                // failed method call (presumably) - ignore
                (_, [None, Some(Call(_)), rest @ ..]) => {
                    head = None;
                    tail = rest;
                }
                // failed access - ignore
                (_, [None, rest @ ..]) => {
                    head = None;
                    tail = rest;
                }
                // function call
                (Some(Name(n)), [Some(Call(a)), rest @ ..]) => {
                    // move the vec out of the slice, we won't use the slice after
                    let args = std::mem::take(a);
                    // replace the object `n` refers to with a default value since it won't be used afterwards
                    let nn =
                        mem::replace(n, ast::Name::unqualified_name(ast::Id::new_unchecked("")));
                    head = nn.into_func(args, errs, src.clone()).map(Expr);
                    tail = rest;
                }
                // variable call - error
                (Some(Var(_, _)), [Some(Call(_)), rest @ ..]) => {
                    errs.push(err::ParseError::ToAST(
                        "Variables cannot be used as functions".to_string(),
                    ));
                    head = None;
                    tail = rest;
                }
                // arbitrary call - error
                (_, [Some(Call(_)), rest @ ..]) => {
                    errs.push(err::ParseError::ToAST(
                        "All functions are named, this cannot be called".to_string(),
                    ));
                    head = None;
                    tail = rest;
                }
                // method call on failure - ignore
                (None, [Some(Field(_)), Some(Call(_)), rest @ ..]) => {
                    tail = rest;
                }
                // method call on name - error
                (Some(Name(_)), [Some(Field(_)), Some(Call(_)), rest @ ..]) => {
                    errs.push(err::ParseError::ToAST(
                        "This item does not have methods".to_string(),
                    ));
                    head = None;
                    tail = rest;
                }
                // method call on variable
                (Some(Var(v, vl)), [Some(Field(i)), Some(Call(a)), rest @ ..]) => {
                    // move var and args out of the slice
                    let var = mem::replace(v, ast::Var::Principal);
                    let args = std::mem::take(a);
                    // move the id out of the slice as well, to avoid cloning the internal string
                    let id = mem::replace(i, ast::Id::new_unchecked(""));
                    head = id
                        .to_meth(construct_expr_var(var, vl.clone()), args, errs, src.clone())
                        .map(Expr);
                    tail = rest;
                }
                // method call on arbitrary expression
                (Some(Expr(e)), [Some(Field(i)), Some(Call(a)), rest @ ..]) => {
                    // move the expr and args out of the slice
                    let args = std::mem::take(a);
                    let expr = mem::replace(e, ast::Expr::val(false));
                    // move the id out of the slice as well, to avoid cloning the internal string
                    let id = mem::replace(i, ast::Id::new_unchecked(""));
                    head = id.to_meth(expr, args, errs, src.clone()).map(Expr);
                    tail = rest;
                }
                // method call on string literal (same as Expr case)
                (Some(StrLit(s, sl)), [Some(Field(i)), Some(Call(a)), rest @ ..]) => {
                    let args = std::mem::take(a);
                    let id = mem::replace(i, ast::Id::new_unchecked(""));
                    let maybe_expr = match to_unescaped_string(s) {
                        Ok(s) => Some(construct_expr_string(s, sl.clone())),
                        Err(escape_errs) => {
                            errs.extend(
                                escape_errs
                                    .into_iter()
                                    .map(|e| ParseError::ToAST(e.to_string())),
                            );
                            None
                        }
                    };
                    head =
                        maybe_expr.and_then(|e| id.to_meth(e, args, errs, src.clone()).map(Expr));
                    tail = rest;
                }
                // access of failure - ignore
                (None, [Some(Field(_)) | Some(Index(_)), rest @ ..]) => {
                    tail = rest;
                }
                // access on arbitrary name - error
                (Some(Name(_)), [Some(Field(_)) | Some(Index(_)), rest @ ..]) => {
                    errs.push(err::ParseError::ToAST(
                        "This item is not a data structure".to_string(),
                    ));
                    head = None;
                    tail = rest;
                }
                // attribute of variable
                (Some(Var(v, vl)), [Some(Field(i)), rest @ ..]) => {
                    let var = mem::replace(v, ast::Var::Principal);
                    let id = mem::replace(i, ast::Id::new_unchecked(""));
                    head = Some(Expr(construct_expr_attr(
                        construct_expr_var(var, vl.clone()),
                        id.to_smolstr(),
                        src.clone(),
                    )));
                    tail = rest;
                }
                // field of arbitrary expr
                (Some(Expr(e)), [Some(Field(i)), rest @ ..]) => {
                    let expr = mem::replace(e, ast::Expr::val(false));
                    let id = mem::replace(i, ast::Id::new_unchecked(""));
                    head = Some(Expr(construct_expr_attr(
                        expr,
                        id.to_smolstr(),
                        src.clone(),
                    )));
                    tail = rest;
                }
                // field of string literal (same as Expr case)
                (Some(StrLit(s, sl)), [Some(Field(i)), rest @ ..]) => {
                    let id = mem::replace(i, ast::Id::new_unchecked(""));
                    let maybe_expr = match to_unescaped_string(s) {
                        Ok(s) => Some(construct_expr_string(s, sl.clone())),
                        Err(escape_errs) => {
                            errs.extend(
                                escape_errs
                                    .into_iter()
                                    .map(|e| ParseError::ToAST(e.to_string())),
                            );
                            None
                        }
                    };
                    head = maybe_expr
                        .map(|e| Expr(construct_expr_attr(e, id.to_smolstr(), src.clone())));
                    tail = rest;
                }
                // index into var
                (Some(Var(v, vl)), [Some(Index(i)), rest @ ..]) => {
                    let var = mem::replace(v, ast::Var::Principal);
                    let s = mem::take(i);
                    head = Some(Expr(construct_expr_attr(
                        construct_expr_var(var, vl.clone()),
                        s,
                        src.clone(),
                    )));
                    tail = rest;
                }
                // index into arbitrary expr
                (Some(Expr(e)), [Some(Index(i)), rest @ ..]) => {
                    let expr = mem::replace(e, ast::Expr::val(false));
                    let s = mem::take(i);
                    head = Some(Expr(construct_expr_attr(expr, s, src.clone())));
                    tail = rest;
                }
                // index into string literal (same as Expr case)
                (Some(StrLit(s, sl)), [Some(Index(i)), rest @ ..]) => {
                    let id = mem::take(i);
                    let maybe_expr = match to_unescaped_string(s) {
                        Ok(s) => Some(construct_expr_string(s, sl.clone())),
                        Err(escape_errs) => {
                            errs.extend(
                                escape_errs
                                    .into_iter()
                                    .map(|e| ParseError::ToAST(e.to_string())),
                            );
                            None
                        }
                    };
                    head = maybe_expr.map(|e| Expr(construct_expr_attr(e, id, src.clone())));
                    tail = rest;
                }
            }
        }
    }
}

impl ASTNode<Option<cst::MemAccess>> {
    fn to_access(&self, errs: Errs<'_>) -> Option<AstAccessor> {
        let maybe_acc = self.as_inner();
        // return right away if there's no data, parse provided error
        let acc = maybe_acc?;

        match acc {
            cst::MemAccess::Field(i) => {
                let ident = i.to_valid_ident(errs);
                ident.map(AstAccessor::Field)
            }
            cst::MemAccess::Call(args) => {
                let conv_args: Vec<_> = args.iter().filter_map(|e| e.to_expr(errs)).collect();
                if conv_args.len() == args.len() {
                    Some(AstAccessor::Call(conv_args))
                } else {
                    None
                }
            }
            cst::MemAccess::Index(index) => {
                let s = index.to_expr_or_special(errs)?.into_string_literal(errs);
                s.map(AstAccessor::Index)
            }
        }
    }
}

impl ASTNode<Option<cst::Primary>> {
    fn to_ref_or_refs<T: RefKind>(&self, errs: Errs<'_>, var: ast::Var) -> Option<T> {
        let maybe_prim = self.as_inner();
        let prim = maybe_prim?;
        let r: Result<Option<T>, String> = match prim {
            cst::Primary::Slot(s) => {
                let slot = s.as_inner()?;
                if slot.matches(var) {
                    Ok(T::create_slot(errs))
                } else {
                    Err(format!(
                        "A slot here must be named ?{}, found ?{}",
                        var, slot
                    ))
                }
            }
            cst::Primary::Literal(_) => {
                Err(format!("expected {} found a literal", T::err_string()))
            }
            cst::Primary::Ref(x) => Ok(T::create_single_ref(x.to_ref(errs)?, errs)),
            cst::Primary::Name(_) => Err(format!("expected {} found a name", T::err_string())),
            cst::Primary::Expr(x) => Ok(x.to_ref_or_refs::<T>(errs, var)),
            cst::Primary::EList(lst) => {
                let v: Option<Vec<EntityUID>> =
                    lst.iter().map(|expr| expr.to_ref(var, errs)).collect();
                Ok(T::create_multiple_refs(v?, errs))
            }
            cst::Primary::RInits(_) => Err("record initializer".to_string()),
        };
        match r {
            Ok(t) => t,
            Err(found) => {
                errs.push(err::ParseError::ToAST(format!(
                    "expected {}, found {}",
                    T::err_string(),
                    found
                )));
                None
            }
        }
    }

    pub(crate) fn to_expr(&self, errs: Errs<'_>) -> Option<ast::Expr> {
        self.to_expr_or_special(errs)?.into_expr(errs)
    }
    fn to_expr_or_special(&self, errs: Errs<'_>) -> Option<ExprOrSpecial<'_>> {
        let (src, maybe_prim) = self.as_inner_pair();
        // return right away if there's no data, parse provided error
        let prim = maybe_prim?;

        match prim {
            cst::Primary::Literal(l) => l.to_expr_or_special(errs),
            cst::Primary::Ref(r) => r.to_expr(errs).map(ExprOrSpecial::Expr),
            cst::Primary::Slot(s) => s.to_expr(errs).map(ExprOrSpecial::Expr),
            #[allow(clippy::manual_map)]
            cst::Primary::Name(n) => {
                // if `n` isn't a var we don't want errors, we'll get them later
                if let Some(v) = n.to_var(&mut Vec::new()) {
                    Some(ExprOrSpecial::Var(v, src.clone()))
                } else if let Some(n) = n.to_name(errs) {
                    Some(ExprOrSpecial::Name(n))
                } else {
                    None
                }
            }
            cst::Primary::Expr(e) => e.to_expr(errs).map(ExprOrSpecial::Expr),
            cst::Primary::EList(es) => {
                let list: Vec<_> = es.iter().filter_map(|e| e.to_expr(errs)).collect();
                if list.len() == es.len() {
                    Some(ExprOrSpecial::Expr(construct_expr_set(list, src.clone())))
                } else {
                    None
                }
            }
            cst::Primary::RInits(is) => {
                let rec: Vec<_> = is.iter().filter_map(|i| i.to_init(errs)).collect();
                if rec.len() == is.len() {
                    Some(ExprOrSpecial::Expr(construct_expr_record(rec, src.clone())))
                } else {
                    errs.push(err::ParseError::ToAST(
                        "record literal has some invalid attributes".to_string(),
                    ));
                    None
                }
            }
        }
    }

    /// convert `cst::Primary` representing a string literal to a `SmolStr`.
    /// Fails (and adds to `errs`) if the `Primary` wasn't a string literal.
    pub fn to_string_literal(&self, errs: Errs<'_>) -> Option<SmolStr> {
        let maybe_prim = self.as_inner();
        // return right away if there's no data, parse provided error
        let prim = maybe_prim?;

        match prim {
            cst::Primary::Literal(l) => l.to_expr_or_special(errs)?.into_string_literal(errs),
            _ => {
                errs.push(err::ParseError::ToAST(format!(
                    "{prim} is not a string literal"
                )));
                None
            }
        }
    }
}

impl ASTNode<Option<cst::Slot>> {
    fn to_expr(&self, _errs: Errs<'_>) -> Option<ast::Expr> {
        let (src, s) = self.as_inner_pair();
        s.map(|s| {
            ast::ExprBuilder::new()
                .with_source_info(src.clone())
                .slot(match s {
                    cst::Slot::Principal => ast::SlotId::principal(),
                    cst::Slot::Resource => ast::SlotId::resource(),
                })
        })
    }
}

impl ASTNode<Option<cst::Name>> {
    /// Build type constraints
    fn to_type_constraint(&self, errs: Errs<'_>) -> Option<ast::Expr> {
        let (src, maybe_name) = self.as_inner_pair();
        match maybe_name {
            Some(_) => {
                errs.push(err::ParseError::ToAST(
                    "type constraints are not currently supported".to_string(),
                ));
                None
            }
            None => Some(construct_expr_bool(true, src.clone())),
        }
    }

    pub(crate) fn to_name(&self, errs: Errs<'_>) -> Option<ast::Name> {
        let maybe_name = self.as_inner();
        // return right away if there's no data, parse provided error
        let name = maybe_name?;

        let path: Vec<_> = name
            .path
            .iter()
            .filter_map(|i| i.to_valid_ident(errs))
            .collect();
        let maybe_name = name.name.to_valid_ident(errs);

        // computation and error generation is complete, so fail or construct
        match (maybe_name, path.len()) {
            (Some(r), l) if l == name.path.len() => Some(construct_name(path, r)),
            _ => None,
        }
    }
    fn to_ident(&self, errs: Errs<'_>) -> Option<&cst::Ident> {
        let maybe_name = self.as_inner();
        // return right away if there's no data, parse provided error
        let name = maybe_name?;

        let path: Vec<_> = name
            .path
            .iter()
            .filter_map(|i| i.to_valid_ident(errs))
            .collect();
        if path.len() > 1 {
            errs.push(err::ParseError::ToAST(
                "A path is not valid in this context".to_string(),
            ));
            return None;
        }

        name.name.as_inner()
    }
    fn to_var(&self, errs: Errs<'_>) -> Option<ast::Var> {
        let name = self.to_ident(errs)?;

        match name {
            cst::Ident::Principal => Some(ast::Var::Principal),
            cst::Ident::Action => Some(ast::Var::Action),
            cst::Ident::Resource => Some(ast::Var::Resource),
            cst::Ident::Context => Some(ast::Var::Context),
            _ => {
                errs.push(err::ParseError::ToAST(
                    "This is not a variable, use principal, action, resource, or context"
                        .to_string(),
                ));
                None
            }
        }
    }
}

impl ast::Name {
    /// Convert the `Name` into a `String` attribute, which fails if it had any namespaces
    fn into_valid_attr(self, errs: Errs<'_>) -> Option<SmolStr> {
        if !self.path.is_empty() {
            errs.push(err::ParseError::ToAST(
                "A name with a path is not a valid attribute".to_string(),
            ));
            None
        } else {
            Some(self.id.to_smolstr())
        }
    }

    fn into_func(self, args: Vec<ast::Expr>, errs: Errs<'_>, l: SourceInfo) -> Option<ast::Expr> {
        // error on standard methods
        if self.path.is_empty() {
            let id = self.id.as_ref();
            match id {
                "contains" | "containsAll" | "containsAny" => {
                    errs.push(err::ParseError::ToAST(format!(
                        "invalid syntax, use method-style function call like e.{}(...)",
                        id
                    )));
                    return None;
                }
                _ => {}
            }
        }
        if EXTENSION_STYLES.functions.contains(&self) {
            Some(construct_ext_func(self, args, l))
        } else {
            errs.push(err::ParseError::ToAST(format!(
                "invalid syntax, expected function, found {}",
                self
            )));
            None
        }
    }
}

impl ASTNode<Option<cst::Ref>> {
    /// convert `cst::Ref` to `ast::EntityUID`
    pub fn to_ref(&self, errs: Errs<'_>) -> Option<ast::EntityUID> {
        let maybe_ref = self.as_inner();
        // return right away if there's no data, parse provided error
        let refr = maybe_ref?;

        match refr {
            cst::Ref::Uid { path, eid } => {
                let maybe_path = path.to_name(errs);
                let maybe_eid = match eid
                    .as_valid_string(errs)
                    .map(|s| to_unescaped_string(s))
                    .transpose()
                {
                    Ok(opt) => opt,
                    Err(escape_errs) => {
                        errs.extend(
                            escape_errs
                                .into_iter()
                                .map(|e| ParseError::ToAST(e.to_string())),
                        );
                        None
                    }
                };

                match (maybe_path, maybe_eid) {
                    (Some(p), Some(e)) => Some(construct_refr(p, e)),
                    _ => None,
                }
            }
            cst::Ref::Ref { .. } => {
                errs.push(err::ParseError::ToAST(
                    "arbitrary entity lookups are not currently supported".to_string(),
                ));
                None
            }
        }
    }
    fn to_expr(&self, errs: Errs<'_>) -> Option<ast::Expr> {
        self.to_ref(errs)
            .map(|euid| construct_expr_ref(euid, self.info.clone()))
    }
}

impl ASTNode<Option<cst::Literal>> {
    fn to_expr_or_special(&self, errs: Errs<'_>) -> Option<ExprOrSpecial<'_>> {
        let (src, maybe_lit) = self.as_inner_pair();
        // return right away if there's no data, parse provided error
        let lit = maybe_lit?;

        match lit {
            cst::Literal::True => Some(ExprOrSpecial::Expr(construct_expr_bool(true, src.clone()))),
            cst::Literal::False => {
                Some(ExprOrSpecial::Expr(construct_expr_bool(false, src.clone())))
            }
            cst::Literal::Num(n) => match i64::try_from(*n) {
                Ok(i) => Some(ExprOrSpecial::Expr(construct_expr_num(i, src.clone()))),
                Err(_) => {
                    errs.push(ParseError::ToAST(format!("Literal {n} is too large")));
                    None
                }
            },
            cst::Literal::Str(s) => {
                let maybe_str = s.as_valid_string(errs);
                maybe_str.map(|s| ExprOrSpecial::StrLit(s, src.clone()))
            }
        }
    }
}

impl ASTNode<Option<cst::RecInit>> {
    fn to_init(&self, errs: Errs<'_>) -> Option<(SmolStr, ast::Expr)> {
        let (_src, maybe_lit) = self.as_inner_pair();
        // return right away if there's no data, parse provided error
        let lit = maybe_lit?;

        let maybe_attr = lit.0.to_expr_or_special(errs)?.into_valid_attr(errs);
        let maybe_value = lit.1.to_expr(errs);

        match (maybe_attr, maybe_value) {
            (Some(s), Some(v)) => Some((s, v)),
            _ => None,
        }
    }
}

/// This section (construct_*) exists to handle differences between standard ast constructors and
/// the needs or conveniences here. Especially concerning source location data.
#[allow(clippy::too_many_arguments)]
fn construct_template_policy(
    id: ast::PolicyID,
    annotations: BTreeMap<ast::Id, SmolStr>,
    effect: ast::Effect,
    principal: ast::PrincipalConstraint,
    action: ast::ActionConstraint,
    resource: ast::ResourceConstraint,
    conds: Vec<ast::Expr>,
    l: SourceInfo,
) -> ast::Template {
    let construct_template = |non_head_constraint| {
        ast::Template::new(
            id,
            annotations,
            effect,
            principal,
            action,
            resource,
            non_head_constraint,
        )
    };
    let mut conds_iter = conds.into_iter();
    if let Some(first_expr) = conds_iter.next() {
        // a left fold of conditions
        // e.g., [c1, c2, c3,] --> ((c1 && c2) && c3)
        construct_template(match conds_iter.next() {
            Some(e) => construct_expr_and(first_expr, e, conds_iter, l),
            None => first_expr,
        })
    } else {
        // use `true` to mark the absence of non-head constraints
        construct_template(construct_expr_bool(true, l))
    }
}
fn construct_id(s: String) -> ast::Id {
    ast::Id::new_unchecked(s)
}
fn construct_string_from_var(v: ast::Var) -> SmolStr {
    match v {
        ast::Var::Principal => "principal".into(),
        ast::Var::Action => "action".into(),
        ast::Var::Resource => "resource".into(),
        ast::Var::Context => "context".into(),
    }
}
fn construct_name(path: Vec<ast::Id>, id: ast::Id) -> ast::Name {
    ast::Name {
        id,
        path: Arc::new(path),
    }
}
fn construct_refr(p: ast::Name, n: SmolStr) -> ast::EntityUID {
    let eid = ast::Eid::new(n);
    ast::EntityUID::from_components(p, eid)
}
fn construct_expr_ref(r: ast::EntityUID, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new().with_source_info(l).val(r)
}
fn construct_expr_num(n: i64, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new().with_source_info(l).val(n)
}
fn construct_expr_string(s: SmolStr, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new().with_source_info(l).val(s)
}
fn construct_expr_bool(b: bool, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new().with_source_info(l).val(b)
}
fn construct_expr_neg(e: ast::Expr, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new().with_source_info(l).neg(e)
}
fn construct_expr_not(e: ast::Expr, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new().with_source_info(l).not(e)
}
fn construct_expr_var(v: ast::Var, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new().with_source_info(l).var(v)
}
fn construct_expr_if(i: ast::Expr, t: ast::Expr, e: ast::Expr, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new().with_source_info(l).ite(i, t, e)
}
fn construct_expr_or(
    f: ast::Expr,
    s: ast::Expr,
    chained: impl IntoIterator<Item = ast::Expr>,
    l: SourceInfo,
) -> ast::Expr {
    let first = ast::ExprBuilder::new().with_source_info(l.clone()).or(f, s);
    chained.into_iter().fold(first, |a, n| {
        ast::ExprBuilder::new().with_source_info(l.clone()).or(a, n)
    })
}
fn construct_expr_and(
    f: ast::Expr,
    s: ast::Expr,
    chained: impl IntoIterator<Item = ast::Expr>,
    l: SourceInfo,
) -> ast::Expr {
    let first = ast::ExprBuilder::new()
        .with_source_info(l.clone())
        .and(f, s);
    chained.into_iter().fold(first, |a, n| {
        ast::ExprBuilder::new()
            .with_source_info(l.clone())
            .and(a, n)
    })
}
fn construct_expr_rel(f: ast::Expr, rel: cst::RelOp, s: ast::Expr, l: SourceInfo) -> ast::Expr {
    let builder = ast::ExprBuilder::new().with_source_info(l);
    match rel {
        cst::RelOp::Less => builder.less(f, s),
        cst::RelOp::LessEq => builder.lesseq(f, s),
        cst::RelOp::GreaterEq => builder.greatereq(f, s),
        cst::RelOp::Greater => builder.greater(f, s),
        cst::RelOp::NotEq => builder.noteq(f, s),
        cst::RelOp::Eq => builder.is_eq(f, s),
        cst::RelOp::In => builder.is_in(f, s),
    }
}
/// used for a chain of addition and/or subtraction
fn construct_expr_add(
    f: ast::Expr,
    chained: impl IntoIterator<Item = (cst::AddOp, ast::Expr)>,
    l: SourceInfo,
) -> ast::Expr {
    let mut expr = f;
    for (op, next_expr) in chained {
        let builder = ast::ExprBuilder::new().with_source_info(l.clone());
        expr = match op {
            cst::AddOp::Plus => builder.add(expr, next_expr),
            cst::AddOp::Minus => builder.sub(expr, next_expr),
        };
    }
    expr
}
/// used for a chain of multiplication only (no division or mod)
fn construct_expr_mul(
    f: ast::Expr,
    chained: impl IntoIterator<Item = i64>,
    l: SourceInfo,
) -> ast::Expr {
    let mut expr = f;
    for next_expr in chained {
        expr = ast::ExprBuilder::new()
            .with_source_info(l.clone())
            .mul(expr, next_expr)
    }
    expr
}
fn construct_expr_has(t: ast::Expr, s: SmolStr, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new().with_source_info(l).has_attr(t, s)
}
fn construct_expr_attr(e: ast::Expr, s: SmolStr, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new().with_source_info(l).get_attr(e, s)
}
fn construct_expr_like(e: ast::Expr, s: Vec<PatternElem>, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new().with_source_info(l).like(e, s)
}
fn construct_ext_func(name: ast::Name, args: Vec<ast::Expr>, l: SourceInfo) -> ast::Expr {
    // INVARIANT (MethodStyleArgs): CallStyle is not MethodStyle, so any args vector is fine
    ast::ExprBuilder::new()
        .with_source_info(l)
        .call_extension_fn(name, args)
}

fn construct_method_contains(e0: ast::Expr, e1: ast::Expr, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new().with_source_info(l).contains(e0, e1)
}
fn construct_method_contains_all(e0: ast::Expr, e1: ast::Expr, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new()
        .with_source_info(l)
        .contains_all(e0, e1)
}
fn construct_method_contains_any(e0: ast::Expr, e1: ast::Expr, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new()
        .with_source_info(l)
        .contains_any(e0, e1)
}

// INVARIANT (MethodStyleArgs), args must be non-empty
fn construct_ext_meth(n: String, args: Vec<ast::Expr>, l: SourceInfo) -> ast::Expr {
    let id = ast::Id::new_unchecked(n);
    let name = ast::Name::unqualified_name(id);
    // INVARIANT (MethodStyleArgs), args must be non-empty
    ast::ExprBuilder::new()
        .with_source_info(l)
        .call_extension_fn(name, args)
}
fn construct_expr_set(s: Vec<ast::Expr>, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new().with_source_info(l).set(s)
}
fn construct_expr_record(kvs: Vec<(SmolStr, ast::Expr)>, l: SourceInfo) -> ast::Expr {
    ast::ExprBuilder::new().with_source_info(l).record(kvs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ast::Expr,
        parser::{err::ParseErrors, *},
    };
    use std::str::FromStr;

    #[test]
    fn show_expr1() {
        let mut errs = Vec::new();
        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            if 7 then 6 > 5 else !5 || "thursday" && ((8) >= "fish")
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");
        assert!(errs.is_empty());
        // manual check at test defn
        println!("{:?}", expr);
    }

    #[test]
    fn show_expr2() {
        let mut errs = Vec::new();
        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            [2,3,4].foo["hello"]
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");
        // manual check at test defn
        println!("{:?}", expr);
    }

    #[test]
    fn show_expr3() {
        // these exprs are ill-typed, but are allowed by the parser
        let mut errs = Vec::new();
        let expr = text_to_cst::parse_expr(
            r#"
            "first".some_ident
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");
        match expr.expr_kind() {
            ast::ExprKind::GetAttr { attr, .. } => {
                assert_eq!(attr, "some_ident");
            }
            _ => panic!("should be a get expr"),
        }

        let expr = text_to_cst::parse_expr(
            r#"
            1.some_ident
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");
        match expr.expr_kind() {
            ast::ExprKind::GetAttr { attr, .. } => {
                assert_eq!(attr, "some_ident");
            }
            _ => panic!("should be a get expr"),
        }

        let expr = text_to_cst::parse_expr(
            r#"
            "first"["some string"]
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");
        match expr.expr_kind() {
            ast::ExprKind::GetAttr { attr, .. } => {
                assert_eq!(attr, "some string");
            }
            _ => panic!("should be a get expr"),
        }
    }

    #[test]
    fn show_expr4() {
        let mut errs = Vec::new();
        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            {"one":1,"two":2} has one
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");

        match expr.expr_kind() {
            ast::ExprKind::HasAttr { attr, .. } => {
                assert_eq!(attr, "one");
            }
            _ => panic!("should be a has expr"),
        }
    }

    #[test]
    fn show_expr5() {
        let mut errs = Vec::new();
        let expr = text_to_cst::parse_expr(
            r#"
            {"one":1,"two":2}.one
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");

        match expr.expr_kind() {
            ast::ExprKind::GetAttr { attr, .. } => {
                assert_eq!(attr, "one");
            }
            _ => panic!("should be a get expr"),
        }

        // parses to the same AST expression as above
        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            {"one":1,"two":2}["one"]
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");

        match expr.expr_kind() {
            ast::ExprKind::GetAttr { attr, .. } => {
                assert_eq!(attr, "one");
            }
            _ => panic!("should be a get expr"),
        }

        // accessing a record with a non-identifier attribute
        let mut errs = Vec::new();
        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            {"this is a valid map key+.-_%()":1,"two":2}["this is a valid map key+.-_%()"]
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");

        match expr.expr_kind() {
            ast::ExprKind::GetAttr { attr, .. } => {
                assert_eq!(attr, "this is a valid map key+.-_%()");
            }
            _ => panic!("should be a get expr"),
        }
    }

    #[test]
    fn show_expr6_idents() {
        let mut errs = Vec::new();
        let expr = text_to_cst::parse_expr(
            r#"
            {if true then a else b:"b"} ||
            {if false then a else b:"b"}
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs);

        println!("{:?}", errs);
        assert!(expr.is_none());
        // a,b,a,b: unsupported variables
        // if .. then .. else are invalid attributes
        assert!(errs.len() == 6);

        errs.clear();
        let expr = text_to_cst::parse_expr(
            r#"
            {principal:"principal"}
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");

        println!("{:?}", expr);
        match expr.expr_kind() {
            ast::ExprKind::Record { .. } => {}
            _ => panic!("should be record"),
        }

        errs.clear();
        let expr = text_to_cst::parse_expr(
            r#"
            {"principal":"principal"}
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");

        println!("{:?}", expr);
        match expr.expr_kind() {
            ast::ExprKind::Record { .. } => {}
            _ => panic!("should be record"),
        }
    }

    #[test]
    fn reserved_idents1() {
        let mut errs = Vec::new();
        let parse = text_to_cst::parse_expr(
            r#"
            The::true::path::to::"enlightenment".false
        "#,
        )
        .expect("failed parse");

        let convert = parse.to_expr(&mut errs);
        println!("{:?}", errs);
        // uses true and false:
        assert!(errs.len() == 2);
        assert!(convert.is_none());

        let mut errs = Vec::new();
        let parse = text_to_cst::parse_expr(
            r#"
            if {if: true}.if then {"if":false}["if"] else {when:true}.permit
        "#,
        )
        .expect("failed parse");

        let convert = parse.to_expr(&mut errs);
        println!("{:?}", errs);
        // uses if twice, one of those triggers an invalid attr
        assert!(errs.len() == 3);
        assert!(convert.is_none());
    }

    #[test]
    fn reserved_idents2() {
        let mut errs = Vec::new();
        let parse = text_to_cst::parse_expr(
            r#"
            if {where: true}.like || {has:false}.in then {"like":false}["in"] else {then:true}.else
        "#,
        )
        .expect("failed parse");

        let convert = parse.to_expr(&mut errs);
        println!("{:?}", errs);
        // uses 5x reserved idents, 2 of those trigger an invalid attr
        assert!(errs.len() == 7);
        assert!(convert.is_none());
    }

    #[test]
    fn show_policy1() {
        let mut errs = Vec::new();
        let parse = text_to_cst::parse_policy(
            r#"
            permit(principal:p,action:a,resource:r)when{w}unless{u}advice{"doit"};
        "#,
        )
        .expect("failed parse");
        println!("{:#}", parse.as_inner().expect("internal parse error"));
        let convert = parse.to_policy(ast::PolicyID::from_string("id"), &mut errs);
        println!("{:?}", errs);
        // 3x type constraints, 2x arbitrary vars, advice block
        assert!(errs.len() == 6);
        assert!(convert.is_none());
        // manual check at test defn
        println!("{:?}", convert);
    }

    #[test]
    fn show_policy2() {
        let mut errs = Vec::new();
        let parse = text_to_cst::parse_policy(
            r#"
            permit(principal,action,resource)when{true};
        "#,
        )
        .expect("failed parse");
        println!("{}", parse.as_inner().expect("internal parse error"));
        println!("{:?}", parse.as_inner().expect("internal parse error"));
        let convert = parse.to_policy(ast::PolicyID::from_string("id"), &mut errs);
        assert!(convert.is_some());
        // manual check at test defn
        println!("{:?}", convert);
    }

    #[test]
    fn show_policy3() {
        let mut errs = Vec::new();
        let parse = text_to_cst::parse_policy(
            r#"
            permit(principal in User::"jane",action,resource);
        "#,
        )
        .expect("failed parse");
        println!("{}", parse.as_inner().expect("internal parse error"));
        println!("{:?}", parse.as_inner().expect("internal parse error"));
        let convert = parse
            .to_policy(ast::PolicyID::from_string("id"), &mut errs)
            .expect("failed convert");
        assert!(errs.is_empty());
        // manual check at test defn
        println!("{:?}", convert);
    }

    #[test]
    fn show_policy4() {
        let mut errs = Vec::new();
        let parse = text_to_cst::parse_policy(
            r#"
            forbid(principal in User::"jane",action,resource)unless{
                context.group != "friends"
            };
        "#,
        )
        .expect("failed parse");
        let convert = parse
            .to_policy(ast::PolicyID::from_string("id"), &mut errs)
            .expect("failed convert");
        assert!(errs.is_empty());
        // manual check at test defn
        println!("\n{:?}", convert);
    }

    #[test]
    fn policy_annotations() {
        // common use-case
        let mut errs = Vec::new();
        let policy = text_to_cst::parse_policy(
            r#"
            @anno("good annotation")permit(principal,action,resource);
        "#,
        )
        .expect("should parse")
        .to_policy(ast::PolicyID::from_string("id"), &mut errs)
        .expect("should be valid");
        assert_eq!(
            policy.annotation(&ast::Id::new_unchecked("anno")),
            Some(&"good annotation".into())
        );

        // duplication is error
        let mut errs = Vec::new();
        let policy = text_to_cst::parse_policy(
            r#"
            @anno("good annotation")
            @anno2("good annotation")
            @anno("oops, duplicate")
            permit(principal,action,resource);
        "#,
        )
        .expect("should parse")
        .to_policy(ast::PolicyID::from_string("id"), &mut errs);
        assert!(policy.is_none());
        // annotation duplication (anno)
        assert!(errs.len() == 1);

        // can have multiple annotations
        let mut errs = Vec::new();
        let policyset = text_to_cst::parse_policies(
            r#"
            @anno1("first")
            permit(principal,action,resource);

            @anno2("second")
            permit(principal,action,resource);

            @anno3a("third-a")
            @anno3b("third-b")
            permit(principal,action,resource);
        "#,
        )
        .expect("should parse")
        .to_policyset(&mut errs)
        .expect("should be valid");
        assert_eq!(
            policyset
                .get(&ast::PolicyID::from_string("policy0"))
                .expect("should be a policy")
                .annotation(&ast::Id::new_unchecked("anno0")),
            None
        );
        assert_eq!(
            policyset
                .get(&ast::PolicyID::from_string("policy0"))
                .expect("should be a policy")
                .annotation(&ast::Id::new_unchecked("anno1")),
            Some(&"first".into())
        );
        assert_eq!(
            policyset
                .get(&ast::PolicyID::from_string("policy1"))
                .expect("should be a policy")
                .annotation(&ast::Id::new_unchecked("anno2")),
            Some(&"second".into())
        );
        assert_eq!(
            policyset
                .get(&ast::PolicyID::from_string("policy2"))
                .expect("should be a policy")
                .annotation(&ast::Id::new_unchecked("anno3a")),
            Some(&"third-a".into())
        );
        assert_eq!(
            policyset
                .get(&ast::PolicyID::from_string("policy2"))
                .expect("should be a policy")
                .annotation(&ast::Id::new_unchecked("anno3b")),
            Some(&"third-b".into())
        );
        assert_eq!(
            policyset
                .get(&ast::PolicyID::from_string("policy2"))
                .expect("should be a policy")
                .annotation(&ast::Id::new_unchecked("anno3c")),
            None
        );
        assert_eq!(
            policyset
                .get(&ast::PolicyID::from_string("policy2"))
                .expect("should be a policy")
                .annotations()
                .count(),
            2
        );
    }

    #[test]
    fn fail_head1() {
        let mut errs = Vec::new();
        let parse = text_to_cst::parse_policy(
            r#"
            permit(
                principal in [User::"jane",Group::"friends"],
                action,
                resource
            );
        "#,
        )
        .expect("failed parse");
        println!("\n{:#}", parse.as_inner().expect("internal parse error"));
        let convert = parse.to_policy(ast::PolicyID::from_string("id"), &mut errs);
        println!("{:?}", errs);
        assert!(errs.len() == 1);
        assert!(convert.is_none());
    }

    #[test]
    fn fail_head2() {
        let mut errs = Vec::new();
        let parse = text_to_cst::parse_policy(
            r#"
            permit(
                principal in User::"jane",
                action == if true then Photo::"view" else Photo::"edit",
                resource
            );
        "#,
        )
        .expect("failed parse");
        println!("{:#}", parse.as_inner().expect("internal parse error"));
        let convert = parse.to_policy(ast::PolicyID::from_string("id"), &mut errs);
        println!("{:?}", errs);
        assert!(errs.len() == 1);
        assert!(convert.is_none());
    }

    #[test]
    fn fail_head3() {
        let mut errs = Vec::new();
        let parse = text_to_cst::parse_policy(
            r#"
            permit(principal,action,resource,context);
        "#,
        )
        .expect("failed parse");
        let convert = parse.to_policy(ast::PolicyID::from_string("id"), &mut errs);
        assert!(errs.len() == 1);
        assert!(convert.is_none());
    }

    #[test]
    fn method_call2() {
        let mut errs = Vec::new();
        let e = text_to_cst::parse_expr(
            r#"
                principal.contains(resource)
                "#,
        )
        // the cst should be acceptable
        .expect("parse error")
        .to_expr(&mut errs);
        // ast should be acceptable
        println!("{:?}", errs);
        assert!(e.is_some());
        assert!(errs.is_empty());

        let e = text_to_cst::parse_expr(
            r#"
            contains(principal,resource)
            "#,
        )
        // cst should be acceptable
        .expect("parse error")
        .to_expr(&mut errs);
        // ast should be error, since "contains" is used inappropriately
        println!("{:?}", errs);
        assert!(e.is_none());
        assert!(errs.len() == 1);
    }

    #[test]
    fn construct_record1() {
        let mut errs = Vec::new();
        let e = text_to_cst::parse_expr(
            r#"
                {one:"one"}
                "#,
        )
        // the cst should be acceptable
        .expect("parse error")
        .to_expr(&mut errs)
        .expect("convert fail");
        // ast should be acceptable, with record construction
        if let ast::ExprKind::Record { .. } = e.expr_kind() {
            // good
        } else {
            panic!("not a record")
        }
        println!("{e}");

        let e = text_to_cst::parse_expr(
            r#"
                {"one":"one"}
                "#,
        )
        // the cst should be acceptable
        .expect("parse error")
        .to_expr(&mut errs)
        .expect("convert fail");
        // ast should be acceptable, with record construction
        if let ast::ExprKind::Record { .. } = e.expr_kind() {
            // good
        } else {
            panic!("not a record")
        }
        println!("{e}");

        let e = text_to_cst::parse_expr(
            r#"
                {"one":"one",two:"two"}
                "#,
        )
        // the cst should be acceptable
        .expect("parse error")
        .to_expr(&mut errs)
        .expect("convert fail");
        // ast should be acceptable, with record construction
        if let ast::ExprKind::Record { .. } = e.expr_kind() {
            // good
        } else {
            panic!("not a record")
        }
        println!("{e}");

        let e = text_to_cst::parse_expr(
            r#"
                {one:"one","two":"two"}
                "#,
        )
        // the cst should be acceptable
        .expect("parse error")
        .to_expr(&mut errs)
        .expect("convert fail");
        // ast should be acceptable, with record construction
        if let ast::ExprKind::Record { .. } = e.expr_kind() {
            // good
        } else {
            panic!("not a record")
        }
        println!("{e}");

        let e = text_to_cst::parse_expr(
            r#"
                {one:"b\"","b\"":2}
                "#,
        )
        // the cst should be acceptable
        .expect("parse error")
        .to_expr(&mut errs)
        .expect("convert fail");
        // ast should be acceptable, with record construction
        if let ast::ExprKind::Record { .. } = e.expr_kind() {
            // good
        } else {
            panic!("not a record")
        }
        println!("{e}");
    }

    #[test]
    fn construct_invalid_get() {
        let mut errs = Vec::new();
        let e = text_to_cst::parse_expr(
            r#"
            {"one":1, "two":"two"}[0]
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs);
        // ast should be error: 0 is not a string literal
        println!("{:?}", errs);
        assert!(e.is_none());
        assert!(errs.len() == 1);

        let e = text_to_cst::parse_expr(
            r#"
            {"one":1, "two":"two"}[-1]
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs);
        // ast should be error: -1 is not a string literal
        println!("{:?}", errs);
        assert!(e.is_none());

        let e = text_to_cst::parse_expr(
            r#"
            {"one":1, "two":"two"}[true]
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs);
        // ast should be error: true is not a string literal
        println!("{:?}", errs);
        assert!(e.is_none());

        let e = text_to_cst::parse_expr(
            r#"
            {"one":1, "two":"two"}[one]
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs);
        // ast should be error: one is not a string literal
        println!("{:?}", errs);
        assert!(e.is_none());
    }

    #[test]
    fn construct_has() {
        let mut errs = Vec::new();
        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            {"one":1,"two":2} has "arbitrary+ _string"
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");

        match expr.expr_kind() {
            ast::ExprKind::HasAttr { attr, .. } => {
                assert_eq!(attr, "arbitrary+ _string");
            }
            _ => panic!("should be a has expr"),
        }

        let mut errs = Vec::new();
        let e = text_to_cst::parse_expr(
            r#"
            {"one":1,"two":2} has 1
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs);
        // ast should be error
        println!("{:?}", errs);
        assert!(e.is_none());
        assert!(errs.len() == 1);
    }

    #[test]
    fn construct_like() {
        let mut errs = Vec::new();
        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            "354 hams" like "*5*"
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");
        match expr.expr_kind() {
            ast::ExprKind::Like { pattern, .. } => {
                assert_eq!(pattern.to_string(), "*5*");
            }
            _ => panic!("should be a like expr"),
        }

        let e = text_to_cst::parse_expr(
            r#"
            "354 hams" like 354
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs);
        // ast should be error
        println!("{:?}", errs);
        assert!(e.is_none());
        assert!(errs.len() == 1);

        let mut errs = Vec::new();
        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            "string\\with\\backslashes" like "string\\with\\backslashes"
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");
        match expr.expr_kind() {
            ast::ExprKind::Like { pattern, .. } => {
                assert_eq!(pattern.to_string(), r#"string\\with\\backslashes"#);
            }
            _ => panic!("should be a like expr"),
        }

        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            "string\\with\\backslashes" like "string\*with\*backslashes"
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");
        match expr.expr_kind() {
            ast::ExprKind::Like { pattern, .. } => {
                assert_eq!(pattern.to_string(), r#"string\*with\*backslashes"#);
            }
            _ => panic!("should be a like expr"),
        }

        let e = text_to_cst::parse_expr(
            r#"
            "string\*with\*escaped\*stars" like "string\*with\*escaped\*stars"
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs);
        // ast should be error, \* is not a valid string character
        println!("{:?}", errs);
        assert!(e.is_none());
        assert!(errs.len() == 3); // 3 invalid escapes in the first argument

        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            "string*with*stars" like "string\*with\*stars"
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");
        match expr.expr_kind() {
            ast::ExprKind::Like { pattern, .. } => {
                assert_eq!(pattern.to_string(), "string\\*with\\*stars");
            }
            _ => panic!("should be a like expr"),
        }

        let mut errs = Vec::new();
        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            "string\\*with\\*backslashes\\*and\\*stars" like "string\\\*with\\\*backslashes\\\*and\\\*stars"
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");
        match expr.expr_kind() {
            ast::ExprKind::Like { pattern, .. } => {
                assert_eq!(
                    pattern.to_string(),
                    r#"string\\\*with\\\*backslashes\\\*and\\\*stars"#
                );
            }
            _ => panic!("should be a like expr"),
        }
        // round trip test
        let test_pattern = &vec![
            PatternElem::Char('h'),
            PatternElem::Char('e'),
            PatternElem::Char('l'),
            PatternElem::Char('l'),
            PatternElem::Char('o'),
            PatternElem::Char('\\'),
            PatternElem::Char('0'),
            PatternElem::Char('*'),
            PatternElem::Char('\\'),
            PatternElem::Char('*'),
        ];
        let e1 = ast::Expr::like(ast::Expr::val("hello"), test_pattern.clone());
        let s1 = format!("{e1}");
        // Char('\\') prints to r#"\\"# and Char('*') prints to r#"\*"#.
        assert_eq!(s1, r#""hello" like "hello\\0\*\\\*""#);
        let e2 = text_to_cst::parse_expr(&s1)
            .expect("failed parser")
            .to_expr(&mut errs)
            .expect("failed convert");
        match e2.expr_kind() {
            ast::ExprKind::Like { pattern, .. } => {
                assert_eq!(pattern.get_elems(), test_pattern);
            }
            _ => panic!("should be a like expr"),
        }
        let s2 = format!("{e2}");
        assert_eq!(s1, s2);
    }

    #[test]
    fn issue_wf_5046() {
        let policy = parse_policy(
            Some("WF-5046".into()),
            r#"permit(
            principal,
            action in [Action::"action"],
            resource in G::""
          ) when {
            true && ("" like "/gisterNatives\\*D")
          };"#,
        );
        assert!(policy.is_ok());
    }

    #[test]
    fn entity_access() {
        // entities can be accessed using the same notation as records

        // ok
        let mut errs = Vec::new();
        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            User::"jane" has age
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");
        match expr.expr_kind() {
            ast::ExprKind::HasAttr { attr, .. } => {
                assert_eq!(attr, "age");
            }
            _ => panic!("should be a has expr"),
        }

        // ok
        let mut errs = Vec::new();
        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            User::"jane" has "arbitrary+ _string"
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");
        match expr.expr_kind() {
            ast::ExprKind::HasAttr { attr, .. } => {
                assert_eq!(attr, "arbitrary+ _string");
            }
            _ => panic!("should be a has expr"),
        }

        // not ok: 1 is not a valid attribute
        let mut errs = Vec::new();
        let e = text_to_cst::parse_expr(
            r#"
            User::"jane" has 1
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs);
        assert!(e.is_none());
        assert!(errs.len() == 1);

        // ok
        let mut errs = Vec::new();
        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            User::"jane".age
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");
        match expr.expr_kind() {
            ast::ExprKind::GetAttr { attr, .. } => {
                assert_eq!(attr, "age");
            }
            _ => panic!("should be a get expr"),
        }

        // ok
        let mut errs = Vec::new();
        let expr: ast::Expr = text_to_cst::parse_expr(
            r#"
            User::"jane"["arbitrary+ _string"]
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs)
        .expect("failed convert");
        match expr.expr_kind() {
            ast::ExprKind::GetAttr { attr, .. } => {
                assert_eq!(attr, "arbitrary+ _string");
            }
            _ => panic!("should be a get expr"),
        }

        // not ok: age is not a string literal
        let mut errs = Vec::new();
        let e = text_to_cst::parse_expr(
            r#"
            User::"jane"[age]
        "#,
        )
        .expect("failed parser")
        .to_expr(&mut errs);
        assert!(e.is_none());
        assert!(errs.len() == 1);
    }

    #[test]
    fn relational_ops1() {
        let mut errs = Vec::new();
        let e = text_to_cst::parse_expr(
            r#"
                3 >= 2 >= 1
                "#,
        )
        // the cst should be acceptable
        .expect("parse error")
        .to_expr(&mut errs);
        // conversion should fail, too many relational ops
        assert!(e.is_none());

        let e = text_to_cst::parse_expr(
            r#"
                    3 >= ("dad" in "dad")
                    "#,
        )
        // the cst should be acceptable
        .expect("parse error")
        .to_expr(&mut errs);
        // conversion should succeed, only one relational op
        assert!(e.is_some());

        let e = text_to_cst::parse_expr(
            r#"
                (3 >= 2) == true
                "#,
        )
        // the cst should be acceptable
        .expect("parse error")
        .to_expr(&mut errs);
        // conversion should succeed, parentheses provided
        assert!(e.is_some());

        let e = text_to_cst::parse_expr(
            r#"
                if 4 < 3 then 4 != 3 else 4 == 3 < 4
                "#,
        )
        // the cst should be acceptable
        .expect("parse error")
        .to_expr(&mut errs);
        // conversion should fail, too many relational ops
        assert!(e.is_none());
    }

    #[test]
    fn arithmetic() {
        let mut errs = Vec::new();
        let e = text_to_cst::parse_expr(r#" 2 + 4 "#)
            // the cst should be acceptable
            .expect("parse error")
            .to_expr(&mut errs);
        // conversion should succeed
        assert!(e.is_some());

        let e = text_to_cst::parse_expr(r#" 2 + -5 "#)
            // the cst should be acceptable
            .expect("parse error")
            .to_expr(&mut errs);
        // conversion should succeed
        assert!(e.is_some());

        let e = text_to_cst::parse_expr(r#" 2 - 5 "#)
            // the cst should be acceptable
            .expect("parse error")
            .to_expr(&mut errs);
        // conversion should succeed
        assert!(e.is_some());

        let e = text_to_cst::parse_expr(r#" 2 * 5 "#)
            // the cst should be acceptable
            .expect("parse error")
            .to_expr(&mut errs);
        // conversion should succeed
        assert!(e.is_some());

        let e = text_to_cst::parse_expr(r#" 2 * -5 "#)
            // the cst should be acceptable
            .expect("parse error")
            .to_expr(&mut errs);
        // conversion should succeed
        assert!(e.is_some());

        let e = text_to_cst::parse_expr(r#" context.size * 4 "#)
            // the cst should be acceptable
            .expect("parse error")
            .to_expr(&mut errs);
        // conversion should succeed
        assert!(e.is_some());

        let e = text_to_cst::parse_expr(r#" 4 * context.size "#)
            // the cst should be acceptable
            .expect("parse error")
            .to_expr(&mut errs);
        // conversion should succeed
        assert!(e.is_some());

        let e = text_to_cst::parse_expr(r#" context.size * context.scale "#)
            // the cst should be acceptable
            .expect("parse error")
            .to_expr(&mut errs);
        // conversion should fail: only multiplication by a constant is allowed
        assert!(e.is_none());

        let e = text_to_cst::parse_expr(r#" 5 + 10 + 90 "#)
            // the cst should be acceptable
            .expect("parse error")
            .to_expr(&mut errs);
        // conversion should succeed
        assert!(e.is_some());

        let e = text_to_cst::parse_expr(r#" 5 + 10 - 90 * -2 "#)
            // the cst should be acceptable
            .expect("parse error")
            .to_expr(&mut errs);
        // conversion should succeed
        assert!(e.is_some());

        let e = text_to_cst::parse_expr(r#" 5 + 10 * 90 - 2 "#)
            // the cst should be acceptable
            .expect("parse error")
            .to_expr(&mut errs);
        // conversion should succeed
        assert!(e.is_some());

        let e = text_to_cst::parse_expr(r#" 5 - 10 - 90 - 2 "#)
            // the cst should be acceptable
            .expect("parse error")
            .to_expr(&mut errs);
        // conversion should succeed
        assert!(e.is_some());

        let e = text_to_cst::parse_expr(r#" 5 * context.size * 10 "#)
            // the cst should be acceptable
            .expect("parse error")
            .to_expr(&mut errs);
        // conversion should succeed
        assert!(e.is_some());

        let e = text_to_cst::parse_expr(r#" context.size * 3 * context.scale "#)
            // the cst should be acceptable
            .expect("parse error")
            .to_expr(&mut errs);
        // conversion should fail: only multiplication by a constant is allowed
        assert!(e.is_none());
    }

    const CORRECT_TEMPLATES: [&str; 7] = [
        r#"permit(principal == ?principal, action == Action::"action", resource == ?resource);"#,
        r#"permit(principal in ?principal, action == Action::"action", resource in ?resource);"#,
        r#"permit(principal in ?principal, action == Action::"action", resource in ?resource);"#,
        r#"permit(principal in p::"principal", action == Action::"action", resource in ?resource);"#,
        r#"permit(principal == p::"principal", action == Action::"action", resource in ?resource);"#,
        r#"permit(principal in ?principal, action == Action::"action", resource in r::"resource");"#,
        r#"permit(principal in ?principal, action == Action::"action", resource == r::"resource");"#,
    ];

    #[test]
    fn template_tests() {
        for src in CORRECT_TEMPLATES {
            let mut errs = Vec::new();
            let e = text_to_cst::parse_policy(src)
                .expect("parse_error")
                .to_policy_template(ast::PolicyID::from_string("i0"), &mut errs);
            if e.is_none() {
                panic!("Failed to create a policy template: {:?}", errs);
            }
        }
    }

    const WRONG_VAR_TEMPLATES: [&str; 16] = [
        r#"permit(principal == ?resource, action, resource);"#,
        r#"permit(principal in ?resource, action, resource);"#,
        r#"permit(principal, action, resource == ?principal);"#,
        r#"permit(principal, action, resource in ?principal);"#,
        r#"permit(principal, action == ?principal, resource);"#,
        r#"permit(principal, action in ?principal, resource);"#,
        r#"permit(principal, action == ?resource, resource);"#,
        r#"permit(principal, action in ?resource, resource);"#,
        r#"forbid(principal == ?resource, action, resource);"#,
        r#"forbid(principal in ?resource, action, resource);"#,
        r#"forbid(principal, action, resource == ?principal);"#,
        r#"forbid(principal, action, resource in ?principal);"#,
        r#"forbid(principal, action == ?principal, resource);"#,
        r#"forbid(principal, action in ?principal, resource);"#,
        r#"forbid(principal, action == ?resource, resource);"#,
        r#"forbid(principal, action in ?resource, resource);"#,
    ];

    #[test]
    fn test_wrong_template_var() {
        for src in WRONG_VAR_TEMPLATES {
            let mut errs = vec![];
            let e = text_to_cst::parse_policy(src)
                .expect("Parse Error")
                .to_policy_template(ast::PolicyID::from_string("id0"), &mut errs);
            assert!(e.is_none());
        }
    }

    #[test]
    fn var_type() {
        let mut errs = Vec::new();
        let e = text_to_cst::parse_policy(
            r#"
                permit(principal,action,resource);
                "#,
        )
        // the cst should be acceptable
        .expect("parse error")
        .to_policy(ast::PolicyID::from_string("0"), &mut errs);
        // conversion should succeed, it's just permit all
        assert!(e.is_some());
        let e = text_to_cst::parse_policy(
            r#"
                permit(principal:User,action,resource);
                "#,
        )
        // the cst should be acceptable
        .expect("parse error")
        .to_policy(ast::PolicyID::from_string("1"), &mut errs);
        // conversion should fail, variable types are not supported
        assert!(e.is_none());
    }
    #[test]
    fn string_escapes() {
        // test strings with valid escapes
        // convert a string `s` to `<double-quote> <escaped-form-of-s> <double-quote>`
        // and test if the resulting string literal AST contains exactly `s`
        // for instance, "\u{1F408}"" is converted into r#""\u{1F408}""#,
        // the latter should be parsed into `Literal(String("🐈"))` and
        // `🐈` is represented by '\u{1F408}'
        let test_valid = |s: &str| {
            let r = parse_literal(&format!("\"{}\"", s.escape_default()));
            assert!(r.is_ok());
            assert_eq!(r.unwrap(), ast::Literal::String(s.into()));
        };
        test_valid("\t");
        test_valid("\0");
        test_valid("👍");
        test_valid("🐈");
        test_valid("\u{1F408}");
        test_valid("abc\tde\\fg");
        test_valid("aaa\u{1F408}bcd👍👍👍");
        // test string with invalid escapes
        let test_invalid = |s: &str, en: usize| {
            let r = parse_literal(&format!("\"{}\"", s));
            assert!(r.is_err());
            assert!(r.unwrap_err().len() == en);
        };
        // invalid escape `\a`
        test_invalid("\\a", 1);
        // invalid escape `\b`
        test_invalid("\\b", 1);
        // invalid escape `\p`
        test_invalid("\\\\aa\\p", 1);
        // invalid escape `\a` and empty unicode escape
        test_invalid(r#"\aaa\u{}"#, 2);
    }

    fn expect_action_error(test: &str, euid_strs: Vec<&str>) {
        let euids = euid_strs
            .into_iter()
            .map(|euid_str| {
                EntityUID::from_str(euid_str).expect("Test was provided with invalid euid")
            })
            .collect::<Vec<_>>();
        let p = parse_policyset(test);
        match p {
            Ok(pset) => panic!("Policy: {pset}, shouln't have parsed!"),
            Err(es) => {
                if es.len() != euids.len() {
                    panic!(
                        "Parse should have produced exactly {} parse errors, produced: {:?}",
                        euids.len(),
                        es
                    );
                } else {
                    for euid in euids {
                        let err = action_type_error_msg(&euid);
                        assert!(es.contains(&err));
                    }
                }
            }
        }
    }

    #[test]
    fn action_checker() {
        let euid = EntityUID::from_str("Action::\"view\"").unwrap();
        assert!(euid_has_action_type(&euid));
        let euid = EntityUID::from_str("Foo::Action::\"view\"").unwrap();
        assert!(euid_has_action_type(&euid));
        let euid = EntityUID::from_str("Foo::\"view\"").unwrap();
        assert!(!euid_has_action_type(&euid));
        let euid = EntityUID::from_str("Action::Foo::\"view\"").unwrap();
        assert!(!euid_has_action_type(&euid));
    }

    #[test]
    fn action_must_be_action() {
        parse_policyset(r#"permit(principal, action == Action::"view", resource);"#)
            .expect("Valid policy failed to parse");
        parse_policyset(r#"permit(principal, action == Foo::Action::"view", resource);"#)
            .expect("Valid policy failed to parse");
        parse_policyset(r#"permit(principal, action in Action::"view", resource);"#)
            .expect("Valid policy failed to parse");
        parse_policyset(r#"permit(principal, action in Foo::Action::"view", resource);"#)
            .expect("Valid policy failed to parse");
        parse_policyset(r#"permit(principal, action in [Foo::Action::"view"], resource);"#)
            .expect("Valid policy failed to parse");
        parse_policyset(
            r#"permit(principal, action in [Foo::Action::"view", Action::"view"], resource);"#,
        )
        .expect("Valid policy failed to parse");
        expect_action_error(
            r#"permit(principal, action == Foo::"view", resource);"#,
            vec!["Foo::\"view\""],
        );
        expect_action_error(
            r#"permit(principal, action == Action::Foo::"view", resource);"#,
            vec!["Action::Foo::\"view\""],
        );
        expect_action_error(
            r#"permit(principal, action == Bar::Action::Foo::"view", resource);"#,
            vec!["Bar::Action::Foo::\"view\""],
        );
        expect_action_error(
            r#"permit(principal, action in Bar::Action::Foo::"view", resource);"#,
            vec!["Bar::Action::Foo::\"view\""],
        );
        expect_action_error(
            r#"permit(principal, action in [Bar::Action::Foo::"view"], resource);"#,
            vec!["Bar::Action::Foo::\"view\""],
        );
        expect_action_error(
            r#"permit(principal, action in [Bar::Action::Foo::"view", Action::"check"], resource);"#,
            vec!["Bar::Action::Foo::\"view\""],
        );
        expect_action_error(
            r#"permit(principal, action in [Bar::Action::Foo::"view", Foo::"delete", Action::"check"], resource);"#,
            vec!["Bar::Action::Foo::\"view\"", "Foo::\"delete\""],
        );
    }

    #[test]
    fn method_style() {
        let policy = parse_policyset(
            r#"permit(principal, action, resource)
            when { contains(true) < 1 };"#,
        );
        assert!(
            policy.is_err()
                && matches!(
                    policy.as_ref().unwrap_err().as_slice(),
                    [err::ParseError::ToAST(_)]
                ),
            "builtin functions must be called in method-style"
        );
    }

    #[test]
    fn test_mul() {
        for (es, expr) in [
            ("--2*3", Expr::mul(Expr::neg(Expr::val(-2)), 3)),
            (
                "1 * 2 * false",
                Expr::mul(Expr::mul(Expr::val(false), 1), 2),
            ),
            (
                "0 * 1 * principal",
                Expr::mul(Expr::mul(Expr::var(ast::Var::Principal), 0), 1),
            ),
            (
                "0 * (-1) * principal",
                Expr::mul(Expr::mul(Expr::var(ast::Var::Principal), 0), -1),
            ),
        ] {
            let mut errs = Vec::new();
            let e = text_to_cst::parse_expr(es)
                .expect("should construct a CST")
                .to_expr(&mut errs)
                .expect("should convert to AST");
            assert!(
                e.eq_shape(&expr),
                "{:?} and {:?} should have the same shape.",
                e,
                expr
            );
        }

        for es in [
            r#"false * "bob""#,
            "principal * (1 + 2)",
            "principal * -(-1)",
            // --1 is parsed as Expr::neg(Expr::val(-1)) and thus is not
            // considered as a constant.
            "principal * --1",
        ] {
            let mut errs = Vec::new();
            let e = text_to_cst::parse_expr(es)
                .expect("should construct a CST")
                .to_expr(&mut errs);
            assert!(e.is_none());
        }
    }

    #[test]
    fn test_not() {
        for (es, expr) in [
            (
                "!1 + 2 == 3",
                Expr::is_eq(
                    Expr::add(Expr::not(Expr::val(1)), Expr::val(2)),
                    Expr::val(3),
                ),
            ),
            (
                "!!1 + 2 == 3",
                Expr::is_eq(
                    Expr::add(Expr::not(Expr::not(Expr::val(1))), Expr::val(2)),
                    Expr::val(3),
                ),
            ),
            (
                "!!!1 + 2 == 3",
                Expr::is_eq(
                    Expr::add(Expr::not(Expr::val(1)), Expr::val(2)),
                    Expr::val(3),
                ),
            ),
            (
                "!!!!1 + 2 == 3",
                Expr::is_eq(
                    Expr::add(Expr::not(Expr::not(Expr::val(1))), Expr::val(2)),
                    Expr::val(3),
                ),
            ),
            (
                "!!(-1) + 2 == 3",
                Expr::is_eq(
                    Expr::add(Expr::not(Expr::not(Expr::val(-1))), Expr::val(2)),
                    Expr::val(3),
                ),
            ),
        ] {
            let mut errs = Vec::new();
            let e = text_to_cst::parse_expr(es)
                .expect("should construct a CST")
                .to_expr(&mut errs)
                .expect("should convert to AST");
            assert!(
                e.eq_shape(&expr),
                "{:?} and {:?} should have the same shape.",
                e,
                expr
            );
        }
    }

    #[test]
    fn test_neg() {
        for (es, expr) in [
            ("-(1 + 2)", Expr::neg(Expr::add(Expr::val(1), Expr::val(2)))),
            ("1-(2)", Expr::sub(Expr::val(1), Expr::val(2))),
            ("1-2", Expr::sub(Expr::val(1), Expr::val(2))),
            ("(-1)", Expr::val(-1)),
            ("-(-1)", Expr::neg(Expr::val(-1))),
            ("--1", Expr::neg(Expr::val(-1))),
            ("--(--1)", Expr::neg(Expr::neg(Expr::neg(Expr::val(-1))))),
            ("2--1", Expr::sub(Expr::val(2), Expr::val(-1))),
            ("-9223372036854775808", Expr::val(-(9223372036854775808))),
            // Evaluating this expression leads to overflows but the parser
            // won't reject it.
            (
                "--9223372036854775808",
                Expr::neg(Expr::val(-9223372036854775808)),
            ),
            (
                "-(9223372036854775807)",
                Expr::neg(Expr::val(9223372036854775807)),
            ),
        ] {
            let mut errs = Vec::new();
            let e = text_to_cst::parse_expr(es)
                .expect("should construct a CST")
                .to_expr(&mut errs)
                .expect("should convert to AST");
            assert!(
                e.eq_shape(&expr),
                "{:?} and {:?} should have the same shape.",
                e,
                expr
            );
        }

        for (es, em) in [
            ("-9223372036854775809", "Integer constant is too large"),
            // Contrary to Rust, this expression is not valid because the
            // parser treats it as a negation operation whereas the operand
            // (9223372036854775808) is too large.
            (
                "-(9223372036854775808)",
                "Literal 9223372036854775808 is too large",
            ),
        ] {
            let mut errs = Vec::new();
            let e = text_to_cst::parse_expr(es)
                .expect("should construct a CST")
                .to_expr(&mut errs);
            assert!(e.is_none());
            assert!(ParseErrors(errs).to_string().contains(em));
        }
    }
}
