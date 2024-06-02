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

//! Conversions from CST to AST
//!
//! This module contains functions to convert Nodes containing CST items into
//! AST items. It works with the parser CST output, where all nodes are optional.
//!
//! An important goal of the transformation is to provide as many errors as
//! possible to expedite development cycles. To this end, many of the functions
//! in this file will continue processing the input, even after an error has
//! been detected. To combine errors before returning a result, we use a
//! `flatten_tuple_N` helper function.

// Throughout this module parameters to functions are references to CSTs or
// owned AST items. This allows the most flexibility and least copying of data.
// CSTs are almost entirely rewritten to ASTs, so we keep those values intact
// and only clone the identifiers inside. ASTs here are temporary values until
// the data passes out of the module, so we deconstruct them freely in the few
// cases where there is a secondary conversion. This prevents any further
// cloning.

use super::cst;
use super::err::{
    self, ParseError, ParseErrors, Ref, RefCreationError, ToASTError, ToASTErrorKind,
};
use super::loc::Loc;
use super::node::Node;
use super::unescape::{to_pattern, to_unescaped_string};
use crate::ast::{
    self, ActionConstraint, CallStyle, EntityReference, EntityType, EntityUID, Integer,
    PatternElem, PolicySetError, PrincipalConstraint, PrincipalOrResourceConstraint,
    ResourceConstraint,
};
use crate::est::extract_single_argument;
use itertools::Either;
use smol_str::SmolStr;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::mem;
use std::sync::Arc;

/// Type alias for convenience
type Result<T> = std::result::Result<T, ParseErrors>;

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

pub(crate) fn flatten_tuple_2<T1, T2>(res1: Result<T1>, res2: Result<T2>) -> Result<(T1, T2)> {
    match res1 {
        Ok(v1) => res2.map(|v2| (v1, v2)),
        Err(mut errs1) => {
            let _ = res2.map_err(|errs2| errs1.extend(errs2));
            Err(errs1)
        }
    }
}

fn flatten_tuple_3<T1, T2, T3>(
    res1: Result<T1>,
    res2: Result<T2>,
    res3: Result<T3>,
) -> Result<(T1, T2, T3)> {
    match res1 {
        Ok(v1) => match res2 {
            Ok(v2) => res3.map(|v3| (v1, v2, v3)),
            Err(mut errs2) => {
                let _ = res3.map_err(|errs3| errs2.extend(errs3));
                Err(errs2)
            }
        },
        Err(mut errs1) => {
            let _ = res2.map_err(|errs2| errs1.extend(errs2));
            let _ = res3.map_err(|errs3| errs1.extend(errs3));
            Err(errs1)
        }
    }
}

pub(crate) fn flatten_tuple_4<T1, T2, T3, T4>(
    res1: Result<T1>,
    res2: Result<T2>,
    res3: Result<T3>,
    res4: Result<T4>,
) -> Result<(T1, T2, T3, T4)> {
    match res1 {
        Ok(v1) => match res2 {
            Ok(v2) => match res3 {
                Ok(v3) => res4.map(|v4| (v1, v2, v3, v4)),
                Err(mut errs3) => {
                    let _ = res4.map_err(|errs4| errs3.extend(errs4));
                    Err(errs3)
                }
            },
            Err(mut errs2) => {
                let _ = res3.map_err(|errs3| errs2.extend(errs3));
                let _ = res4.map_err(|errs4| errs2.extend(errs4));
                Err(errs2)
            }
        },
        Err(mut errs1) => {
            let _ = res2.map_err(|errs2| errs1.extend(errs2));
            let _ = res3.map_err(|errs3| errs1.extend(errs3));
            let _ = res4.map_err(|errs4| errs1.extend(errs4));
            Err(errs1)
        }
    }
}

impl Node<Option<cst::Policies>> {
    /// Iterate over the `Policy` nodes in this `cst::Policies`, with
    /// corresponding generated `PolicyID`s
    pub fn with_generated_policyids(
        &self,
    ) -> Result<impl Iterator<Item = (ast::PolicyID, &Node<Option<cst::Policy>>)>> {
        let policies = self.try_as_inner()?;

        Ok(policies
            .0
            .iter()
            .enumerate()
            .map(|(count, node)| (ast::PolicyID::from_string(format!("policy{count}")), node)))
    }

    /// convert `cst::Policies` to `ast::PolicySet`
    pub fn to_policyset(&self) -> Result<ast::PolicySet> {
        let mut pset = ast::PolicySet::new();
        let mut all_errs: Vec<ParseErrors> = vec![];
        // Caution: `parser::parse_policyset_and_also_return_policy_text()`
        // depends on this function returning a policy set with `PolicyID`s as
        // generated by `with_generated_policyids()` to maintain an invariant.
        for (policy_id, policy) in self.with_generated_policyids()? {
            // policy may have convert error
            match policy.to_policy_or_template(policy_id) {
                Ok(Either::Right(template)) => {
                    if let Err(e) = pset.add_template(template) {
                        match e {
                            PolicySetError::Occupied { id } => all_errs.push(
                                self.to_ast_err(ToASTErrorKind::DuplicateTemplateId(id))
                                    .into(),
                            ),
                        };
                    }
                }
                Ok(Either::Left(inline_policy)) => {
                    if let Err(e) = pset.add_static(inline_policy) {
                        match e {
                            PolicySetError::Occupied { id } => all_errs.push(
                                self.to_ast_err(ToASTErrorKind::DuplicatePolicyId(id))
                                    .into(),
                            ),
                        };
                    }
                }
                Err(errs) => {
                    all_errs.push(errs);
                }
            };
        }

        // fail on any error
        if let Some(errs) = ParseErrors::flatten(all_errs) {
            Err(errs)
        } else {
            Ok(pset)
        }
    }
}

impl Node<Option<cst::Policy>> {
    /// Convert `cst::Policy` to an AST `InlinePolicy` or `Template`
    pub fn to_policy_or_template(
        &self,
        id: ast::PolicyID,
    ) -> Result<Either<ast::StaticPolicy, ast::Template>> {
        let t = self.to_policy_template(id)?;
        if t.slots().count() == 0 {
            // PANIC SAFETY: A `Template` with no slots will successfully convert to a `StaticPolicy`
            #[allow(clippy::expect_used)]
            let p = ast::StaticPolicy::try_from(t).expect("internal invariant violation: a template with no slots should be a valid static policy");
            Ok(Either::Left(p))
        } else {
            Ok(Either::Right(t))
        }
    }

    /// Convert `cst::Policy` to an AST `InlinePolicy`. (Will fail if the CST is for a template)
    pub fn to_policy(&self, id: ast::PolicyID) -> Result<ast::StaticPolicy> {
        let maybe_template = self.to_policy_template(id);
        let maybe_policy = maybe_template.map(ast::StaticPolicy::try_from);
        match maybe_policy {
            // Successfully parsed a static policy
            Ok(Ok(p)) => Ok(p),
            // The source parsed as a template, but not a static policy
            Ok(Err(ast::UnexpectedSlotError::FoundSlot(slot))) => Err(ToASTError::new(
                ToASTErrorKind::UnexpectedTemplate {
                    slot: slot.id.into(),
                },
                slot.loc.unwrap_or_else(|| self.loc.clone()),
            )
            .into()),
            // The source failed to parse completely. If the parse errors include
            // `SlotsInConditionClause` also add an `UnexpectedTemplate` error.
            Err(mut errs) => {
                let new_errs = errs
                    .iter()
                    .filter_map(|err| match err {
                        ParseError::ToAST(err) => match err.kind() {
                            ToASTErrorKind::SlotsInConditionClause { slot, .. } => {
                                Some(ToASTError::new(
                                    ToASTErrorKind::UnexpectedTemplate { slot: slot.clone() },
                                    err.source_loc().clone(),
                                ))
                            }
                            _ => None,
                        },
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                errs.extend(new_errs);
                Err(errs)
            }
        }
    }

    /// Convert `cst::Policy` to `ast::Template`. Works for inline policies as
    /// well, which will become templates with 0 slots
    pub fn to_policy_template(&self, id: ast::PolicyID) -> Result<ast::Template> {
        let policy = self.try_as_inner()?;

        // convert effect
        let maybe_effect = policy.effect.to_effect();

        // convert annotations
        let maybe_annotations = policy.get_ast_annotations();

        // convert scope
        let maybe_scope = policy.extract_scope();

        // convert conditions
        let maybe_conds = ParseErrors::transpose(policy.conds.iter().map(|c| {
            let (e, is_when) = c.to_expr()?;
            let slot_errs = e.slots().map(|slot| {
                ToASTError::new(
                    ToASTErrorKind::SlotsInConditionClause {
                        slot: slot.id.into(),
                        clausetype: if is_when { "when" } else { "unless" },
                    },
                    slot.loc.unwrap_or_else(|| c.loc.clone()),
                )
                .into()
            });
            match ParseErrors::from_iter(slot_errs) {
                Some(errs) => Err(errs),
                None => Ok(e),
            }
        }));

        let (effect, annotations, (principal, action, resource), conds) =
            flatten_tuple_4(maybe_effect, maybe_annotations, maybe_scope, maybe_conds)?;
        Ok(construct_template_policy(
            id,
            annotations,
            effect,
            principal,
            action,
            resource,
            conds,
            &self.loc,
        ))
    }
}

impl cst::Policy {
    /// Get the scope constraints from the `cst::Policy`
    pub fn extract_scope(
        &self,
    ) -> Result<(PrincipalConstraint, ActionConstraint, ResourceConstraint)> {
        // Tracks where the last variable in the scope ended. We'll point to
        // this position to indicate where to fill in vars if we're missing one.
        let mut end_of_last_var = self.effect.loc.end();

        let mut vars = self.variables.iter().peekable();
        let maybe_principal = if let Some(scope1) = vars.next() {
            end_of_last_var = scope1.loc.end();
            scope1.to_principal_constraint()
        } else {
            Err(ToASTError::new(
                ToASTErrorKind::MissingScopeConstraint(ast::Var::Principal),
                self.effect.loc.span(end_of_last_var),
            )
            .into())
        };
        let maybe_action = if let Some(scope2) = vars.next() {
            end_of_last_var = scope2.loc.end();
            scope2.to_action_constraint()
        } else {
            Err(ToASTError::new(
                ToASTErrorKind::MissingScopeConstraint(ast::Var::Action),
                self.effect.loc.span(end_of_last_var),
            )
            .into())
        };
        let maybe_resource = if let Some(scope3) = vars.next() {
            scope3.to_resource_constraint()
        } else {
            Err(ToASTError::new(
                ToASTErrorKind::MissingScopeConstraint(ast::Var::Resource),
                self.effect.loc.span(end_of_last_var),
            )
            .into())
        };
        let maybe_extra_vars = if vars.peek().is_some() {
            // Add each of the extra constraints to the error list
            let mut errs: Vec<ParseError> = vec![];
            for extra_var in vars {
                if let Some(def) = extra_var.as_inner() {
                    errs.push(
                        extra_var
                            .to_ast_err(ToASTErrorKind::ExtraScopeConstraints(def.clone()))
                            .into(),
                    )
                }
            }
            match ParseErrors::from_iter(errs) {
                None => Ok(()),
                Some(errs) => Err(errs),
            }
        } else {
            Ok(())
        };
        let (principal, action, resource, _) = flatten_tuple_4(
            maybe_principal,
            maybe_action,
            maybe_resource,
            maybe_extra_vars,
        )?;
        Ok((principal, action, resource))
    }

    /// Get annotations from the `cst::Policy`
    pub fn get_ast_annotations(&self) -> Result<ast::Annotations> {
        let mut annotations = BTreeMap::new();
        let mut all_errs: Vec<ParseErrors> = vec![];
        for node in self.annotations.iter() {
            match node.to_kv_pair() {
                Ok((k, v)) => {
                    use std::collections::btree_map::Entry;
                    match annotations.entry(k) {
                        Entry::Occupied(oentry) => {
                            all_errs.push(
                                ToASTError::new(
                                    ToASTErrorKind::DuplicateAnnotation(oentry.key().clone()),
                                    node.loc.clone(),
                                )
                                .into(),
                            );
                        }
                        Entry::Vacant(ventry) => {
                            ventry.insert(v);
                        }
                    }
                }
                Err(errs) => {
                    all_errs.push(errs);
                }
            }
        }
        match ParseErrors::flatten(all_errs) {
            Some(errs) => Err(errs),
            None => Ok(annotations.into()),
        }
    }
}

impl Node<Option<cst::Annotation>> {
    /// Get the (k, v) pair for the annotation. Critically, this checks validity
    /// for the strings and does unescaping
    pub fn to_kv_pair(&self) -> Result<(ast::AnyId, ast::Annotation)> {
        let anno = self.try_as_inner()?;

        let maybe_key = anno.key.to_any_ident();
        let maybe_value = anno.value.as_valid_string().and_then(|s| {
            to_unescaped_string(s).map_err(|unescape_errs| {
                ParseErrors::new_from_nonempty(unescape_errs.map(|e| self.to_ast_err(e).into()))
            })
        });

        let (k, v) = flatten_tuple_2(maybe_key, maybe_value)?;
        Ok((
            k,
            ast::Annotation {
                val: v,
                loc: Some(self.loc.clone()), // self's loc, not the loc of the value alone; see comments on ast::Annotation
            },
        ))
    }
}

impl Node<Option<cst::Ident>> {
    /// Convert `cst::Ident` to `ast::Id`. Fails for reserved or invalid identifiers
    pub fn to_valid_ident(&self) -> Result<ast::Id> {
        let ident = self.try_as_inner()?;

        match ident {
            cst::Ident::If
            | cst::Ident::True
            | cst::Ident::False
            | cst::Ident::Then
            | cst::Ident::Else
            | cst::Ident::In
            | cst::Ident::Is
            | cst::Ident::Has
            | cst::Ident::Like => Err(self
                .to_ast_err(ToASTErrorKind::ReservedIdentifier(ident.clone()))
                .into()),
            cst::Ident::Invalid(i) => Err(self
                .to_ast_err(ToASTErrorKind::InvalidIdentifier(i.clone()))
                .into()),
            _ => Ok(ast::Id::new_unchecked(format!("{ident}"))),
        }
    }

    /// Convert [`cst::Ident`] to [`ast::AnyId`]. This method does not fail for
    /// reserved identifiers; see notes on [`ast::AnyId`].
    /// (It does fail for invalid identifiers, but there are no invalid
    /// identifiers at the time of this writing; see notes on
    /// [`cst::Ident::Invalid`])
    pub fn to_any_ident(&self) -> Result<ast::AnyId> {
        let ident = self.try_as_inner()?;

        match ident {
            cst::Ident::Invalid(i) => Err(self
                .to_ast_err(ToASTErrorKind::InvalidIdentifier(i.clone()))
                .into()),
            _ => Ok(ast::AnyId::new_unchecked(format!("{ident}"))),
        }
    }

    pub(crate) fn to_effect(&self) -> Result<ast::Effect> {
        let effect = self.try_as_inner()?;

        match effect {
            cst::Ident::Permit => Ok(ast::Effect::Permit),
            cst::Ident::Forbid => Ok(ast::Effect::Forbid),
            _ => Err(self
                .to_ast_err(ToASTErrorKind::InvalidEffect(effect.clone()))
                .into()),
        }
    }

    /// Returns `Ok(true)` if the condition is "when" and `Ok(false)` if the
    /// condition is "unless"
    pub(crate) fn to_cond_is_when(&self) -> Result<bool> {
        let cond = self.try_as_inner()?;

        match cond {
            cst::Ident::When => Ok(true),
            cst::Ident::Unless => Ok(false),
            _ => Err(self
                .to_ast_err(ToASTErrorKind::InvalidCondition(cond.clone()))
                .into()),
        }
    }

    fn to_var(&self) -> Result<ast::Var> {
        let ident = self.try_as_inner()?;

        match ident {
            cst::Ident::Principal => Ok(ast::Var::Principal),
            cst::Ident::Action => Ok(ast::Var::Action),
            cst::Ident::Resource => Ok(ast::Var::Resource),
            ident => Err(self
                .to_ast_err(ToASTErrorKind::InvalidScopeConstraintVariable(
                    ident.clone(),
                ))
                .into()),
        }
    }
}

impl ast::Id {
    fn to_meth(&self, e: ast::Expr, mut args: Vec<ast::Expr>, loc: &Loc) -> Result<ast::Expr> {
        match self.as_ref() {
            "contains" => extract_single_argument(args.into_iter(), "contains", loc)
                .map(|arg| construct_method_contains(e, arg, loc.clone())),
            "containsAll" => extract_single_argument(args.into_iter(), "containsAll", loc)
                .map(|arg| construct_method_contains_all(e, arg, loc.clone())),
            "containsAny" => extract_single_argument(args.into_iter(), "containsAny", loc)
                .map(|arg| construct_method_contains_any(e, arg, loc.clone())),
            id => {
                if EXTENSION_STYLES.methods.contains(&id) {
                    args.insert(0, e);
                    // INVARIANT (MethodStyleArgs), we call insert above, so args is non-empty
                    Ok(construct_ext_meth(id.to_string(), args, loc.clone()))
                } else {
                    let unqual_name = ast::Name::unqualified_name(self.clone());
                    if EXTENSION_STYLES.functions.contains(&unqual_name) {
                        Err(ToASTError::new(
                            ToASTErrorKind::MethodCallOnFunction(unqual_name.id),
                            loc.clone(),
                        )
                        .into())
                    } else {
                        Err(ToASTError::new(
                            ToASTErrorKind::InvalidMethodName(id.to_string()),
                            loc.clone(),
                        )
                        .into())
                    }
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

impl Node<Option<cst::VariableDef>> {
    fn to_principal_constraint(&self) -> Result<PrincipalConstraint> {
        match self.to_principal_or_resource_constraint(ast::Var::Principal)? {
            PrincipalOrResource::Principal(p) => Ok(p),
            PrincipalOrResource::Resource(_) => Err(self
                .to_ast_err(ToASTErrorKind::IncorrectVariable {
                    expected: ast::Var::Principal,
                    got: ast::Var::Resource,
                })
                .into()),
        }
    }

    fn to_resource_constraint(&self) -> Result<ResourceConstraint> {
        match self.to_principal_or_resource_constraint(ast::Var::Resource)? {
            PrincipalOrResource::Principal(_) => Err(self
                .to_ast_err(ToASTErrorKind::IncorrectVariable {
                    expected: ast::Var::Resource,
                    got: ast::Var::Principal,
                })
                .into()),
            PrincipalOrResource::Resource(r) => Ok(r),
        }
    }

    fn to_principal_or_resource_constraint(
        &self,
        expected: ast::Var,
    ) -> Result<PrincipalOrResource> {
        let vardef = self.try_as_inner()?;

        let var = vardef.variable.to_var()?;

        if let Some(unused_typename) = vardef.unused_type_name.as_ref() {
            unused_typename.to_type_constraint()?;
        }

        let c = if let Some((op, rel_expr)) = &vardef.ineq {
            let eref = rel_expr.to_ref_or_slot(var)?;
            match (op, &vardef.entity_type) {
                (cst::RelOp::Eq, None) => Ok(PrincipalOrResourceConstraint::Eq(eref)),
                (cst::RelOp::Eq, Some(_)) => Err(self.to_ast_err(ToASTErrorKind::InvalidIs(
                    err::InvalidIsError::WrongOp(cst::RelOp::Eq),
                ))),
                (cst::RelOp::In, None) => Ok(PrincipalOrResourceConstraint::In(eref)),
                (cst::RelOp::In, Some(entity_type)) => Ok(PrincipalOrResourceConstraint::IsIn(
                    entity_type.to_expr_or_special()?.into_name()?,
                    eref,
                )),
                (cst::RelOp::InvalidSingleEq, _) => {
                    Err(self.to_ast_err(ToASTErrorKind::InvalidSingleEq))
                }
                (op, _) => Err(self.to_ast_err(ToASTErrorKind::InvalidConstraintOperator(*op))),
            }
        } else if let Some(entity_type) = &vardef.entity_type {
            Ok(PrincipalOrResourceConstraint::Is(
                entity_type.to_expr_or_special()?.into_name()?,
            ))
        } else {
            Ok(PrincipalOrResourceConstraint::Any)
        }?;
        match var {
            ast::Var::Principal => Ok(PrincipalOrResource::Principal(PrincipalConstraint::new(c))),
            ast::Var::Resource => Ok(PrincipalOrResource::Resource(ResourceConstraint::new(c))),
            got => Err(self
                .to_ast_err(ToASTErrorKind::IncorrectVariable { expected, got })
                .into()),
        }
    }

    fn to_action_constraint(&self) -> Result<ast::ActionConstraint> {
        let vardef = self.try_as_inner()?;

        match vardef.variable.to_var() {
            Ok(ast::Var::Action) => Ok(()),
            Ok(got) => Err(self
                .to_ast_err(ToASTErrorKind::IncorrectVariable {
                    expected: ast::Var::Action,
                    got,
                })
                .into()),
            Err(errs) => Err(errs),
        }?;

        if let Some(typename) = vardef.unused_type_name.as_ref() {
            typename.to_type_constraint()?;
        }

        if vardef.entity_type.is_some() {
            return Err(self
                .to_ast_err(ToASTErrorKind::InvalidIs(err::InvalidIsError::ActionScope))
                .into());
        }

        let action_constraint = if let Some((op, rel_expr)) = &vardef.ineq {
            match op {
                cst::RelOp::In => match rel_expr.to_refs(ast::Var::Action)? {
                    OneOrMultipleRefs::Single(single_ref) => {
                        Ok(ActionConstraint::is_in([single_ref]))
                    }
                    OneOrMultipleRefs::Multiple(refs) => Ok(ActionConstraint::is_in(refs)),
                },
                cst::RelOp::Eq => {
                    let single_ref = rel_expr.to_ref(ast::Var::Action)?;
                    Ok(ActionConstraint::is_eq(single_ref))
                }
                cst::RelOp::InvalidSingleEq => {
                    Err(self.to_ast_err(ToASTErrorKind::InvalidSingleEq))
                }
                op => Err(self.to_ast_err(ToASTErrorKind::InvalidConstraintOperator(*op))),
            }
        } else {
            Ok(ActionConstraint::Any)
        }?;

        action_constraint_contains_only_action_types(action_constraint, &self.loc)
    }
}

/// Check that all of the EUIDs in an action constraint have the type `Action`, under an arbitrary namespace
fn action_constraint_contains_only_action_types(
    a: ActionConstraint,
    loc: &Loc,
) -> Result<ActionConstraint> {
    match a {
        ActionConstraint::Any => Ok(a),
        ActionConstraint::In(ref euids) => {
            let non_actions = euids
                .iter()
                .filter(|euid| !euid_has_action_type(euid))
                .collect::<Vec<_>>();
            match ParseErrors::from_iter(non_actions.into_iter().map(|euid| {
                ToASTError::new(
                    ToASTErrorKind::InvalidActionType(euid.as_ref().clone()),
                    loc.clone(),
                )
                .into()
            })) {
                None => Ok(a),
                Some(errs) => Err(errs),
            }
        }
        ActionConstraint::Eq(ref euid) => {
            if euid_has_action_type(euid) {
                Ok(a)
            } else {
                Err(ToASTError::new(
                    ToASTErrorKind::InvalidActionType(euid.as_ref().clone()),
                    loc.clone(),
                )
                .into())
            }
        }
    }
}

/// Check if an EUID has the type `Action` under an arbitrary namespace
fn euid_has_action_type(euid: &EntityUID) -> bool {
    if let EntityType::Specified(name) = euid.entity_type() {
        name.id.as_ref() == "Action"
    } else {
        false
    }
}

impl Node<Option<cst::Cond>> {
    /// to expr. Also returns, for informational purposes, a `bool` which is
    /// `true` if the cond is a `when` clause, `false` if it is an `unless`
    /// clause. (The returned `expr` is already adjusted for this, the `bool` is
    /// for information only.)
    fn to_expr(&self) -> Result<(ast::Expr, bool)> {
        let cond = self.try_as_inner()?;

        let is_when = cond.cond.to_cond_is_when()?;

        let maybe_expr = match &cond.expr {
            Some(expr) => expr.to_expr(),
            None => {
                let ident = match cond.cond.as_inner() {
                    Some(ident) => ident.clone(),
                    None => {
                        // `cond.cond.to_cond_is_when()` returned with `Ok`,
                        // so `cond.cond.as_inner()` must have been `Ok`
                        // inside that function call, making this unreachable.
                        if is_when {
                            cst::Ident::Ident("when".into())
                        } else {
                            cst::Ident::Ident("unless".into())
                        }
                    }
                };
                Err(self
                    .to_ast_err(ToASTErrorKind::EmptyClause(Some(ident)))
                    .into())
            }
        };

        maybe_expr.map(|e| {
            if is_when {
                (e, true)
            } else {
                (construct_expr_not(e, self.loc.clone()), false)
            }
        })
    }
}

impl Node<Option<cst::Str>> {
    pub(crate) fn as_valid_string(&self) -> Result<&SmolStr> {
        let id = self.try_as_inner()?;

        match id {
            cst::Str::String(s) => Ok(s),
            // at time of comment, all strings are valid
            cst::Str::Invalid(s) => Err(self
                .to_ast_err(ToASTErrorKind::InvalidString(s.to_string()))
                .into()),
        }
    }
}

/// Result type of conversion when we expect an Expr, Var, Name, or String.
///
/// During conversion it is useful to keep track of expression that may be used
/// as function names, record names, or record attributes. This prevents parsing these
/// terms to a general Expr expression and then immediately unwrapping them.
#[derive(Debug)]
pub(crate) enum ExprOrSpecial<'a> {
    /// Any expression except a variable, name, or string literal
    Expr { expr: ast::Expr, loc: Loc },
    /// Variables, which act as expressions or names
    Var { var: ast::Var, loc: Loc },
    /// Name that isn't an expr and couldn't be converted to var
    Name { name: ast::Name, loc: Loc },
    /// String literal, not yet unescaped
    /// Must be processed with to_unescaped_string or to_pattern before inclusion in the AST
    StrLit { lit: &'a SmolStr, loc: Loc },
}

impl ExprOrSpecial<'_> {
    fn to_ast_err(&self, kind: impl Into<ToASTErrorKind>) -> ToASTError {
        ToASTError::new(
            kind.into(),
            match self {
                ExprOrSpecial::Expr { loc, .. } => loc.clone(),
                ExprOrSpecial::Var { loc, .. } => loc.clone(),
                ExprOrSpecial::Name { loc, .. } => loc.clone(),
                ExprOrSpecial::StrLit { loc, .. } => loc.clone(),
            },
        )
    }

    fn into_expr(self) -> Result<ast::Expr> {
        match self {
            Self::Expr { expr, .. } => Ok(expr),
            Self::Var { var, loc } => Ok(construct_expr_var(var, loc)),
            Self::Name { name, loc } => Err(ToASTError::new(
                ToASTErrorKind::ArbitraryVariable(name.to_string().into()),
                loc,
            )
            .into()),
            Self::StrLit { lit, loc } => {
                match to_unescaped_string(lit) {
                    Ok(s) => Ok(construct_expr_string(s, loc)),
                    Err(escape_errs) => Err(ParseErrors::new_from_nonempty(escape_errs.map(|e| {
                        ToASTError::new(ToASTErrorKind::Unescape(e), loc.clone()).into()
                    }))),
                }
            }
        }
    }

    /// Variables, names (with no prefixes), and string literals can all be used as record attributes
    pub(crate) fn into_valid_attr(self) -> Result<SmolStr> {
        match self {
            Self::Var { var, .. } => Ok(construct_string_from_var(var)),
            Self::Name { name, loc } => name.into_valid_attr(loc),
            Self::StrLit { lit, loc } => {
                match to_unescaped_string(lit) {
                    Ok(s) => Ok(s),
                    Err(escape_errs) => Err(ParseErrors::new_from_nonempty(escape_errs.map(|e| {
                        ToASTError::new(ToASTErrorKind::Unescape(e), loc.clone()).into()
                    }))),
                }
            }
            Self::Expr { expr, loc } => Err(ToASTError::new(
                ToASTErrorKind::InvalidAttribute(expr.to_string().into()),
                loc,
            )
            .into()),
        }
    }

    pub(crate) fn into_pattern(self) -> Result<Vec<PatternElem>> {
        match &self {
            Self::StrLit { lit, .. } => match to_pattern(lit) {
                Ok(pat) => Ok(pat),
                Err(escape_errs) => {
                    Err(ParseErrors::new_from_nonempty(escape_errs.map(|e| {
                        self.to_ast_err(ToASTErrorKind::Unescape(e)).into()
                    })))
                }
            },
            Self::Var { var, .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidPattern(var.to_string()))
                .into()),
            Self::Name { name, .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidPattern(name.to_string()))
                .into()),
            Self::Expr { expr, .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidPattern(expr.to_string()))
                .into()),
        }
    }
    /// to string literal
    fn into_string_literal(self) -> Result<SmolStr> {
        match &self {
            Self::StrLit { lit, .. } => match to_unescaped_string(lit) {
                Ok(s) => Ok(s),
                Err(escape_errs) => {
                    Err(ParseErrors::new_from_nonempty(escape_errs.map(|e| {
                        self.to_ast_err(ToASTErrorKind::Unescape(e)).into()
                    })))
                }
            },
            Self::Var { var, .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidString(var.to_string()))
                .into()),
            Self::Name { name, .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidString(name.to_string()))
                .into()),
            Self::Expr { expr, .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidString(expr.to_string()))
                .into()),
        }
    }

    fn into_name(self) -> Result<ast::Name> {
        match self {
            Self::StrLit { lit, .. } => Err(self
                .to_ast_err(ToASTErrorKind::IsInvalidName(lit.to_string()))
                .into()),
            Self::Var { var, .. } => Ok(ast::Name::unqualified_name(var.into())),
            Self::Name { name, .. } => Ok(name),
            Self::Expr { ref expr, .. } => Err(self
                .to_ast_err(ToASTErrorKind::IsInvalidName(expr.to_string()))
                .into()),
        }
    }
}

impl Node<Option<cst::Expr>> {
    fn to_ref(&self, var: ast::Var) -> Result<EntityUID> {
        self.to_ref_or_refs::<SingleEntity>(var).map(|x| x.0)
    }

    fn to_ref_or_slot(&self, var: ast::Var) -> Result<EntityReference> {
        self.to_ref_or_refs::<EntityReference>(var)
    }

    fn to_refs(&self, var: ast::Var) -> Result<OneOrMultipleRefs> {
        self.to_ref_or_refs::<OneOrMultipleRefs>(var)
    }

    fn to_ref_or_refs<T: RefKind>(&self, var: ast::Var) -> Result<T> {
        let expr = self.try_as_inner()?;

        match &*expr.expr {
            cst::ExprData::Or(o) => o.to_ref_or_refs::<T>(var),
            cst::ExprData::If(_, _, _) => Err(self
                .to_ast_err(ToASTErrorKind::wrong_node(
                    T::err_str(),
                    "an `if` expression",
                    None::<String>,
                ))
                .into()),
        }
    }

    /// convert `cst::Expr` to `ast::Expr`
    pub fn to_expr(&self) -> Result<ast::Expr> {
        self.to_expr_or_special()?.into_expr()
    }
    pub(crate) fn to_expr_or_special(&self) -> Result<ExprOrSpecial<'_>> {
        let expr = self.try_as_inner()?;

        match &*expr.expr {
            cst::ExprData::Or(or) => or.to_expr_or_special(),
            cst::ExprData::If(i, t, e) => {
                let maybe_guard = i.to_expr();
                let maybe_then = t.to_expr();
                let maybe_else = e.to_expr();

                let (i, t, e) = flatten_tuple_3(maybe_guard, maybe_then, maybe_else)?;
                Ok(ExprOrSpecial::Expr {
                    expr: construct_expr_if(i, t, e, self.loc.clone()),
                    loc: self.loc.clone(),
                })
            }
        }
    }
}

/// Type level marker for parsing sets of entity uids or single uids
/// This presents having either a large level of code duplication
/// or runtime data.
trait RefKind: Sized {
    fn err_str() -> &'static str;
    fn create_single_ref(e: EntityUID, loc: &Loc) -> Result<Self>;
    fn create_multiple_refs(es: Vec<EntityUID>, loc: &Loc) -> Result<Self>;
    fn create_slot(loc: &Loc) -> Result<Self>;
}

struct SingleEntity(pub EntityUID);

impl RefKind for SingleEntity {
    fn err_str() -> &'static str {
        "an entity uid"
    }

    fn create_single_ref(e: EntityUID, _loc: &Loc) -> Result<Self> {
        Ok(SingleEntity(e))
    }

    fn create_multiple_refs(_es: Vec<EntityUID>, loc: &Loc) -> Result<Self> {
        Err(ToASTError::new(
            RefCreationError::one_expected(Ref::Single, Ref::Set).into(),
            loc.clone(),
        )
        .into())
    }

    fn create_slot(loc: &Loc) -> Result<Self> {
        Err(ToASTError::new(
            RefCreationError::one_expected(Ref::Single, Ref::Template).into(),
            loc.clone(),
        )
        .into())
    }
}

impl RefKind for EntityReference {
    fn err_str() -> &'static str {
        "an entity uid or matching template slot"
    }

    fn create_slot(_loc: &Loc) -> Result<Self> {
        Ok(EntityReference::Slot)
    }

    fn create_single_ref(e: EntityUID, _loc: &Loc) -> Result<Self> {
        Ok(EntityReference::euid(e))
    }

    fn create_multiple_refs(_es: Vec<EntityUID>, loc: &Loc) -> Result<Self> {
        Err(ToASTError::new(
            RefCreationError::two_expected(Ref::Single, Ref::Template, Ref::Set).into(),
            loc.clone(),
        )
        .into())
    }
}

/// Simple utility enum for parsing lists/individual entityuids
#[derive(Debug)]
enum OneOrMultipleRefs {
    Single(EntityUID),
    Multiple(Vec<EntityUID>),
}

impl RefKind for OneOrMultipleRefs {
    fn err_str() -> &'static str {
        "an entity uid or set of entity uids"
    }

    fn create_slot(loc: &Loc) -> Result<Self> {
        Err(ToASTError::new(
            RefCreationError::two_expected(Ref::Single, Ref::Set, Ref::Template).into(),
            loc.clone(),
        )
        .into())
    }

    fn create_single_ref(e: EntityUID, _loc: &Loc) -> Result<Self> {
        Ok(OneOrMultipleRefs::Single(e))
    }

    fn create_multiple_refs(es: Vec<EntityUID>, _loc: &Loc) -> Result<Self> {
        Ok(OneOrMultipleRefs::Multiple(es))
    }
}

impl Node<Option<cst::Or>> {
    fn to_expr_or_special(&self) -> Result<ExprOrSpecial<'_>> {
        let or = self.try_as_inner()?;

        let maybe_first = or.initial.to_expr_or_special();
        let maybe_rest = ParseErrors::transpose(or.extended.iter().map(|i| i.to_expr()));

        let (first, rest) = flatten_tuple_2(maybe_first, maybe_rest)?;
        match rest.split_first() {
            None => Ok(first),
            Some((second, rest)) => first.into_expr().map(|first| ExprOrSpecial::Expr {
                expr: construct_expr_or(first, second.clone(), rest.to_owned(), &self.loc),
                loc: self.loc.clone(),
            }),
        }
    }

    fn to_ref_or_refs<T: RefKind>(&self, var: ast::Var) -> Result<T> {
        let or = self.try_as_inner()?;

        match or.extended.len() {
            0 => or.initial.to_ref_or_refs::<T>(var),
            _n => Err(self
                .to_ast_err(ToASTErrorKind::wrong_node(
                    T::err_str(),
                    "a `||` expression",
                    None::<String>,
                ))
                .into()),
        }
    }
}

impl Node<Option<cst::And>> {
    fn to_ref_or_refs<T: RefKind>(&self, var: ast::Var) -> Result<T> {
        let and = self.try_as_inner()?;

        match and.extended.len() {
            0 => and.initial.to_ref_or_refs::<T>(var),
            _n => Err(self
                .to_ast_err(ToASTErrorKind::wrong_node(
                    T::err_str(),
                    "a `&&` expression",
                    None::<String>,
                ))
                .into()),
        }
    }

    fn to_expr(&self) -> Result<ast::Expr> {
        self.to_expr_or_special()?.into_expr()
    }
    fn to_expr_or_special(&self) -> Result<ExprOrSpecial<'_>> {
        let and = self.try_as_inner()?;

        let maybe_first = and.initial.to_expr_or_special();
        let maybe_rest = ParseErrors::transpose(and.extended.iter().map(|i| i.to_expr()));

        let (first, rest) = flatten_tuple_2(maybe_first, maybe_rest)?;
        match rest.split_first() {
            None => Ok(first),
            Some((second, rest)) => first.into_expr().map(|first| ExprOrSpecial::Expr {
                expr: construct_expr_and(first, second.clone(), rest.to_owned(), &self.loc),
                loc: self.loc.clone(),
            }),
        }
    }
}

impl Node<Option<cst::Relation>> {
    fn to_ref_or_refs<T: RefKind>(&self, var: ast::Var) -> Result<T> {
        let rel = self.try_as_inner()?;

        match rel {
            cst::Relation::Common { initial, extended } => match extended.len() {
                0 => initial.to_ref_or_refs::<T>(var),
                _n => Err(self
                    .to_ast_err(ToASTErrorKind::wrong_node(
                        T::err_str(),
                        "a binary operator",
                        None::<String>,
                    ))
                    .into()),
            },
            cst::Relation::Has { .. } => Err(self
                .to_ast_err(ToASTErrorKind::wrong_node(
                    T::err_str(),
                    "a `has` expression",
                    None::<String>,
                ))
                .into()),
            cst::Relation::Like { .. } => Err(self
                .to_ast_err(ToASTErrorKind::wrong_node(
                    T::err_str(),
                    "a `like` expression",
                    None::<String>,
                ))
                .into()),
            cst::Relation::IsIn { .. } => Err(self
                .to_ast_err(ToASTErrorKind::wrong_node(
                    T::err_str(),
                    "an `is` expression",
                    None::<String>,
                ))
                .into()),
        }
    }

    fn to_expr(&self) -> Result<ast::Expr> {
        self.to_expr_or_special()?.into_expr()
    }
    fn to_expr_or_special(&self) -> Result<ExprOrSpecial<'_>> {
        let rel = self.try_as_inner()?;

        match rel {
            cst::Relation::Common { initial, extended } => {
                let maybe_first = initial.to_expr_or_special();
                let maybe_rest = ParseErrors::transpose(
                    extended.iter().map(|(op, i)| i.to_expr().map(|e| (op, e))),
                );
                let maybe_extra_elmts = if extended.len() > 1 {
                    Err(self.to_ast_err(ToASTErrorKind::AmbiguousOperators).into())
                } else {
                    Ok(())
                };

                let (first, rest, _) = flatten_tuple_3(maybe_first, maybe_rest, maybe_extra_elmts)?;
                match rest.split_first() {
                    None => Ok(first),
                    Some(((&op, second), _)) => first.into_expr().and_then(|first| {
                        Ok(ExprOrSpecial::Expr {
                            expr: construct_expr_rel(first, op, second.clone(), self.loc.clone())?,
                            loc: self.loc.clone(),
                        })
                    }),
                }
            }
            cst::Relation::Has { target, field } => {
                let maybe_target = target.to_expr();
                let maybe_field = field.to_expr_or_special()?.into_valid_attr();
                let (target, field) = flatten_tuple_2(maybe_target, maybe_field)?;
                Ok(ExprOrSpecial::Expr {
                    expr: construct_expr_has(target, field, self.loc.clone()),
                    loc: self.loc.clone(),
                })
            }
            cst::Relation::Like { target, pattern } => {
                let maybe_target = target.to_expr();
                let maybe_pattern = pattern.to_expr_or_special()?.into_pattern();
                let (target, pattern) = flatten_tuple_2(maybe_target, maybe_pattern)?;
                Ok(ExprOrSpecial::Expr {
                    expr: construct_expr_like(target, pattern, self.loc.clone()),
                    loc: self.loc.clone(),
                })
            }
            cst::Relation::IsIn {
                target,
                entity_type,
                in_entity,
            } => {
                let maybe_target = target.to_expr();
                let maybe_entity_type = entity_type.to_expr_or_special()?.into_name();
                let (t, n) = flatten_tuple_2(maybe_target, maybe_entity_type)?;
                match in_entity {
                    Some(in_entity) => {
                        let in_expr = in_entity.to_expr()?;
                        Ok(ExprOrSpecial::Expr {
                            expr: construct_expr_and(
                                construct_expr_is(t.clone(), n, self.loc.clone()),
                                construct_expr_rel(t, cst::RelOp::In, in_expr, self.loc.clone())?,
                                std::iter::empty(),
                                &self.loc,
                            ),
                            loc: self.loc.clone(),
                        })
                    }
                    None => Ok(ExprOrSpecial::Expr {
                        expr: construct_expr_is(t, n, self.loc.clone()),
                        loc: self.loc.clone(),
                    }),
                }
            }
        }
    }
}

impl Node<Option<cst::Add>> {
    fn to_ref_or_refs<T: RefKind>(&self, var: ast::Var) -> Result<T> {
        let add = self.try_as_inner()?;

        match add.extended.len() {
            0 => add.initial.to_ref_or_refs::<T>(var),
            _n => {
                Err(self.to_ast_err(ToASTErrorKind::wrong_node(T::err_str(), "a `+/-` expression", Some("entity types and namespaces cannot use `+` or `-` characters -- perhaps try `_` or `::` instead?"))).into())
            }
        }
    }

    fn to_expr(&self) -> Result<ast::Expr> {
        self.to_expr_or_special()?.into_expr()
    }
    pub(crate) fn to_expr_or_special(&self) -> Result<ExprOrSpecial<'_>> {
        let add = self.try_as_inner()?;

        let maybe_first = add.initial.to_expr_or_special();
        let maybe_rest = ParseErrors::transpose(
            add.extended
                .iter()
                .map(|&(op, ref i)| i.to_expr().map(|e| (op, e))),
        );
        let (first, rest) = flatten_tuple_2(maybe_first, maybe_rest)?;
        if !rest.is_empty() {
            // in this case, `first` must be an expr, we should check for errors there as well
            let first = first.into_expr()?;
            Ok(ExprOrSpecial::Expr {
                expr: construct_expr_add(first, rest, &self.loc),
                loc: self.loc.clone(),
            })
        } else {
            Ok(first)
        }
    }
}

impl Node<Option<cst::Mult>> {
    fn to_ref_or_refs<T: RefKind>(&self, var: ast::Var) -> Result<T> {
        let mult = self.try_as_inner()?;

        match mult.extended.len() {
            0 => mult.initial.to_ref_or_refs::<T>(var),
            _n => Err(self
                .to_ast_err(ToASTErrorKind::wrong_node(
                    T::err_str(),
                    "a `*` expression",
                    None::<String>,
                ))
                .into()),
        }
    }

    fn to_expr(&self) -> Result<ast::Expr> {
        self.to_expr_or_special()?.into_expr()
    }
    fn to_expr_or_special(&self) -> Result<ExprOrSpecial<'_>> {
        let mult = self.try_as_inner()?;

        let maybe_first = mult.initial.to_expr_or_special();
        let maybe_rest = ParseErrors::transpose(mult.extended.iter().map(|&(op, ref i)| {
            i.to_expr().and_then(|e| match op {
                cst::MultOp::Times => Ok(e),
                cst::MultOp::Divide => {
                    Err(self.to_ast_err(ToASTErrorKind::UnsupportedDivision).into())
                }
                cst::MultOp::Mod => Err(self.to_ast_err(ToASTErrorKind::UnsupportedModulo).into()),
            })
        }));

        let (first, rest) = flatten_tuple_2(maybe_first, maybe_rest)?;
        if !rest.is_empty() {
            // in this case, `first` must be an expr, we should check for errors there as well
            let first = first.into_expr()?;
            Ok(ExprOrSpecial::Expr {
                expr: construct_expr_mul(first, rest, &self.loc),
                loc: self.loc.clone(),
            })
        } else {
            Ok(first)
        }
    }
}

impl Node<Option<cst::Unary>> {
    fn to_ref_or_refs<T: RefKind>(&self, var: ast::Var) -> Result<T> {
        let unary = self.try_as_inner()?;

        match &unary.op {
            Some(op) => Err(self
                .to_ast_err(ToASTErrorKind::wrong_node(
                    T::err_str(),
                    format!("a `{op}` expression"),
                    None::<String>,
                ))
                .into()),
            None => unary.item.to_ref_or_refs::<T>(var),
        }
    }

    fn to_expr(&self) -> Result<ast::Expr> {
        self.to_expr_or_special()?.into_expr()
    }
    fn to_expr_or_special(&self) -> Result<ExprOrSpecial<'_>> {
        let unary = self.try_as_inner()?;

        // A thunk to delay the evaluation of `item`
        let maybe_item = || unary.item.to_expr_or_special();

        match unary.op {
            None => maybe_item(),
            Some(cst::NegOp::Bang(0)) => maybe_item(),
            Some(cst::NegOp::Dash(0)) => maybe_item(),
            Some(cst::NegOp::Bang(n)) => {
                let item = maybe_item().and_then(|i| i.into_expr());
                if n % 2 == 0 {
                    item.map(|i| ExprOrSpecial::Expr {
                        expr: construct_expr_not(
                            construct_expr_not(i, self.loc.clone()),
                            self.loc.clone(),
                        ),
                        loc: self.loc.clone(),
                    })
                } else {
                    // safe to collapse to !
                    item.map(|i| ExprOrSpecial::Expr {
                        expr: construct_expr_not(i, self.loc.clone()),
                        loc: self.loc.clone(),
                    })
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
                            Ok(construct_expr_num(i64::MIN, unary.item.loc.clone())),
                            c - 1,
                        ),
                        Ordering::Less => (
                            Ok(construct_expr_num(-(*n as i64), unary.item.loc.clone())),
                            c - 1,
                        ),
                        Ordering::Greater => (
                            Err(self
                                .to_ast_err(ToASTErrorKind::IntegerLiteralTooLarge(*n))
                                .into()),
                            0,
                        ),
                    }
                } else {
                    // If the operand is not a CST literal, convert it into
                    // an expression.
                    (maybe_item().and_then(|i| i.into_expr()), c)
                };
                // Fold the expression into a series of negation operations.
                (0..rc)
                    .fold(last, |r, _| {
                        r.map(|e| (construct_expr_neg(e, self.loc.clone())))
                    })
                    .map(|expr| ExprOrSpecial::Expr {
                        expr,
                        loc: self.loc.clone(),
                    })
            }
            Some(cst::NegOp::OverBang) => Err(self
                .to_ast_err(ToASTErrorKind::UnaryOpLimit(ast::UnaryOp::Not))
                .into()),
            Some(cst::NegOp::OverDash) => Err(self
                .to_ast_err(ToASTErrorKind::UnaryOpLimit(ast::UnaryOp::Neg))
                .into()),
        }
    }
}

/// Temporary converted data, mirroring `cst::MemAccess`
enum AstAccessor {
    Field(ast::Id),
    Call(Vec<ast::Expr>),
    Index(SmolStr),
}

impl Node<Option<cst::Member>> {
    /// Try to convert `cst::Member` into a `cst::Literal`, i.e.
    /// match `Member(Primary(Literal(_), []))`.
    /// It does not match the `Expr` arm of `Primary`, which means expressions
    /// like `(1)` are not considered as literals on the CST level.
    pub fn to_lit(&self) -> Option<&cst::Literal> {
        let m = self.as_ref().node.as_ref()?;
        if !m.access.is_empty() {
            return None;
        }
        match m.item.as_ref().node.as_ref()? {
            cst::Primary::Literal(lit) => lit.as_ref().node.as_ref(),
            _ => None,
        }
    }

    fn to_ref_or_refs<T: RefKind>(&self, var: ast::Var) -> Result<T> {
        let mem = self.try_as_inner()?;

        match mem.access.len() {
            0 => mem.item.to_ref_or_refs::<T>(var),
            _n => {
                Err(self.to_ast_err(ToASTErrorKind::wrong_node(T::err_str(), "a `.` expression", Some("entity types and namespaces cannot use `.` characters -- perhaps try `_` or `::` instead?"))).into())
            }
        }
    }

    fn to_expr_or_special(&self) -> Result<ExprOrSpecial<'_>> {
        let mem = self.try_as_inner()?;

        let maybe_prim = mem.item.to_expr_or_special();
        let maybe_accessors = ParseErrors::transpose(mem.access.iter().map(|a| a.to_access()));

        // Return errors in case parsing failed for any element
        let (prim, mut accessors) = flatten_tuple_2(maybe_prim, maybe_accessors)?;

        // `head` will store the current translated expression
        let mut head = prim;
        // `tail` will store what remains to be translated
        let mut tail = &mut accessors[..];

        // This algorithm is essentially an iterator over the accessor slice, but the
        // pattern match should be easier to read, since we have to check multiple elements
        // at once. We use `mem::replace` to "deconstruct" the slice as we go, filling it
        // with empty data and taking ownership of its contents.
        // The loop returns on the first error observed.
        loop {
            use AstAccessor::*;
            use ExprOrSpecial::*;
            match (&mut head, tail) {
                // no accessors left - we're done
                (_, []) => break Ok(head),
                // function call
                (Name { name, .. }, [Call(a), rest @ ..]) => {
                    // move the vec out of the slice, we won't use the slice after
                    let args = std::mem::take(a);
                    // replace the object `name` refers to with a default value since it won't be used afterwards
                    let nn = mem::replace(
                        name,
                        ast::Name::unqualified_name(ast::Id::new_unchecked("")),
                    );
                    head = nn.into_func(args, self.loc.clone()).map(|expr| Expr {
                        expr,
                        loc: self.loc.clone(),
                    })?;
                    tail = rest;
                }
                // variable call - error
                (Var { var, .. }, [Call(_), ..]) => {
                    break Err(self.to_ast_err(ToASTErrorKind::VariableCall(*var)).into())
                }
                // arbitrary call - error
                (_, [Call(_), ..]) => {
                    break Err(self.to_ast_err(ToASTErrorKind::ExpressionCall).into())
                }
                // method call on name - error
                (Name { name, .. }, [Field(f), Call(_), ..]) => {
                    break Err(self
                        .to_ast_err(ToASTErrorKind::NoMethods(name.clone(), f.clone()))
                        .into())
                }
                // method call on variable
                (Var { var, loc: var_loc }, [Field(i), Call(a), rest @ ..]) => {
                    // move var and args out of the slice
                    let var = mem::replace(var, ast::Var::Principal);
                    let args = std::mem::take(a);
                    // move the id out of the slice as well, to avoid cloning the internal string
                    let id = mem::replace(i, ast::Id::new_unchecked(""));
                    head = id
                        .to_meth(construct_expr_var(var, var_loc.clone()), args, &self.loc)
                        .map(|expr| Expr {
                            expr,
                            loc: self.loc.clone(),
                        })?;
                    tail = rest;
                }
                // method call on arbitrary expression
                (Expr { expr, .. }, [Field(i), Call(a), rest @ ..]) => {
                    // move the expr and args out of the slice
                    let args = std::mem::take(a);
                    let expr = mem::replace(expr, ast::Expr::val(false));
                    // move the id out of the slice as well, to avoid cloning the internal string
                    let id = mem::replace(i, ast::Id::new_unchecked(""));
                    head = id.to_meth(expr, args, &self.loc).map(|expr| Expr {
                        expr,
                        loc: self.loc.clone(),
                    })?;
                    tail = rest;
                }
                // method call on string literal (same as Expr case)
                (StrLit { lit, loc: lit_loc }, [Field(i), Call(a), rest @ ..]) => {
                    let args = std::mem::take(a);
                    let id = mem::replace(i, ast::Id::new_unchecked(""));
                    let maybe_expr = match to_unescaped_string(lit) {
                        Ok(s) => Ok(construct_expr_string(s, lit_loc.clone())),
                        Err(escape_errs) => {
                            Err(ParseErrors::new_from_nonempty(escape_errs.map(|e| {
                                self.to_ast_err(ToASTErrorKind::Unescape(e)).into()
                            })))
                        }
                    };
                    head = maybe_expr.and_then(|e| {
                        id.to_meth(e, args, &self.loc).map(|expr| Expr {
                            expr,
                            loc: self.loc.clone(),
                        })
                    })?;
                    tail = rest;
                }
                // access on arbitrary name - error
                (Name { name, .. }, [Field(f), ..]) => {
                    break Err(self
                        .to_ast_err(ToASTErrorKind::InvalidAccess(
                            name.clone(),
                            f.to_string().into(),
                        ))
                        .into())
                }
                (Name { name, .. }, [Index(i), ..]) => {
                    break Err(self
                        .to_ast_err(ToASTErrorKind::InvalidIndex(name.clone(), i.clone()))
                        .into())
                }
                // attribute of variable
                (Var { var, loc: var_loc }, [Field(i), rest @ ..]) => {
                    let var = mem::replace(var, ast::Var::Principal);
                    let id = mem::replace(i, ast::Id::new_unchecked(""));
                    head = Expr {
                        expr: construct_expr_attr(
                            construct_expr_var(var, var_loc.clone()),
                            id.into_smolstr(),
                            self.loc.clone(),
                        ),
                        loc: self.loc.clone(),
                    };
                    tail = rest;
                }
                // field of arbitrary expr
                (Expr { expr, .. }, [Field(i), rest @ ..]) => {
                    let expr = mem::replace(expr, ast::Expr::val(false));
                    let id = mem::replace(i, ast::Id::new_unchecked(""));
                    head = Expr {
                        expr: construct_expr_attr(expr, id.into_smolstr(), self.loc.clone()),
                        loc: self.loc.clone(),
                    };
                    tail = rest;
                }
                // field of string literal (same as Expr case)
                (StrLit { lit, loc: lit_loc }, [Field(i), rest @ ..]) => {
                    let id = mem::replace(i, ast::Id::new_unchecked(""));
                    let maybe_expr = match to_unescaped_string(lit) {
                        Ok(s) => Ok(construct_expr_string(s, lit_loc.clone())),
                        Err(escape_errs) => {
                            Err(ParseErrors::new_from_nonempty(escape_errs.map(|e| {
                                self.to_ast_err(ToASTErrorKind::Unescape(e)).into()
                            })))
                        }
                    };
                    head = maybe_expr.map(|e| Expr {
                        expr: construct_expr_attr(e, id.into_smolstr(), self.loc.clone()),
                        loc: self.loc.clone(),
                    })?;
                    tail = rest;
                }
                // index into var
                (Var { var, loc: var_loc }, [Index(i), rest @ ..]) => {
                    let var = mem::replace(var, ast::Var::Principal);
                    let s = mem::take(i);
                    head = Expr {
                        expr: construct_expr_attr(
                            construct_expr_var(var, var_loc.clone()),
                            s,
                            self.loc.clone(),
                        ),
                        loc: self.loc.clone(),
                    };
                    tail = rest;
                }
                // index into arbitrary expr
                (Expr { expr, .. }, [Index(i), rest @ ..]) => {
                    let expr = mem::replace(expr, ast::Expr::val(false));
                    let s = mem::take(i);
                    head = Expr {
                        expr: construct_expr_attr(expr, s, self.loc.clone()),
                        loc: self.loc.clone(),
                    };
                    tail = rest;
                }
                // index into string literal (same as Expr case)
                (StrLit { lit, loc: lit_loc }, [Index(i), rest @ ..]) => {
                    let id = mem::take(i);
                    let maybe_expr = match to_unescaped_string(lit) {
                        Ok(s) => Ok(construct_expr_string(s, lit_loc.clone())),
                        Err(escape_errs) => {
                            Err(ParseErrors::new_from_nonempty(escape_errs.map(|e| {
                                self.to_ast_err(ToASTErrorKind::Unescape(e)).into()
                            })))
                        }
                    };
                    head = maybe_expr.map(|e| Expr {
                        expr: construct_expr_attr(e, id, self.loc.clone()),
                        loc: self.loc.clone(),
                    })?;
                    tail = rest;
                }
            }
        }
    }
}

impl Node<Option<cst::MemAccess>> {
    fn to_access(&self) -> Result<AstAccessor> {
        let acc = self.try_as_inner()?;

        match acc {
            cst::MemAccess::Field(i) => {
                let maybe_ident = i.to_valid_ident();
                maybe_ident.map(AstAccessor::Field)
            }
            cst::MemAccess::Call(args) => {
                let maybe_args = ParseErrors::transpose(args.iter().map(|e| e.to_expr()));
                maybe_args.map(AstAccessor::Call)
            }
            cst::MemAccess::Index(index) => {
                let maybe_index = index.to_expr_or_special()?.into_string_literal();
                maybe_index.map(AstAccessor::Index)
            }
        }
    }
}

impl Node<Option<cst::Primary>> {
    fn to_ref_or_refs<T: RefKind>(&self, var: ast::Var) -> Result<T> {
        let prim = self.try_as_inner()?;

        match prim {
            cst::Primary::Slot(s) => {
                // Call `create_slot` first so that we fail immediately if the
                // `RefKind` does not permit slots, and only then complain if
                // it's the wrong slot. This avoids getting an error
                // `found ?action instead of ?action` when `action` doesn't
                // support slots.
                let slot_ref = T::create_slot(&self.loc)?;
                let slot = s.try_as_inner()?;
                if slot.matches(var) {
                    Ok(slot_ref)
                } else {
                    Err(self
                        .to_ast_err(ToASTErrorKind::wrong_node(
                            T::err_str(),
                            format!("{slot} instead of ?{var}"),
                            None::<String>,
                        ))
                        .into())
                }
            }
            cst::Primary::Literal(lit) => {
                let found = match lit.as_inner() {
                    Some(lit) => format!("literal `{lit}`"),
                    None => "empty node".to_string(),
                };
                Err(self
                    .to_ast_err(ToASTErrorKind::wrong_node(
                        T::err_str(),
                        found,
                        None::<String>,
                    ))
                    .into())
            }
            cst::Primary::Ref(x) => T::create_single_ref(x.to_ref()?, &self.loc),
            cst::Primary::Name(name) => {
                let found = match name.as_inner() {
                    Some(name) => format!("name `{name}`"),
                    None => "name".to_string(),
                };
                Err(self
                    .to_ast_err(ToASTErrorKind::wrong_node(
                        T::err_str(),
                        found,
                        None::<String>,
                    ))
                    .into())
            }
            cst::Primary::Expr(x) => x.to_ref_or_refs::<T>(var),
            cst::Primary::EList(lst) => {
                let v = ParseErrors::transpose(lst.iter().map(|expr| expr.to_ref(var)))?;
                T::create_multiple_refs(v, &self.loc)
            }
            cst::Primary::RInits(_) => Err(self
                .to_ast_err(ToASTErrorKind::wrong_node(
                    T::err_str(),
                    "record initializer",
                    None::<String>,
                ))
                .into()),
        }
    }

    pub(crate) fn to_expr(&self) -> Result<ast::Expr> {
        self.to_expr_or_special()?.into_expr()
    }
    fn to_expr_or_special(&self) -> Result<ExprOrSpecial<'_>> {
        let prim = self.try_as_inner()?;

        match prim {
            cst::Primary::Literal(lit) => lit.to_expr_or_special(),
            cst::Primary::Ref(r) => r.to_expr().map(|expr| ExprOrSpecial::Expr {
                expr,
                loc: r.loc.clone(),
            }),
            cst::Primary::Slot(s) => s.clone().into_expr().map(|expr| ExprOrSpecial::Expr {
                expr,
                loc: s.loc.clone(),
            }),
            #[allow(clippy::manual_map)]
            cst::Primary::Name(n) => {
                // ignore errors in the case where `n` isn't a var - we'll get them elsewhere
                if let Ok(var) = n.to_var() {
                    Ok(ExprOrSpecial::Var {
                        var,
                        loc: self.loc.clone(),
                    })
                } else {
                    n.to_name().map(|name| ExprOrSpecial::Name {
                        name,
                        loc: self.loc.clone(),
                    })
                }
            }
            cst::Primary::Expr(e) => e.to_expr().map(|expr| ExprOrSpecial::Expr {
                expr,
                loc: e.loc.clone(),
            }),
            cst::Primary::EList(es) => {
                let maybe_list = ParseErrors::transpose(es.iter().map(|e| e.to_expr()));
                maybe_list.map(|list| ExprOrSpecial::Expr {
                    expr: construct_expr_set(list, self.loc.clone()),
                    loc: self.loc.clone(),
                })
            }
            cst::Primary::RInits(is) => {
                let maybe_rec = ParseErrors::transpose(is.iter().map(|i| i.to_init()));
                match maybe_rec {
                    Ok(rec) => {
                        let expr = construct_expr_record(rec, self.loc.clone())?;
                        Ok(ExprOrSpecial::Expr {
                            expr,
                            loc: self.loc.clone(),
                        })
                    }
                    Err(mut errs) => {
                        errs.push(
                            self.to_ast_err(ToASTErrorKind::InvalidAttributesInRecordLiteral)
                                .into(),
                        );
                        Err(errs)
                    }
                }
            }
        }
    }

    /// convert `cst::Primary` representing a string literal to a `SmolStr`.
    pub fn to_string_literal(&self) -> Result<SmolStr> {
        let prim = self.try_as_inner()?;

        match prim {
            cst::Primary::Literal(lit) => lit.to_expr_or_special()?.into_string_literal(),
            _ => Err(self
                .to_ast_err(ToASTErrorKind::InvalidString(prim.to_string()))
                .into()),
        }
    }
}

impl Node<Option<cst::Slot>> {
    fn into_expr(self) -> Result<ast::Expr> {
        match self.try_as_inner()?.try_into() {
            Ok(slot_id) => Ok(ast::ExprBuilder::new()
                .with_source_loc(self.loc)
                .slot(slot_id)),
            Err(e) => Err(self.to_ast_err(e).into()),
        }
    }
}

impl TryFrom<&cst::Slot> for ast::SlotId {
    type Error = ToASTErrorKind;

    fn try_from(slot: &cst::Slot) -> std::result::Result<Self, Self::Error> {
        match slot {
            cst::Slot::Principal => Ok(ast::SlotId::principal()),
            cst::Slot::Resource => Ok(ast::SlotId::resource()),
            cst::Slot::Other(slot) => Err(ToASTErrorKind::InvalidSlot(slot.clone())),
        }
    }
}

impl From<ast::SlotId> for cst::Slot {
    fn from(slot: ast::SlotId) -> cst::Slot {
        match slot {
            ast::SlotId(ast::ValidSlotId::Principal) => cst::Slot::Principal,
            ast::SlotId(ast::ValidSlotId::Resource) => cst::Slot::Resource,
        }
    }
}

impl Node<Option<cst::Name>> {
    /// Build type constraints
    fn to_type_constraint(&self) -> Result<ast::Expr> {
        match self.as_inner() {
            Some(_) => Err(self.to_ast_err(ToASTErrorKind::TypeConstraints).into()),
            None => Ok(construct_expr_bool(true, self.loc.clone())),
        }
    }

    pub(crate) fn to_name(&self) -> Result<ast::Name> {
        let name = self.try_as_inner()?;

        let maybe_path = ParseErrors::transpose(name.path.iter().map(|i| i.to_valid_ident()));
        let maybe_name = name.name.to_valid_ident();

        // computation and error generation is complete, so fail or construct
        let (name, path) = flatten_tuple_2(maybe_name, maybe_path)?;
        Ok(construct_name(path, name, self.loc.clone()))
    }
    fn to_ident(&self) -> Result<&cst::Ident> {
        let name = self.try_as_inner()?;

        match ParseErrors::transpose(name.path.iter().map(|id| id.to_valid_ident())) {
            Ok(path) => {
                if !path.is_empty() {
                    // The path should be empty for a variable
                    Err(self.to_ast_err(ToASTErrorKind::InvalidPath).into())
                } else {
                    name.name.try_as_inner().map_err(ParseErrors::singleton)
                }
            }
            Err(mut errs) => {
                // If there are any errors, that means the path was nonempty
                // and we should report that as an error as well.
                errs.push(self.to_ast_err(ToASTErrorKind::InvalidPath).into());
                Err(errs)
            }
        }
    }
    fn to_var(&self) -> Result<ast::Var> {
        let name = self.to_ident()?;

        match name {
            cst::Ident::Principal => Ok(ast::Var::Principal),
            cst::Ident::Action => Ok(ast::Var::Action),
            cst::Ident::Resource => Ok(ast::Var::Resource),
            cst::Ident::Context => Ok(ast::Var::Context),
            n => Err(self
                .to_ast_err(ToASTErrorKind::ArbitraryVariable(n.to_string().into()))
                .into()),
        }
    }
}

impl ast::Name {
    /// Convert the `Name` into a `String` attribute, which fails if it had any namespaces
    fn into_valid_attr(self, loc: Loc) -> Result<SmolStr> {
        if !self.path.is_empty() {
            Err(ToASTError::new(ToASTErrorKind::PathAsAttribute(self.to_string()), loc).into())
        } else {
            Ok(self.id.into_smolstr())
        }
    }

    /// If this name is a known extension function/method name or not
    pub(crate) fn is_known_extension_func_name(&self) -> bool {
        EXTENSION_STYLES.functions.contains(self)
            || (self.path.is_empty() && EXTENSION_STYLES.methods.contains(self.id.as_ref()))
    }

    fn into_func(self, args: Vec<ast::Expr>, loc: Loc) -> Result<ast::Expr> {
        // error on standard methods
        if self.path.is_empty() {
            let id = self.id.as_ref();
            if EXTENSION_STYLES.methods.contains(id)
                || matches!(id, "contains" | "containsAll" | "containsAny")
            {
                return Err(
                    ToASTError::new(ToASTErrorKind::FunctionCallOnMethod(self.id), loc).into(),
                );
            }
        }
        if EXTENSION_STYLES.functions.contains(&self) {
            Ok(construct_ext_func(self, args, loc))
        } else {
            Err(ToASTError::new(ToASTErrorKind::NotAFunction(self), loc).into())
        }
    }
}

impl Node<Option<cst::Ref>> {
    /// convert `cst::Ref` to `ast::EntityUID`
    pub fn to_ref(&self) -> Result<ast::EntityUID> {
        let refr = self.try_as_inner()?;

        match refr {
            cst::Ref::Uid { path, eid } => {
                let maybe_path = path.to_name();
                let maybe_eid = eid.as_valid_string().and_then(|s| {
                    to_unescaped_string(s).map_err(|escape_errs| {
                        ParseErrors::new_from_nonempty(
                            escape_errs
                                .map(|e| self.to_ast_err(ToASTErrorKind::Unescape(e)).into()),
                        )
                    })
                });

                let (p, e) = flatten_tuple_2(maybe_path, maybe_eid)?;
                Ok(construct_refr(p, e, self.loc.clone()))
            }
            cst::Ref::Ref { .. } => Err(self
                .to_ast_err(ToASTErrorKind::UnsupportedEntityLiterals)
                .into()),
        }
    }
    fn to_expr(&self) -> Result<ast::Expr> {
        self.to_ref()
            .map(|euid| construct_expr_ref(euid, self.loc.clone()))
    }
}

impl Node<Option<cst::Literal>> {
    fn to_expr_or_special(&self) -> Result<ExprOrSpecial<'_>> {
        let lit = self.try_as_inner()?;

        match lit {
            cst::Literal::True => Ok(ExprOrSpecial::Expr {
                expr: construct_expr_bool(true, self.loc.clone()),
                loc: self.loc.clone(),
            }),
            cst::Literal::False => Ok(ExprOrSpecial::Expr {
                expr: construct_expr_bool(false, self.loc.clone()),
                loc: self.loc.clone(),
            }),
            cst::Literal::Num(n) => match Integer::try_from(*n) {
                Ok(i) => Ok(ExprOrSpecial::Expr {
                    expr: construct_expr_num(i, self.loc.clone()),
                    loc: self.loc.clone(),
                }),
                Err(_) => Err(self
                    .to_ast_err(ToASTErrorKind::IntegerLiteralTooLarge(*n))
                    .into()),
            },
            cst::Literal::Str(s) => {
                let maybe_str = s.as_valid_string();
                maybe_str.map(|lit| ExprOrSpecial::StrLit {
                    lit,
                    loc: self.loc.clone(),
                })
            }
        }
    }
}

impl Node<Option<cst::RecInit>> {
    fn to_init(&self) -> Result<(SmolStr, ast::Expr)> {
        let lit = self.try_as_inner()?;

        let maybe_attr = lit.0.to_expr_or_special()?.into_valid_attr();
        let maybe_value = lit.1.to_expr();

        flatten_tuple_2(maybe_attr, maybe_value)
    }
}

/// This section (construct_*) exists to handle differences between standard ast constructors and
/// the needs or conveniences here. Especially concerning source location data.
#[allow(clippy::too_many_arguments)]
fn construct_template_policy(
    id: ast::PolicyID,
    annotations: ast::Annotations,
    effect: ast::Effect,
    principal: ast::PrincipalConstraint,
    action: ast::ActionConstraint,
    resource: ast::ResourceConstraint,
    conds: Vec<ast::Expr>,
    loc: &Loc,
) -> ast::Template {
    let construct_template = |non_scope_constraint| {
        ast::Template::new(
            id,
            Some(loc.clone()),
            annotations,
            effect,
            principal,
            action,
            resource,
            non_scope_constraint,
        )
    };
    let mut conds_iter = conds.into_iter();
    if let Some(first_expr) = conds_iter.next() {
        // a left fold of conditions
        // e.g., [c1, c2, c3,] --> ((c1 && c2) && c3)
        construct_template(match conds_iter.next() {
            Some(e) => construct_expr_and(first_expr, e, conds_iter, loc),
            None => first_expr,
        })
    } else {
        // use `true` to mark the absence of non-scope constraints
        construct_template(construct_expr_bool(true, loc.clone()))
    }
}
fn construct_string_from_var(v: ast::Var) -> SmolStr {
    match v {
        ast::Var::Principal => "principal".into(),
        ast::Var::Action => "action".into(),
        ast::Var::Resource => "resource".into(),
        ast::Var::Context => "context".into(),
    }
}
fn construct_name(path: Vec<ast::Id>, id: ast::Id, loc: Loc) -> ast::Name {
    ast::Name {
        id,
        path: Arc::new(path),
        loc: Some(loc),
    }
}
fn construct_refr(p: ast::Name, n: SmolStr, loc: Loc) -> ast::EntityUID {
    let eid = ast::Eid::new(n);
    ast::EntityUID::from_components(p, eid, Some(loc))
}
fn construct_expr_ref(r: ast::EntityUID, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new().with_source_loc(loc).val(r)
}
fn construct_expr_num(n: Integer, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new().with_source_loc(loc).val(n)
}
fn construct_expr_string(s: SmolStr, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new().with_source_loc(loc).val(s)
}
fn construct_expr_bool(b: bool, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new().with_source_loc(loc).val(b)
}
fn construct_expr_neg(e: ast::Expr, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new().with_source_loc(loc).neg(e)
}
fn construct_expr_not(e: ast::Expr, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new().with_source_loc(loc).not(e)
}
fn construct_expr_var(v: ast::Var, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new().with_source_loc(loc).var(v)
}
fn construct_expr_if(i: ast::Expr, t: ast::Expr, e: ast::Expr, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new().with_source_loc(loc).ite(i, t, e)
}
fn construct_expr_or(
    f: ast::Expr,
    s: ast::Expr,
    chained: impl IntoIterator<Item = ast::Expr>,
    loc: &Loc,
) -> ast::Expr {
    let first = ast::ExprBuilder::new()
        .with_source_loc(loc.clone())
        .or(f, s);
    chained.into_iter().fold(first, |a, n| {
        ast::ExprBuilder::new()
            .with_source_loc(loc.clone())
            .or(a, n)
    })
}
fn construct_expr_and(
    f: ast::Expr,
    s: ast::Expr,
    chained: impl IntoIterator<Item = ast::Expr>,
    loc: &Loc,
) -> ast::Expr {
    let first = ast::ExprBuilder::new()
        .with_source_loc(loc.clone())
        .and(f, s);
    chained.into_iter().fold(first, |a, n| {
        ast::ExprBuilder::new()
            .with_source_loc(loc.clone())
            .and(a, n)
    })
}
fn construct_expr_rel(f: ast::Expr, rel: cst::RelOp, s: ast::Expr, loc: Loc) -> Result<ast::Expr> {
    let builder = ast::ExprBuilder::new().with_source_loc(loc.clone());
    match rel {
        cst::RelOp::Less => Ok(builder.less(f, s)),
        cst::RelOp::LessEq => Ok(builder.lesseq(f, s)),
        cst::RelOp::GreaterEq => Ok(builder.greatereq(f, s)),
        cst::RelOp::Greater => Ok(builder.greater(f, s)),
        cst::RelOp::NotEq => Ok(builder.noteq(f, s)),
        cst::RelOp::Eq => Ok(builder.is_eq(f, s)),
        cst::RelOp::In => Ok(builder.is_in(f, s)),
        cst::RelOp::InvalidSingleEq => {
            Err(ToASTError::new(ToASTErrorKind::InvalidSingleEq, loc).into())
        }
    }
}
/// used for a chain of addition and/or subtraction
fn construct_expr_add(
    f: ast::Expr,
    chained: impl IntoIterator<Item = (cst::AddOp, ast::Expr)>,
    loc: &Loc,
) -> ast::Expr {
    let mut expr = f;
    for (op, next_expr) in chained {
        let builder = ast::ExprBuilder::new().with_source_loc(loc.clone());
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
    chained: impl IntoIterator<Item = ast::Expr>,
    loc: &Loc,
) -> ast::Expr {
    let mut expr = f;
    for next_expr in chained {
        expr = ast::ExprBuilder::new()
            .with_source_loc(loc.clone())
            .mul(expr, next_expr);
    }
    expr
}
fn construct_expr_has(t: ast::Expr, s: SmolStr, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new().with_source_loc(loc).has_attr(t, s)
}
fn construct_expr_attr(e: ast::Expr, s: SmolStr, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new().with_source_loc(loc).get_attr(e, s)
}
fn construct_expr_like(e: ast::Expr, s: Vec<PatternElem>, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new().with_source_loc(loc).like(e, s)
}
fn construct_expr_is(e: ast::Expr, n: ast::Name, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new()
        .with_source_loc(loc)
        .is_entity_type(e, n)
}
fn construct_ext_func(name: ast::Name, args: Vec<ast::Expr>, loc: Loc) -> ast::Expr {
    // INVARIANT (MethodStyleArgs): CallStyle is not MethodStyle, so any args vector is fine
    ast::ExprBuilder::new()
        .with_source_loc(loc)
        .call_extension_fn(name, args)
}

fn construct_method_contains(e0: ast::Expr, e1: ast::Expr, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new()
        .with_source_loc(loc)
        .contains(e0, e1)
}
fn construct_method_contains_all(e0: ast::Expr, e1: ast::Expr, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new()
        .with_source_loc(loc)
        .contains_all(e0, e1)
}
fn construct_method_contains_any(e0: ast::Expr, e1: ast::Expr, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new()
        .with_source_loc(loc)
        .contains_any(e0, e1)
}

// INVARIANT (MethodStyleArgs), args must be non-empty
fn construct_ext_meth(n: String, args: Vec<ast::Expr>, loc: Loc) -> ast::Expr {
    let id = ast::Id::new_unchecked(n);
    let name = ast::Name::unqualified_name(id);
    // INVARIANT (MethodStyleArgs), args must be non-empty
    ast::ExprBuilder::new()
        .with_source_loc(loc)
        .call_extension_fn(name, args)
}
fn construct_expr_set(s: Vec<ast::Expr>, loc: Loc) -> ast::Expr {
    ast::ExprBuilder::new().with_source_loc(loc).set(s)
}
fn construct_expr_record(kvs: Vec<(SmolStr, ast::Expr)>, loc: Loc) -> Result<ast::Expr> {
    ast::ExprBuilder::new()
        .with_source_loc(loc.clone())
        .record(kvs)
        .map_err(|e| ToASTError::new(e.into(), loc).into())
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
// PANIC SAFETY: Unit Test Code
#[allow(clippy::indexing_slicing)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ast::Expr,
        parser::{err::ParseErrors, test_utils::*, *},
        test_utils::*,
    };
    use cool_asserts::assert_matches;
    use std::str::FromStr;

    #[track_caller]
    fn assert_parse_expr_succeeds(text: &str) -> Expr {
        let expr = text_to_cst::parse_expr(text)
            .expect("failed parser")
            .to_expr()
            .unwrap_or_else(|errs| {
                panic!(
                    "failed conversion to AST:\n{:?}",
                    miette::Report::new(ParseErrors::from(errs))
                )
            });
        expr
    }

    #[track_caller]
    fn assert_parse_expr_fails(text: &str) -> ParseErrors {
        let result = text_to_cst::parse_expr(text)
            .expect("failed parser")
            .to_expr();
        match result {
            Ok(expr) => {
                panic!("conversion to AST should have failed, but succeeded with:\n{expr}")
            }
            Err(errs) => errs,
        }
    }

    #[track_caller]
    fn assert_parse_policy_succeeds(text: &str) -> ast::StaticPolicy {
        let expr = text_to_cst::parse_policy(text)
            .expect("failed parser")
            .to_policy(ast::PolicyID::from_string("id"))
            .unwrap_or_else(|errs| {
                panic!("failed conversion to AST:\n{:?}", miette::Report::new(errs))
            });
        expr
    }

    #[track_caller]
    fn assert_parse_policy_fails(text: &str) -> ParseErrors {
        let result = text_to_cst::parse_policy(text)
            .expect("failed parser")
            .to_policy(ast::PolicyID::from_string("id"));
        match result {
            Ok(policy) => {
                panic!("conversion to AST should have failed, but succeeded with:\n{policy}")
            }
            Err(errs) => errs,
        }
    }

    #[test]
    fn show_expr1() {
        assert_parse_expr_succeeds(
            r#"
            if 7 then 6 > 5 else !5 || "thursday" && ((8) >= "fish")
        "#,
        );
    }

    #[test]
    fn show_expr2() {
        assert_parse_expr_succeeds(
            r#"
            [2,3,4].foo["hello"]
        "#,
        );
    }

    #[test]
    fn show_expr3() {
        // these exprs are ill-typed, but are allowed by the parser
        let expr = assert_parse_expr_succeeds(
            r#"
            "first".some_ident
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::GetAttr { attr, .. } => {
            assert_eq!(attr, "some_ident");
        });
    }

    #[test]
    fn show_expr4() {
        let expr = assert_parse_expr_succeeds(
            r#"
            1.some_ident
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::GetAttr { attr, .. } => {
            assert_eq!(attr, "some_ident");
        });
    }

    #[test]
    fn show_expr5() {
        let expr = assert_parse_expr_succeeds(
            r#"
            "first"["some string"]
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::GetAttr { attr, .. } => {
            assert_eq!(attr, "some string");
        });
    }

    #[test]
    fn show_expr6() {
        let expr = assert_parse_expr_succeeds(
            r#"
            {"one":1,"two":2} has one
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::HasAttr { attr, .. } => {
            assert_eq!(attr, "one");
        });
    }

    #[test]
    fn show_expr7() {
        let expr = assert_parse_expr_succeeds(
            r#"
            {"one":1,"two":2}.one
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::GetAttr { attr, .. } => {
            assert_eq!(attr, "one");
        });
    }

    #[test]
    fn show_expr8() {
        // parses to the same AST expression as above
        let expr = assert_parse_expr_succeeds(
            r#"
            {"one":1,"two":2}["one"]
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::GetAttr { attr, .. } => {
            assert_eq!(attr, "one");
        });
    }

    #[test]
    fn show_expr9() {
        // accessing a record with a non-identifier attribute
        let expr = assert_parse_expr_succeeds(
            r#"
            {"this is a valid map key+.-_%()":1,"two":2}["this is a valid map key+.-_%()"]
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::GetAttr { attr, .. } => {
            assert_eq!(attr, "this is a valid map key+.-_%()");
        });
    }

    #[test]
    fn show_expr10() {
        let src = r#"
            {if true then a else b:"b"} ||
            {if false then a else b:"b"}
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 6);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("record literal has invalid attributes")
                .exactly_one_underline("{if true then a else b:\"b\"}")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("record literal has invalid attributes")
                .exactly_one_underline("{if false then a else b:\"b\"}")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("arbitrary variables are not supported; the valid Cedar variables are `principal`, `action`, `resource`, and `context`")
                .help("did you mean to enclose `a` in quotes to make a string?")
                .exactly_one_underline("a")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("arbitrary variables are not supported; the valid Cedar variables are `principal`, `action`, `resource`, and `context`")
                .help("did you mean to enclose `b` in quotes to make a string?")
                .exactly_one_underline("b")
                .build(),
        );
    }

    #[test]
    fn show_expr11() {
        let expr = assert_parse_expr_succeeds(
            r#"
            {principal:"principal"}
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::Record { .. });
    }

    #[test]
    fn show_expr12() {
        let expr = assert_parse_expr_succeeds(
            r#"
            {"principal":"principal"}
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::Record { .. });
    }

    #[test]
    fn reserved_idents1() {
        let src = r#"
            The::true::path::to::"enlightenment".false
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 2);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: `true`",
            )
            .exactly_one_underline("true")
            .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: `false`",
            )
            .exactly_one_underline("false")
            .build(),
        );
    }

    #[test]
    fn reserved_idents2() {
        let src = r#"
            if {if: true}.if then {"if":false}["if"] else {when:true}.permit
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 3);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: `if`",
            )
            .exactly_one_underline("if: true")
            .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: `if`",
            )
            .exactly_one_underline("if")
            .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("record literal has invalid attributes")
                .exactly_one_underline("{if: true}")
                .build(),
        );
    }

    #[test]
    fn reserved_idents3() {
        let src = r#"
            if {where: true}.like || {has:false}.in then {"like":false}["in"] else {then:true}.else
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 7);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: `has`",
            )
            .exactly_one_underline("has")
            .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: `like`",
            )
            .exactly_one_underline("like")
            .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: `in`",
            )
            .exactly_one_underline("in")
            .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: `then`",
            )
            .exactly_one_underline("then")
            .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: `else`",
            )
            .exactly_one_underline("else")
            .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("record literal has invalid attributes")
                .exactly_one_underline("{has:false}")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("record literal has invalid attributes")
                .exactly_one_underline("{then:true}")
                .build(),
        );
    }

    #[test]
    fn show_policy1() {
        let src = r#"
            permit(principal:p,action:a,resource:r)when{w}unless{u}advice{"doit"};
        "#;
        let errs = assert_parse_policy_fails(src);
        expect_n_errors(src, &errs, 6);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("type constraints using `:` are not supported")
                .help("try using `is` instead")
                .exactly_one_underline("p")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("type constraints using `:` are not supported")
                .help("try using `is` instead")
                .exactly_one_underline("a")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("type constraints using `:` are not supported")
                .help("try using `is` instead")
                .exactly_one_underline("r")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("arbitrary variables are not supported; the valid Cedar variables are `principal`, `action`, `resource`, and `context`")
                .help("did you mean to enclose `w` in quotes to make a string?")
                .exactly_one_underline("w")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("arbitrary variables are not supported; the valid Cedar variables are `principal`, `action`, `resource`, and `context`")
                .help("did you mean to enclose `u` in quotes to make a string?")
                .exactly_one_underline("u")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("not a valid policy condition: `advice`")
                .help("condition must be either `when` or `unless`")
                .exactly_one_underline("advice")
                .build(),
        );
    }

    #[test]
    fn show_policy2() {
        let src = r#"
            permit(principal,action,resource)when{true};
        "#;
        assert_parse_policy_succeeds(src);
    }

    #[test]
    fn show_policy3() {
        let src = r#"
            permit(principal in User::"jane",action,resource);
        "#;
        assert_parse_policy_succeeds(src);
    }

    #[test]
    fn show_policy4() {
        let src = r#"
            forbid(principal in User::"jane",action,resource)unless{
                context.group != "friends"
            };
        "#;
        assert_parse_policy_succeeds(src);
    }

    #[test]
    fn policy_annotations() {
        // common use-case
        let policy = assert_parse_policy_succeeds(
            r#"
            @anno("good annotation")permit(principal,action,resource);
        "#,
        );
        assert_matches!(
            policy.annotation(&ast::AnyId::new_unchecked("anno")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "good annotation")
        );

        // duplication is error
        let src = r#"
            @anno("good annotation")
            @anno2("good annotation")
            @anno("oops, duplicate")
            permit(principal,action,resource);
        "#;
        let errs = assert_parse_policy_fails(src);
        // annotation duplication (anno)
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("duplicate annotation: @anno")
                .exactly_one_underline("@anno(\"oops, duplicate\")")
                .build(),
        );

        // can have multiple annotations
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
        .to_policyset()
        .unwrap_or_else(|errs| panic!("failed convert to AST:\n{:?}", miette::Report::new(errs)));
        assert_matches!(
            policyset
                .get(&ast::PolicyID::from_string("policy0"))
                .expect("should be a policy")
                .annotation(&ast::AnyId::new_unchecked("anno0")),
            None
        );
        assert_matches!(
            policyset
                .get(&ast::PolicyID::from_string("policy0"))
                .expect("should be a policy")
                .annotation(&ast::AnyId::new_unchecked("anno1")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "first")
        );
        assert_matches!(
            policyset
                .get(&ast::PolicyID::from_string("policy1"))
                .expect("should be a policy")
                .annotation(&ast::AnyId::new_unchecked("anno2")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "second")
        );
        assert_matches!(
            policyset
                .get(&ast::PolicyID::from_string("policy2"))
                .expect("should be a policy")
                .annotation(&ast::AnyId::new_unchecked("anno3a")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "third-a")
        );
        assert_matches!(
            policyset
                .get(&ast::PolicyID::from_string("policy2"))
                .expect("should be a policy")
                .annotation(&ast::AnyId::new_unchecked("anno3b")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "third-b")
        );
        assert_matches!(
            policyset
                .get(&ast::PolicyID::from_string("policy2"))
                .expect("should be a policy")
                .annotation(&ast::AnyId::new_unchecked("anno3c")),
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

        // can't have spaces or '+' in annotation keys
        assert_matches!(
            text_to_cst::parse_policy(
                r#"
            @hi mom("this should be invalid")
            permit(principal, action, resource);
            "#,
            ),
            Err(_)
        );
        assert_matches!(
            text_to_cst::parse_policy(
                r#"
            @hi+mom("this should be invalid")
            permit(principal, action, resource);
            "#,
            ),
            Err(_)
        );

        // can have Cedar reserved words as annotation keys
        let policyset = text_to_cst::parse_policies(
            r#"
            @if("this is the annotation for `if`")
            @then("this is the annotation for `then`")
            @else("this is the annotation for `else`")
            @true("this is the annotation for `true`")
            @false("this is the annotation for `false`")
            @in("this is the annotation for `in`")
            @is("this is the annotation for `is`")
            @like("this is the annotation for `like`")
            @has("this is the annotation for `has`")
            @principal("this is the annotation for `principal`") // not reserved at time of this writing, but we test it anyway
            permit(principal, action, resource);
            "#,
        ).expect("should parse")
        .to_policyset()
        .unwrap_or_else(|errs| panic!("failed convert to AST:\n{:?}", miette::Report::new(errs)));
        let policy0 = policyset
            .get(&ast::PolicyID::from_string("policy0"))
            .expect("should be the right policy ID");
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("if")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "this is the annotation for `if`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("then")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "this is the annotation for `then`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("else")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "this is the annotation for `else`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("true")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "this is the annotation for `true`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("false")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "this is the annotation for `false`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("in")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "this is the annotation for `in`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("is")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "this is the annotation for `is`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("like")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "this is the annotation for `like`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("has")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "this is the annotation for `has`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("principal")),
            Some(ast::Annotation { val, .. }) => assert_eq!(val.as_ref(), "this is the annotation for `principal`")
        );
    }

    #[test]
    fn fail_scope1() {
        let src = r#"
            permit(
                principal in [User::"jane",Group::"friends"],
                action,
                resource
            );
        "#;
        let errs = assert_parse_policy_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "expected single entity uid or template slot, got: set of entity uids",
            )
            .exactly_one_underline(r#"[User::"jane",Group::"friends"]"#)
            .build(),
        );
    }

    #[test]
    fn fail_scope2() {
        let src = r#"
            permit(
                principal in User::"jane",
                action == if true then Photo::"view" else Photo::"edit",
                resource
            );
        "#;
        let errs = assert_parse_policy_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("expected an entity uid, found an `if` expression")
                .exactly_one_underline(r#"if true then Photo::"view" else Photo::"edit""#)
                .build(),
        );
    }

    #[test]
    fn fail_scope3() {
        let src = r#"
            permit(principal,action,resource,context);
        "#;
        let errs = assert_parse_policy_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this policy has an extra constraint in the scope: `context`",
            )
            .help("a policy must have exactly `principal`, `action`, and `resource` constraints")
            .exactly_one_underline("context")
            .build(),
        );
    }

    #[test]
    fn method_call2() {
        assert_parse_expr_succeeds(
            r#"
                principal.contains(resource)
                "#,
        );

        let src = r#"
        contains(principal,resource)
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("`contains` is a method, not a function")
                .help("use a method-style call: `e.contains(..)`")
                .exactly_one_underline("contains(principal,resource)")
                .build(),
        );
    }

    #[test]
    fn construct_record_1() {
        let e = assert_parse_expr_succeeds(
            r#"
                {one:"one"}
                "#,
        );
        // ast should be acceptable, with record construction
        assert_matches!(e.expr_kind(), ast::ExprKind::Record { .. });
        println!("{e}");
    }

    #[test]
    fn construct_record_2() {
        let e = assert_parse_expr_succeeds(
            r#"
                {"one":"one"}
                "#,
        );
        // ast should be acceptable, with record construction
        assert_matches!(e.expr_kind(), ast::ExprKind::Record { .. });
        println!("{e}");
    }

    #[test]
    fn construct_record_3() {
        let e = assert_parse_expr_succeeds(
            r#"
                {"one":"one",two:"two"}
                "#,
        );
        // ast should be acceptable, with record construction
        assert_matches!(e.expr_kind(), ast::ExprKind::Record { .. });
        println!("{e}");
    }

    #[test]
    fn construct_record_4() {
        let e = assert_parse_expr_succeeds(
            r#"
                {one:"one","two":"two"}
                "#,
        );
        // ast should be acceptable, with record construction
        assert_matches!(e.expr_kind(), ast::ExprKind::Record { .. });
        println!("{e}");
    }

    #[test]
    fn construct_record_5() {
        let e = assert_parse_expr_succeeds(
            r#"
                {one:"b\"","b\"":2}
                "#,
        );
        // ast should be acceptable, with record construction
        assert_matches!(e.expr_kind(), ast::ExprKind::Record { .. });
        println!("{e}");
    }

    #[test]
    fn construct_invalid_get_1() {
        let src = r#"
            {"one":1, "two":"two"}[0]
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("invalid string literal: `0`")
                .exactly_one_underline("0")
                .build(),
        );
    }

    #[test]
    fn construct_invalid_get_2() {
        let src = r#"
            {"one":1, "two":"two"}[-1]
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("invalid string literal: `(-1)`")
                .exactly_one_underline("-1")
                .build(),
        );
    }

    #[test]
    fn construct_invalid_get_3() {
        let src = r#"
            {"one":1, "two":"two"}[true]
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("invalid string literal: `true`")
                .exactly_one_underline("true")
                .build(),
        );
    }

    #[test]
    fn construct_invalid_get_4() {
        let src = r#"
            {"one":1, "two":"two"}[one]
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("invalid string literal: `one`")
                .exactly_one_underline("one")
                .build(),
        );
    }

    #[test]
    fn construct_has_1() {
        let expr = assert_parse_expr_succeeds(
            r#"
            {"one":1,"two":2} has "arbitrary+ _string"
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::HasAttr { attr, .. } => {
            assert_eq!(attr, "arbitrary+ _string");
        });
    }

    #[test]
    fn construct_has_2() {
        let src = r#"
            {"one":1,"two":2} has 1
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("not a valid attribute name: `1`")
                .help("attribute names can either be identifiers or string literals")
                .exactly_one_underline("1")
                .build(),
        );
    }

    #[test]
    fn construct_like_1() {
        let expr = assert_parse_expr_succeeds(
            r#"
            "354 hams" like "*5*"
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::Like { pattern, .. } => {
            assert_eq!(pattern.to_string(), "*5*");
        });
    }

    #[test]
    fn construct_like_2() {
        let src = r#"
            "354 hams" like 354
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "right hand side of a `like` expression must be a pattern literal, but got `354`",
            )
            .exactly_one_underline("354")
            .build(),
        );
    }

    #[test]
    fn construct_like_3() {
        let expr = assert_parse_expr_succeeds(
            r#"
            "string\\with\\backslashes" like "string\\with\\backslashes"
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::Like { pattern, .. } => {
            assert_eq!(pattern.to_string(), r"string\\with\\backslashes");
        });
    }

    #[test]
    fn construct_like_4() {
        let expr = assert_parse_expr_succeeds(
            r#"
            "string\\with\\backslashes" like "string\*with\*backslashes"
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::Like { pattern, .. } => {
            assert_eq!(pattern.to_string(), r"string\*with\*backslashes");
        });
    }

    #[test]
    fn construct_like_5() {
        let src = r#"
            "string\*with\*escaped\*stars" like "string\*with\*escaped\*stars"
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 3);
        // all three errors are the same -- they report a use of \* in the first argument
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("the input `\\*` is not a valid escape")
                .exactly_one_underline(r#""string\*with\*escaped\*stars""#)
                .build(),
        );
    }

    #[test]
    fn construct_like_6() {
        let expr = assert_parse_expr_succeeds(
            r#"
            "string*with*stars" like "string\*with\*stars"
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::Like { pattern, .. } => {
            assert_eq!(pattern.to_string(), "string\\*with\\*stars");
        });
    }

    #[test]
    fn construct_like_7() {
        let expr = assert_parse_expr_succeeds(
            r#"
            "string\\*with\\*backslashes\\*and\\*stars" like "string\\\*with\\\*backslashes\\\*and\\\*stars"
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::Like { pattern, .. } => {
            assert_eq!(
                pattern.to_string(),
                r"string\\\*with\\\*backslashes\\\*and\\\*stars"
            );
        });
    }

    #[test]
    fn pattern_roundtrip() {
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
        let e2 = assert_parse_expr_succeeds(&s1);
        assert_matches!(e2.expr_kind(), ast::ExprKind::Like { pattern, .. } => {
            assert_eq!(pattern.get_elems(), test_pattern);
        });
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
        let expr = assert_parse_expr_succeeds(
            r#"
            User::"jane" has age
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::HasAttr { attr, .. } => {
            assert_eq!(attr, "age");
        });

        // ok
        let expr = assert_parse_expr_succeeds(
            r#"
            User::"jane" has "arbitrary+ _string"
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::HasAttr { attr, .. } => {
            assert_eq!(attr, "arbitrary+ _string");
        });

        // not ok: 1 is not a valid attribute
        let src = r#"
            User::"jane" has 1
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("not a valid attribute name: `1`")
                .help("attribute names can either be identifiers or string literals")
                .exactly_one_underline("1")
                .build(),
        );

        // ok
        let expr = assert_parse_expr_succeeds(
            r#"
            User::"jane".age
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::GetAttr { attr, .. } => {
            assert_eq!(attr, "age");
        });

        // ok
        let expr: ast::Expr = assert_parse_expr_succeeds(
            r#"
            User::"jane"["arbitrary+ _string"]
        "#,
        );
        assert_matches!(expr.expr_kind(), ast::ExprKind::GetAttr { attr, .. } => {
            assert_eq!(attr, "arbitrary+ _string");
        });

        // not ok: age is not a string literal
        let src = r#"
            User::"jane"[age]
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("invalid string literal: `age`")
                .exactly_one_underline("age")
                .build(),
        );
    }

    #[test]
    fn relational_ops1() {
        let src = r#"
            3 >= 2 >= 1
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("multiple relational operators (>, ==, in, etc.) must be used with parentheses to make ordering explicit")
                .exactly_one_underline("3 >= 2 >= 1")
                .build(),
        );
    }

    #[test]
    fn relational_ops2() {
        assert_parse_expr_succeeds(
            r#"
                    3 >= ("dad" in "dad")
                    "#,
        );
    }

    #[test]
    fn relational_ops3() {
        assert_parse_expr_succeeds(
            r#"
                (3 >= 2) == true
                "#,
        );
    }

    #[test]
    fn relational_ops4() {
        let src = r#"
            if 4 < 3 then 4 != 3 else 4 == 3 < 4
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("multiple relational operators (>, ==, in, etc.) must be used with parentheses to make ordering explicit")
                .exactly_one_underline("4 == 3 < 4")
                .build(),
        );
    }

    #[test]
    fn arithmetic() {
        assert_parse_expr_succeeds(r#" 2 + 4 "#);
        assert_parse_expr_succeeds(r#" 2 + -5 "#);
        assert_parse_expr_succeeds(r#" 2 - 5 "#);
        assert_parse_expr_succeeds(r#" 2 * 5 "#);
        assert_parse_expr_succeeds(r#" 2 * -5 "#);
        assert_parse_expr_succeeds(r#" context.size * 4 "#);
        assert_parse_expr_succeeds(r#" 4 * context.size "#);
        assert_parse_expr_succeeds(r#" context.size * context.scale "#);
        assert_parse_expr_succeeds(r#" 5 + 10 + 90 "#);
        assert_parse_expr_succeeds(r#" 5 + 10 - 90 * -2 "#);
        assert_parse_expr_succeeds(r#" 5 + 10 * 90 - 2 "#);
        assert_parse_expr_succeeds(r#" 5 - 10 - 90 - 2 "#);
        assert_parse_expr_succeeds(r#" 5 * context.size * 10 "#);
        assert_parse_expr_succeeds(r#" context.size * 3 * context.scale "#);
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
            text_to_cst::parse_policy(src)
                .expect("parse_error")
                .to_policy_template(ast::PolicyID::from_string("i0"))
                .unwrap_or_else(|errs| {
                    panic!(
                        "Failed to create a policy template: {:?}",
                        miette::Report::new(errs)
                    );
                });
        }
    }

    #[test]
    fn var_type() {
        assert_parse_policy_succeeds(
            r#"
                permit(principal,action,resource);
                "#,
        );

        let src = r#"
            permit(principal:User,action,resource);
        "#;
        let errs = assert_parse_policy_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("type constraints using `:` are not supported")
                .help("try using `is` instead")
                .exactly_one_underline("User")
                .build(),
        );
    }

    #[test]
    fn unescape_err_positions() {
        let assert_invalid_escape = |p_src, underline| {
            assert_matches!(parse_policy_template(None, p_src), Err(e) => {
                expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("the input `\\q` is not a valid escape").exactly_one_underline(underline).build());
            });
        };
        assert_invalid_escape(
            r#"@foo("\q")permit(principal, action, resource);"#,
            r#"@foo("\q")"#,
        );
        assert_invalid_escape(
            r#"permit(principal, action, resource) when { "\q" };"#,
            r#""\q""#,
        );
        assert_invalid_escape(
            r#"permit(principal, action, resource) when { "\q".contains(0) };"#,
            r#""\q".contains(0)"#,
        );
        assert_invalid_escape(
            r#"permit(principal, action, resource) when { "\q".bar };"#,
            r#""\q".bar"#,
        );
        assert_invalid_escape(
            r#"permit(principal, action, resource) when { "\q"["a"] };"#,
            r#""\q"["a"]"#,
        );
        assert_invalid_escape(
            r#"permit(principal, action, resource) when { "" like "\q" };"#,
            r#""\q""#,
        );
        assert_invalid_escape(
            r#"permit(principal, action, resource) when { {}["\q"] };"#,
            r#""\q""#,
        );
        assert_invalid_escape(
            r#"permit(principal, action, resource) when { {"\q": 0} };"#,
            r#""\q""#,
        );
        assert_invalid_escape(
            r#"permit(principal, action, resource) when { User::"\q" };"#,
            r#"User::"\q""#,
        );
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn expect_action_error(test: &str, euid_strs: Vec<&str>, underlines: Vec<&str>) {
        let euids = euid_strs
            .iter()
            .map(|euid_str| {
                EntityUID::from_str(euid_str).expect("Test was provided with invalid euid")
            })
            .collect::<Vec<_>>();
        assert_matches!(parse_policyset(test), Err(es) => {
            assert_eq!(es.len(), euids.len(),
                "should have produced exactly {} parse errors, produced {}:\n{:?}",
                euids.len(),
                es.len(),
                miette::Report::new(es)
            );
            for (euid, underline) in euids.into_iter().zip(underlines.into_iter()) {
                expect_some_error_matches(
                    test,
                    &es,
                    &ExpectedErrorMessageBuilder::error(&format!("expected an entity uid with the type `Action` but got `{euid}`")).help(
                        "action entities must have type `Action`, optionally in a namespace",
                    ).exactly_one_underline(underline).build(),
                );
            }
        });
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
            vec!["action == Foo::\"view\""], // TODO: don't underline the `action ==` part
        );
        expect_action_error(
            r#"permit(principal, action == Action::Foo::"view", resource);"#,
            vec!["Action::Foo::\"view\""],
            vec!["action == Action::Foo::\"view\""], // TODO: don't underline the `action ==` part
        );
        expect_action_error(
            r#"permit(principal, action == Bar::Action::Foo::"view", resource);"#,
            vec!["Bar::Action::Foo::\"view\""],
            vec!["action == Bar::Action::Foo::\"view\""], // TODO: don't underline the `action ==` part
        );
        expect_action_error(
            r#"permit(principal, action in Bar::Action::Foo::"view", resource);"#,
            vec!["Bar::Action::Foo::\"view\""],
            vec!["action in Bar::Action::Foo::\"view\""], // TODO: don't underline the `action in` part
        );
        expect_action_error(
            r#"permit(principal, action in [Bar::Action::Foo::"view"], resource);"#,
            vec!["Bar::Action::Foo::\"view\""],
            vec!["action in [Bar::Action::Foo::\"view\"]"], // TODO: don't underline the `action in` part
        );
        expect_action_error(
            r#"permit(principal, action in [Bar::Action::Foo::"view", Action::"check"], resource);"#,
            vec!["Bar::Action::Foo::\"view\""],
            vec!["action in [Bar::Action::Foo::\"view\", Action::\"check\"]"], // TODO: don't underline the `action in` part
        );
        expect_action_error(
            r#"permit(principal, action in [Bar::Action::Foo::"view", Foo::"delete", Action::"check"], resource);"#,
            vec!["Bar::Action::Foo::\"view\"", "Foo::\"delete\""],
            vec!["action in [Bar::Action::Foo::\"view\", Foo::\"delete\", Action::\"check\"]"], // TODO: don't underline the `action in` part
        );
    }

    #[test]
    fn method_style() {
        let src = r#"permit(principal, action, resource)
            when { contains(true) < 1 };"#;
        assert_matches!(parse_policyset(src), Err(e) => {
            expect_n_errors(src, &e, 1);
            expect_some_error_matches(src, &e, &ExpectedErrorMessageBuilder::error(
                "`contains` is a method, not a function",
            ).help(
                "use a method-style call: `e.contains(..)`",
            ).exactly_one_underline("contains(true)").build());
        });
    }

    #[test]
    fn test_mul() {
        for (str, expected) in [
            ("--2*3", Expr::mul(Expr::neg(Expr::val(-2)), Expr::val(3))),
            (
                "1 * 2 * false",
                Expr::mul(Expr::mul(Expr::val(1), Expr::val(2)), Expr::val(false)),
            ),
            (
                "0 * 1 * principal",
                Expr::mul(
                    Expr::mul(Expr::val(0), Expr::val(1)),
                    Expr::var(ast::Var::Principal),
                ),
            ),
            (
                "0 * (-1) * principal",
                Expr::mul(
                    Expr::mul(Expr::val(0), Expr::val(-1)),
                    Expr::var(ast::Var::Principal),
                ),
            ),
            (
                "0 * 6 * context.foo",
                Expr::mul(
                    Expr::mul(Expr::val(0), Expr::val(6)),
                    Expr::get_attr(Expr::var(ast::Var::Context), "foo".into()),
                ),
            ),
            (
                "(0 * 6) * context.foo",
                Expr::mul(
                    Expr::mul(Expr::val(0), Expr::val(6)),
                    Expr::get_attr(Expr::var(ast::Var::Context), "foo".into()),
                ),
            ),
            (
                "0 * (6 * context.foo)",
                Expr::mul(
                    Expr::val(0),
                    Expr::mul(
                        Expr::val(6),
                        Expr::get_attr(Expr::var(ast::Var::Context), "foo".into()),
                    ),
                ),
            ),
            (
                "0 * (context.foo * 6)",
                Expr::mul(
                    Expr::val(0),
                    Expr::mul(
                        Expr::get_attr(Expr::var(ast::Var::Context), "foo".into()),
                        Expr::val(6),
                    ),
                ),
            ),
            (
                "1 * 2 * 3 * context.foo * 4 * 5 * 6",
                Expr::mul(
                    Expr::mul(
                        Expr::mul(
                            Expr::mul(
                                Expr::mul(Expr::mul(Expr::val(1), Expr::val(2)), Expr::val(3)),
                                Expr::get_attr(Expr::var(ast::Var::Context), "foo".into()),
                            ),
                            Expr::val(4),
                        ),
                        Expr::val(5),
                    ),
                    Expr::val(6),
                ),
            ),
            (
                "principal * (1 + 2)",
                Expr::mul(
                    Expr::var(ast::Var::Principal),
                    Expr::add(Expr::val(1), Expr::val(2)),
                ),
            ),
            (
                "principal * -(-1)",
                Expr::mul(Expr::var(ast::Var::Principal), Expr::neg(Expr::val(-1))),
            ),
            (
                "principal * --1",
                Expr::mul(Expr::var(ast::Var::Principal), Expr::neg(Expr::val(-1))),
            ),
            (
                r#"false * "bob""#,
                Expr::mul(Expr::val(false), Expr::val("bob")),
            ),
        ] {
            let e = assert_parse_expr_succeeds(str);
            assert!(
                e.eq_shape(&expected),
                "{e:?} and {expected:?} should have the same shape",
            );
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
            let e = assert_parse_expr_succeeds(es);
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
            let e = assert_parse_expr_succeeds(es);
            assert!(
                e.eq_shape(&expr),
                "{:?} and {:?} should have the same shape.",
                e,
                expr
            );
        }

        for (es, em) in [
            (
                "-9223372036854775809",
                ExpectedErrorMessageBuilder::error(
                    "integer literal `9223372036854775809` is too large",
                )
                .help("maximum allowed integer literal is `9223372036854775807`")
                .exactly_one_underline("-9223372036854775809")
                .build(),
            ),
            // This test doesn't fail with an internal representation of i128:
            // Contrary to Rust, this expression is not valid because the
            // parser treats it as a negation operation whereas the operand
            // (9223372036854775808) is too large.
            (
                "-(9223372036854775808)",
                ExpectedErrorMessageBuilder::error(
                    "integer literal `9223372036854775808` is too large",
                )
                .help("maximum allowed integer literal is `9223372036854775807`")
                .exactly_one_underline("9223372036854775808")
                .build(),
            ),
        ] {
            let errs = assert_parse_expr_fails(es);
            expect_err(es, &miette::Report::new(errs), &em);
        }
    }

    #[test]
    fn test_is_condition_ok() {
        for (es, expr) in [
            (
                r#"User::"alice" is User"#,
                Expr::is_entity_type(
                    Expr::val(r#"User::"alice""#.parse::<EntityUID>().unwrap()),
                    "User".parse().unwrap(),
                ),
            ),
            (
                r#"principal is User"#,
                Expr::is_entity_type(Expr::var(ast::Var::Principal), "User".parse().unwrap()),
            ),
            (
                r#"principal.foo is User"#,
                Expr::is_entity_type(
                    Expr::get_attr(Expr::var(ast::Var::Principal), "foo".into()),
                    "User".parse().unwrap(),
                ),
            ),
            (
                r#"1 is User"#,
                Expr::is_entity_type(Expr::val(1), "User".parse().unwrap()),
            ),
            (
                r#"principal is User in Group::"friends""#,
                Expr::and(
                    Expr::is_entity_type(Expr::var(ast::Var::Principal), "User".parse().unwrap()),
                    Expr::is_in(
                        Expr::var(ast::Var::Principal),
                        Expr::val(r#"Group::"friends""#.parse::<EntityUID>().unwrap()),
                    ),
                ),
            ),
            (
                r#"principal is User && principal in Group::"friends""#,
                Expr::and(
                    Expr::is_entity_type(Expr::var(ast::Var::Principal), "User".parse().unwrap()),
                    Expr::is_in(
                        Expr::var(ast::Var::Principal),
                        Expr::val(r#"Group::"friends""#.parse::<EntityUID>().unwrap()),
                    ),
                ),
            ),
            (
                r#"principal is User || principal in Group::"friends""#,
                Expr::or(
                    Expr::is_entity_type(Expr::var(ast::Var::Principal), "User".parse().unwrap()),
                    Expr::is_in(
                        Expr::var(ast::Var::Principal),
                        Expr::val(r#"Group::"friends""#.parse::<EntityUID>().unwrap()),
                    ),
                ),
            ),
            (
                r#"true && principal is User in principal"#,
                Expr::and(
                    Expr::val(true),
                    Expr::and(
                        Expr::is_entity_type(
                            Expr::var(ast::Var::Principal),
                            "User".parse().unwrap(),
                        ),
                        Expr::is_in(
                            Expr::var(ast::Var::Principal),
                            Expr::var(ast::Var::Principal),
                        ),
                    ),
                ),
            ),
            (
                r#"principal is User in principal && true"#,
                Expr::and(
                    Expr::and(
                        Expr::is_entity_type(
                            Expr::var(ast::Var::Principal),
                            "User".parse().unwrap(),
                        ),
                        Expr::is_in(
                            Expr::var(ast::Var::Principal),
                            Expr::var(ast::Var::Principal),
                        ),
                    ),
                    Expr::val(true),
                ),
            ),
            (
                r#"principal is A::B::C::User"#,
                Expr::is_entity_type(
                    Expr::var(ast::Var::Principal),
                    "A::B::C::User".parse().unwrap(),
                ),
            ),
            (
                r#"principal is A::B::C::User in Group::"friends""#,
                Expr::and(
                    Expr::is_entity_type(
                        Expr::var(ast::Var::Principal),
                        "A::B::C::User".parse().unwrap(),
                    ),
                    Expr::is_in(
                        Expr::var(ast::Var::Principal),
                        Expr::val(r#"Group::"friends""#.parse::<EntityUID>().unwrap()),
                    ),
                ),
            ),
            (
                r#"if principal is User then 1 else 2"#,
                Expr::ite(
                    Expr::is_entity_type(Expr::var(ast::Var::Principal), "User".parse().unwrap()),
                    Expr::val(1),
                    Expr::val(2),
                ),
            ),
            (
                r#"if principal is User in Group::"friends" then 1 else 2"#,
                Expr::ite(
                    Expr::and(
                        Expr::is_entity_type(
                            Expr::var(ast::Var::Principal),
                            "User".parse().unwrap(),
                        ),
                        Expr::is_in(
                            Expr::var(ast::Var::Principal),
                            Expr::val(r#"Group::"friends""#.parse::<EntityUID>().unwrap()),
                        ),
                    ),
                    Expr::val(1),
                    Expr::val(2),
                ),
            ),
            (
                r#"principal::"alice" is principal"#,
                Expr::is_entity_type(
                    Expr::val(r#"principal::"alice""#.parse::<EntityUID>().unwrap()),
                    "principal".parse().unwrap(),
                ),
            ),
            (
                r#"foo::principal::"alice" is foo::principal"#,
                Expr::is_entity_type(
                    Expr::val(r#"foo::principal::"alice""#.parse::<EntityUID>().unwrap()),
                    "foo::principal".parse().unwrap(),
                ),
            ),
            (
                r#"principal::foo::"alice" is principal::foo"#,
                Expr::is_entity_type(
                    Expr::val(r#"principal::foo::"alice""#.parse::<EntityUID>().unwrap()),
                    "principal::foo".parse().unwrap(),
                ),
            ),
            (
                r#"resource::"thing" is resource"#,
                Expr::is_entity_type(
                    Expr::val(r#"resource::"thing""#.parse::<EntityUID>().unwrap()),
                    "resource".parse().unwrap(),
                ),
            ),
            (
                r#"action::"do" is action"#,
                Expr::is_entity_type(
                    Expr::val(r#"action::"do""#.parse::<EntityUID>().unwrap()),
                    "action".parse().unwrap(),
                ),
            ),
            (
                r#"context::"stuff" is context"#,
                Expr::is_entity_type(
                    Expr::val(r#"context::"stuff""#.parse::<EntityUID>().unwrap()),
                    "context".parse().unwrap(),
                ),
            ),
        ] {
            let e = parse_expr(es).unwrap();
            assert!(
                e.eq_shape(&expr),
                "{:?} and {:?} should have the same shape.",
                e,
                expr
            );
        }
    }

    #[test]
    fn is_scope() {
        for (src, p, a, r) in [
            (
                r#"permit(principal is User, action, resource);"#,
                PrincipalConstraint::is_entity_type("User".parse().unwrap()),
                ActionConstraint::any(),
                ResourceConstraint::any(),
            ),
            (
                r#"permit(principal is principal, action, resource);"#,
                PrincipalConstraint::is_entity_type("principal".parse().unwrap()),
                ActionConstraint::any(),
                ResourceConstraint::any(),
            ),
            (
                r#"permit(principal is A::User, action, resource);"#,
                PrincipalConstraint::is_entity_type("A::User".parse().unwrap()),
                ActionConstraint::any(),
                ResourceConstraint::any(),
            ),
            (
                r#"permit(principal is User in Group::"thing", action, resource);"#,
                PrincipalConstraint::is_entity_type_in(
                    "User".parse().unwrap(),
                    r#"Group::"thing""#.parse().unwrap(),
                ),
                ActionConstraint::any(),
                ResourceConstraint::any(),
            ),
            (
                r#"permit(principal is principal in Group::"thing", action, resource);"#,
                PrincipalConstraint::is_entity_type_in(
                    "principal".parse().unwrap(),
                    r#"Group::"thing""#.parse().unwrap(),
                ),
                ActionConstraint::any(),
                ResourceConstraint::any(),
            ),
            (
                r#"permit(principal is A::User in Group::"thing", action, resource);"#,
                PrincipalConstraint::is_entity_type_in(
                    "A::User".parse().unwrap(),
                    r#"Group::"thing""#.parse().unwrap(),
                ),
                ActionConstraint::any(),
                ResourceConstraint::any(),
            ),
            (
                r#"permit(principal is User in ?principal, action, resource);"#,
                PrincipalConstraint::is_entity_type_in_slot("User".parse().unwrap()),
                ActionConstraint::any(),
                ResourceConstraint::any(),
            ),
            (
                r#"permit(principal, action, resource is Folder);"#,
                PrincipalConstraint::any(),
                ActionConstraint::any(),
                ResourceConstraint::is_entity_type("Folder".parse().unwrap()),
            ),
            (
                r#"permit(principal, action, resource is Folder in Folder::"inner");"#,
                PrincipalConstraint::any(),
                ActionConstraint::any(),
                ResourceConstraint::is_entity_type_in(
                    "Folder".parse().unwrap(),
                    r#"Folder::"inner""#.parse().unwrap(),
                ),
            ),
            (
                r#"permit(principal, action, resource is Folder in ?resource);"#,
                PrincipalConstraint::any(),
                ActionConstraint::any(),
                ResourceConstraint::is_entity_type_in_slot("Folder".parse().unwrap()),
            ),
        ] {
            let policy = parse_policy_template(None, src).unwrap();
            assert_eq!(policy.principal_constraint(), &p);
            assert_eq!(policy.action_constraint(), &a);
            assert_eq!(policy.resource_constraint(), &r);
        }
    }

    #[test]
    fn is_err() {
        let invalid_is_policies = [
            (
                r#"permit(principal in Group::"friends" is User, action, resource);"#,
                ExpectedErrorMessageBuilder::error("expected an entity uid or matching template slot, found an `is` expression").exactly_one_underline(r#"Group::"friends" is User"#).build(),
            ),
            (
                r#"permit(principal, action, resource in Folder::"folder" is File);"#,
                ExpectedErrorMessageBuilder::error("expected an entity uid or matching template slot, found an `is` expression").exactly_one_underline(r#"Folder::"folder" is File"#).build(),
            ),
            (
                r#"permit(principal is User == User::"Alice", action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    "`is` cannot appear in the scope at the same time as `==`",
                ).help(
                    "try moving `is` into a `when` condition"
                ).exactly_one_underline("principal is User == User::\"Alice\"").build(),
            ),
            (
                r#"permit(principal, action, resource is Doc == Doc::"a");"#,
                ExpectedErrorMessageBuilder::error(
                    "`is` cannot appear in the scope at the same time as `==`",
                ).help(
                    "try moving `is` into a `when` condition"
                ).exactly_one_underline("resource is Doc == Doc::\"a\"").build(),
            ),
            (
                r#"permit(principal is User::"alice", action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `User::"alice"`"#,
                ).help(
                    "try using `==` to test for equality"
                ).exactly_one_underline("User::\"alice\"").build(),
            ),
            (
                r#"permit(principal, action, resource is File::"f");"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `File::"f"`"#,
                ).help(
                    "try using `==` to test for equality"
                ).exactly_one_underline("File::\"f\"").build(),
            ),
            (
                r#"permit(principal is User in 1, action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    "expected an entity uid or matching template slot, found literal `1`",
                ).exactly_one_underline("1").build(),
            ),
            (
                r#"permit(principal, action, resource is File in 1);"#,
                ExpectedErrorMessageBuilder::error(
                    "expected an entity uid or matching template slot, found literal `1`",
                ).exactly_one_underline("1").build(),
            ),
            (
                r#"permit(principal is User in User, action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    "expected an entity uid or matching template slot, found name `User`",
                ).exactly_one_underline("User").build(),
            ),
            (
                r#"permit(principal is User::"Alice" in Group::"f", action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `User::"Alice"`"#,
                ).help(
                    "try using `==` to test for equality"
                ).exactly_one_underline("User::\"Alice\"").build(),
            ),
            (
                r#"permit(principal, action, resource is File in File);"#,
                ExpectedErrorMessageBuilder::error(
                    "expected an entity uid or matching template slot, found name `File`",
                ).exactly_one_underline("File").build(),
            ),
            (
                r#"permit(principal, action, resource is File::"file" in Folder::"folder");"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `File::"file"`"#,
                ).help(
                    "try using `==` to test for equality"
                ).exactly_one_underline("File::\"file\"").build(),
            ),
            (
                r#"permit(principal is 1, action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `1`"#,
                ).help(
                    "try using `==` to test for equality"
                ).exactly_one_underline("1").build(),
            ),
            (
                r#"permit(principal, action, resource is 1);"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `1`"#,
                ).help(
                    "try using `==` to test for equality"
                ).exactly_one_underline("1").build(),
            ),
            (
                r#"permit(principal, action is Action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    "`is` cannot appear in the action scope",
                ).help(
                    "try moving `action is ..` into a `when` condition"
                ).exactly_one_underline("action is Action").build(),
            ),
            (
                r#"permit(principal, action is Action::"a", resource);"#,
                ExpectedErrorMessageBuilder::error(
                    "`is` cannot appear in the action scope",
                ).help(
                    "try moving `action is ..` into a `when` condition"
                ).exactly_one_underline("action is Action::\"a\"").build(),
            ),
            (
                r#"permit(principal, action is Action in Action::"A", resource);"#,
                ExpectedErrorMessageBuilder::error(
                    "`is` cannot appear in the action scope",
                ).help(
                    "try moving `action is ..` into a `when` condition"
                ).exactly_one_underline("action is Action in Action::\"A\"").build(),
            ),
            (
                r#"permit(principal, action is Action in Action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    "`is` cannot appear in the action scope",
                ).help(
                    "try moving `action is ..` into a `when` condition"
                ).exactly_one_underline("action is Action in Action").build(),
            ),
            (
                r#"permit(principal, action is Action::"a" in Action::"b", resource);"#,
                ExpectedErrorMessageBuilder::error(
                    "`is` cannot appear in the action scope",
                ).help(
                    "try moving `action is ..` into a `when` condition"
                ).exactly_one_underline("action is Action::\"a\" in Action::\"b\"").build(),
            ),
            (
                r#"permit(principal, action is Action in ?action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    "`is` cannot appear in the action scope",
                ).help(
                    "try moving `action is ..` into a `when` condition"
                ).exactly_one_underline("action is Action in ?action").build(),
            ),
            (
                r#"permit(principal, action is ?action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    "`is` cannot appear in the action scope",
                ).help(
                    "try moving `action is ..` into a `when` condition"
                ).exactly_one_underline("action is ?action").build(),
            ),
            (
                r#"permit(principal is User in ?resource, action, resource);"#,
                ExpectedErrorMessageBuilder::error("expected an entity uid or matching template slot, found ?resource instead of ?principal").exactly_one_underline("?resource").build(),
            ),
            (
                r#"permit(principal, action, resource is Folder in ?principal);"#,
                ExpectedErrorMessageBuilder::error("expected an entity uid or matching template slot, found ?principal instead of ?resource").exactly_one_underline("?principal").build(),
            ),
            (
                r#"permit(principal is ?principal, action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    "right hand side of an `is` expression must be an entity type name, but got `?principal`",
                ).help(
                    "try using `==` to test for equality"
                ).exactly_one_underline("?principal").build(),
            ),
            (
                r#"permit(principal, action, resource is ?resource);"#,
                ExpectedErrorMessageBuilder::error(
                    "right hand side of an `is` expression must be an entity type name, but got `?resource`",
                ).help(
                    "try using `==` to test for equality"
                ).exactly_one_underline("?resource").build(),
            ),
            (
                r#"permit(principal, action, resource) when { principal is 1 };"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `1`"#,
                ).help(
                    "try using `==` to test for equality"
                ).exactly_one_underline("1").build(),
            ),
            (
                r#"permit(principal, action, resource) when { principal is User::"alice" in Group::"friends" };"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `User::"alice"`"#,
                ).help(
                    "try using `==` to test for equality"
                ).exactly_one_underline("User::\"alice\"").build(),
            ),
            (
                r#"permit(principal, action, resource) when { principal is ! User::"alice" in Group::"friends" };"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `!User::"alice"`"#,
                ).help(
                    "try using `==` to test for equality"
                ).exactly_one_underline("! User::\"alice\"").build(),
            ),
            (
                r#"permit(principal, action, resource) when { principal is User::"alice" + User::"alice" in Group::"friends" };"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `User::"alice" + User::"alice"`"#,
                ).help(
                    "try using `==` to test for equality"
                ).exactly_one_underline("User::\"alice\" + User::\"alice\"").build(),
            ),
            (
                r#"permit(principal, action, resource) when { principal is User in User::"alice" in Group::"friends" };"#,
                ExpectedErrorMessageBuilder::error(
                    "unexpected token `in`"
                ).exactly_one_underline("in").build(),
            ),
            (
                r#"permit(principal, action, resource) when { principal is User == User::"alice" in Group::"friends" };"#,
                ExpectedErrorMessageBuilder::error(
                    "unexpected token `==`"
                ).exactly_one_underline("==").build(),
            ),
        ];
        for (p_src, expected) in invalid_is_policies {
            assert_matches!(parse_policy_template(None, p_src), Err(e) => {
                expect_err(p_src, &miette::Report::new(e), &expected);
            });
        }
    }

    #[test]
    fn issue_255() {
        let policy = r#"
            permit (
                principal == name-with-dashes::"Alice",
                action,
                resource
            );
        "#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "expected an entity uid or matching template slot, found a `+/-` expression",
                ).help(
                    "entity types and namespaces cannot use `+` or `-` characters -- perhaps try `_` or `::` instead?",
                ).exactly_one_underline("name-with-dashes::\"Alice\"").build());
            }
        );
    }

    #[test]
    fn invalid_methods_function_calls() {
        let invalid_exprs = [
            (
                r#"contains([], 1)"#,
                ExpectedErrorMessageBuilder::error("`contains` is a method, not a function")
                    .help("use a method-style call: `e.contains(..)`")
                    .exactly_one_underline("contains([], 1)")
                    .build(),
            ),
            (
                r#"[].contains()"#,
                ExpectedErrorMessageBuilder::error(
                    "call to `contains` requires exactly 1 argument, but got 0 arguments",
                )
                .exactly_one_underline("[].contains()")
                .build(),
            ),
            (
                r#"[].contains(1, 2)"#,
                ExpectedErrorMessageBuilder::error(
                    "call to `contains` requires exactly 1 argument, but got 2 arguments",
                )
                .exactly_one_underline("[].contains(1, 2)")
                .build(),
            ),
            (
                r#"[].containsAll()"#,
                ExpectedErrorMessageBuilder::error(
                    "call to `containsAll` requires exactly 1 argument, but got 0 arguments",
                )
                .exactly_one_underline("[].containsAll()")
                .build(),
            ),
            (
                r#"[].containsAll(1, 2)"#,
                ExpectedErrorMessageBuilder::error(
                    "call to `containsAll` requires exactly 1 argument, but got 2 arguments",
                )
                .exactly_one_underline("[].containsAll(1, 2)")
                .build(),
            ),
            (
                r#"[].containsAny()"#,
                ExpectedErrorMessageBuilder::error(
                    "call to `containsAny` requires exactly 1 argument, but got 0 arguments",
                )
                .exactly_one_underline("[].containsAny()")
                .build(),
            ),
            (
                r#"[].containsAny(1, 2)"#,
                ExpectedErrorMessageBuilder::error(
                    "call to `containsAny` requires exactly 1 argument, but got 2 arguments",
                )
                .exactly_one_underline("[].containsAny(1, 2)")
                .build(),
            ),
            (
                r#""1.1.1.1".ip()"#,
                ExpectedErrorMessageBuilder::error("`ip` is a function, not a method")
                    .help("use a function-style call: `ip(..)`")
                    .exactly_one_underline(r#""1.1.1.1".ip()"#)
                    .build(),
            ),
            (
                r#"greaterThan(1, 2)"#,
                ExpectedErrorMessageBuilder::error("`greaterThan` is a method, not a function")
                    .help("use a method-style call: `e.greaterThan(..)`")
                    .exactly_one_underline("greaterThan(1, 2)")
                    .build(),
            ),
            (
                "[].bar()",
                ExpectedErrorMessageBuilder::error("not a valid method name: `bar`")
                    .exactly_one_underline("[].bar()")
                    .build(),
            ),
            (
                "bar([])",
                ExpectedErrorMessageBuilder::error("`bar` is not a function")
                    .exactly_one_underline("bar([])")
                    .build(),
            ),
            (
                "principal()",
                ExpectedErrorMessageBuilder::error("`principal(...)` is not a valid function call")
                    .help("variables cannot be called as functions")
                    .exactly_one_underline("principal()")
                    .build(),
            ),
            (
                "(1+1)()",
                ExpectedErrorMessageBuilder::error(
                    "function calls must be of the form: `<name>(arg1, arg2, ...)`",
                )
                .exactly_one_underline("(1+1)()")
                .build(),
            ),
            (
                "foo.bar()",
                ExpectedErrorMessageBuilder::error(
                    "attempted to call `foo.bar`, but `foo` does not have any methods",
                )
                .exactly_one_underline("foo.bar()")
                .build(),
            ),
        ];
        for (src, expected) in invalid_exprs {
            assert_matches!(parse_expr(src), Err(e) => {
                expect_err(src, &miette::Report::new(e), &expected);
            });
        }
    }

    #[test]
    fn invalid_slot() {
        let invalid_policies = [
            (
                r#"permit(principal == ?resource, action, resource);"#,
                ExpectedErrorMessageBuilder::error("expected an entity uid or matching template slot, found ?resource instead of ?principal").exactly_one_underline("?resource").build(),
            ),
            (
                r#"permit(principal in ?resource, action, resource);"#,
                ExpectedErrorMessageBuilder::error("expected an entity uid or matching template slot, found ?resource instead of ?principal").exactly_one_underline("?resource").build(),
            ),
            (
                r#"permit(principal == ?foo, action, resource);"#,
                ExpectedErrorMessageBuilder::error("expected an entity uid or matching template slot, found ?foo instead of ?principal").exactly_one_underline("?foo").build(),
            ),
            (
                r#"permit(principal in ?foo, action, resource);"#,
                ExpectedErrorMessageBuilder::error("expected an entity uid or matching template slot, found ?foo instead of ?principal").exactly_one_underline("?foo").build(),
            ),

            (
                r#"permit(principal, action, resource == ?principal);"#,
                ExpectedErrorMessageBuilder::error("expected an entity uid or matching template slot, found ?principal instead of ?resource").exactly_one_underline("?principal").build(),
            ),
            (
                r#"permit(principal, action, resource in ?principal);"#,
                ExpectedErrorMessageBuilder::error("expected an entity uid or matching template slot, found ?principal instead of ?resource").exactly_one_underline("?principal").build(),
            ),
            (
                r#"permit(principal, action, resource == ?baz);"#,
                ExpectedErrorMessageBuilder::error("expected an entity uid or matching template slot, found ?baz instead of ?resource").exactly_one_underline("?baz").build(),
            ),
            (
                r#"permit(principal, action, resource in ?baz);"#,
                ExpectedErrorMessageBuilder::error("expected an entity uid or matching template slot, found ?baz instead of ?resource").exactly_one_underline("?baz").build(),
            ),
            (
                r#"permit(principal, action, resource) when { principal == ?foo};"#,
                ExpectedErrorMessageBuilder::error(
                    "`?foo` is not a valid template slot",
                ).help(
                    "a template slot may only be `?principal` or `?resource`",
                ).exactly_one_underline("?foo").build(),
            ),

            (
                r#"permit(principal, action == ?action, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid, got: template slot").exactly_one_underline("?action").build(),
            ),
            (
                r#"permit(principal, action in ?action, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid or set of entity uids, got: template slot").exactly_one_underline("?action").build(),
            ),
            (
                r#"permit(principal, action == ?principal, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid, got: template slot").exactly_one_underline("?principal").build(),
            ),
            (
                r#"permit(principal, action in ?principal, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid or set of entity uids, got: template slot").exactly_one_underline("?principal").build(),
            ),
            (
                r#"permit(principal, action == ?resource, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid, got: template slot").exactly_one_underline("?resource").build(),
            ),
            (
                r#"permit(principal, action in ?resource, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid or set of entity uids, got: template slot").exactly_one_underline("?resource").build(),
            ),
            (
                r#"permit(principal, action in [?bar], resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid, got: template slot").exactly_one_underline("?bar").build(),
            ),
        ];

        for (p_src, expected) in invalid_policies {
            assert_matches!(parse_policy_template(None, p_src), Err(e) => {
                expect_err(p_src, &miette::Report::new(e), &expected);
            });
            let forbid_src = format!("forbid{}", &p_src[6..]);
            assert_matches!(parse_policy_template(None, &forbid_src), Err(e) => {
                expect_err(forbid_src.as_str(), &miette::Report::new(e), &expected);
            });
        }
    }

    #[test]
    fn missing_scope_constraint() {
        let p_src = "permit();";
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("this policy is missing the `principal` variable in the scope").exactly_one_underline("").build());
        });
        let p_src = "permit(principal);";
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("this policy is missing the `action` variable in the scope").exactly_one_underline("").build());
        });
        let p_src = "permit(principal, action);";
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("this policy is missing the `resource` variable in the scope").exactly_one_underline("").build());
        });
    }

    #[test]
    fn invalid_scope_constraint() {
        let p_src = "permit(foo, action, resource);";
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "expected a variable that is valid in the policy scope; found: `foo`",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("foo").build());
        });
        let p_src = "permit(foo::principal, action, resource);";
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "unexpected token `::`",
            ).exactly_one_underline("::").build());
        });
        let p_src = "permit(resource, action, resource);";
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found the variable `resource` where the variable `principal` must be used",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("resource").build());
        });

        let p_src = "permit(principal, principal, resource);";
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found the variable `principal` where the variable `action` must be used",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("principal").build());
        });
        let p_src = "permit(principal, if, resource);";
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "expected a variable that is valid in the policy scope; found: `if`",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("if").build());
        });

        let p_src = "permit(principal, action, like);";
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "expected a variable that is valid in the policy scope; found: `like`",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("like").build());
        });
        let p_src = "permit(principal, action, principal);";
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found the variable `principal` where the variable `resource` must be used",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("principal").build());
        });
        let p_src = "permit(principal, action, action);";
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found the variable `action` where the variable `resource` must be used",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("action").build());
        });
    }

    #[test]
    fn invalid_scope_operator() {
        let p_src = r#"permit(principal > User::"alice", action, resource);"#;
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "not a valid policy scope constraint: >",
                ).help(
                "policy scope constraints must be either `==`, `in`, `is`, or `_ is _ in _`"
            ).exactly_one_underline("principal > User::\"alice\"").build());
        });
        let p_src = r#"permit(principal, action != Action::"view", resource);"#;
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "not a valid policy scope constraint: !=",
                ).help(
                "policy scope constraints must be either `==`, `in`, `is`, or `_ is _ in _`"
            ).exactly_one_underline("action != Action::\"view\"").build());
        });
        let p_src = r#"permit(principal, action, resource <= Folder::"things");"#;
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "not a valid policy scope constraint: <=",
                ).help(
                "policy scope constraints must be either `==`, `in`, `is`, or `_ is _ in _`"
            ).exactly_one_underline("resource <= Folder::\"things\"").build());
        });
        let p_src = r#"permit(principal = User::"alice", action, resource);"#;
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "'=' is not a valid operator in Cedar",
                ).help(
                "try using '==' instead",
            ).exactly_one_underline("principal = User::\"alice\"").build());
        });
    }

    #[test]
    fn scope_action_eq_set() {
        let p_src = r#"permit(principal, action == [Action::"view", Action::"edit"], resource);"#;
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("expected single entity uid, got: set of entity uids").exactly_one_underline(r#"[Action::"view", Action::"edit"]"#).build());
        });
    }

    #[test]
    fn scope_action_in_set_set() {
        let p_src = r#"permit(principal, action in [[Action::"view"]], resource);"#;
        assert_matches!(parse_policy_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("expected single entity uid, got: set of entity uids").exactly_one_underline(r#"[Action::"view"]"#).build());
        });
    }

    #[test]
    fn unsupported_ops() {
        let src = "1/2";
        assert_matches!(parse_expr(src), Err(e) => {
            expect_err(src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("division is not supported").exactly_one_underline("1/2").build());
        });
        let src = "7 % 3";
        assert_matches!(parse_expr(src), Err(e) => {
            expect_err(src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("remainder/modulo is not supported").exactly_one_underline("7 % 3").build());
        });
    }

    #[test]
    fn over_unary() {
        let src = "!!!!!!false";
        assert_matches!(parse_expr(src), Err(e) => {
            expect_err(src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "too many occurrences of `!_`",
                ).help(
                "cannot chain more the 4 applications of a unary operator"
            ).exactly_one_underline("!!!!!!false").build());
        });
        let src = "-------0";
        assert_matches!(parse_expr(src), Err(e) => {
            expect_err(src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "too many occurrences of `-_`",
                ).help(
                "cannot chain more the 4 applications of a unary operator"
            ).exactly_one_underline("-------0").build());
        });
    }

    #[test]
    fn arbitrary_variables() {
        #[track_caller]
        fn expect_arbitrary_var(name: &str) {
            assert_matches!(parse_expr(name), Err(e) => {
                expect_err(name, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                    "arbitrary variables are not supported; the valid Cedar variables are `principal`, `action`, `resource`, and `context`",
                ).help(
                    &format!("did you mean to enclose `{name}` in quotes to make a string?"),
                ).exactly_one_underline(name).build());
            })
        }
        expect_arbitrary_var("foo::principal");
        expect_arbitrary_var("bar::action");
        expect_arbitrary_var("baz::resource");
        expect_arbitrary_var("buz::context");
        expect_arbitrary_var("foo::principal");
        expect_arbitrary_var("foo::bar::principal");
        expect_arbitrary_var("principal::foo");
        expect_arbitrary_var("principal::foo::bar");
        expect_arbitrary_var("foo::principal::bar");
        expect_arbitrary_var("foo");
        expect_arbitrary_var("foo::bar");
        expect_arbitrary_var("foo::bar::baz");
    }

    #[test]
    fn empty_clause() {
        #[track_caller]
        fn expect_empty_clause(policy: &str, clause: &str) {
            assert_matches!(parse_policy_template(None, policy), Err(e) => {
                expect_err(policy, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                    &format!("`{clause}` condition clause cannot be empty")
                ).exactly_one_underline(&format!("{clause} {{}}")).build());
            })
        }

        expect_empty_clause("permit(principal, action, resource) when {};", "when");
        expect_empty_clause("permit(principal, action, resource) unless {};", "unless");
        expect_empty_clause(
            "permit(principal, action, resource) when { principal has foo } when {};",
            "when",
        );
        expect_empty_clause(
            "permit(principal, action, resource) when { principal has foo } unless {};",
            "unless",
        );
        expect_empty_clause(
            "permit(principal, action, resource) when {} unless { resource.bar };",
            "when",
        );
        expect_empty_clause(
            "permit(principal, action, resource) unless {} unless { resource.bar };",
            "unless",
        );
    }

    #[test]
    fn namespaced_attr() {
        #[track_caller]
        fn expect_namespaced_attr(expr: &str, name: &str) {
            assert_matches!(parse_expr(expr), Err(e) => {
                expect_err(expr, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                    &format!("`{name}` cannot be used as an attribute as it contains a namespace")
                ).exactly_one_underline(name).build());
            })
        }

        expect_namespaced_attr("principal has foo::bar", "foo::bar");
        expect_namespaced_attr("principal has foo::bar::baz", "foo::bar::baz");
        expect_namespaced_attr("principal has foo::principal", "foo::principal");
        expect_namespaced_attr("{foo::bar: 1}", "foo::bar");

        let expr = "principal has if::foo";
        assert_matches!(parse_expr(expr), Err(e) => {
            expect_err(expr, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: `if`"
            ).exactly_one_underline("if").build());
        })
    }

    #[test]
    fn reserved_ident_var() {
        #[track_caller]
        fn expect_reserved_ident(name: &str, reserved: &str) {
            assert_matches!(parse_expr(name), Err(e) => {
                expect_err(name, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                    &format!("this identifier is reserved and cannot be used: `{reserved}`"),
                ).exactly_one_underline(reserved).build());
            })
        }
        expect_reserved_ident("if::principal", "if");
        expect_reserved_ident("then::action", "then");
        expect_reserved_ident("else::resource", "else");
        expect_reserved_ident("true::context", "true");
        expect_reserved_ident("false::bar::principal", "false");
        expect_reserved_ident("foo::in::principal", "in");
        expect_reserved_ident("foo::is::bar::principal", "is");
    }
}
