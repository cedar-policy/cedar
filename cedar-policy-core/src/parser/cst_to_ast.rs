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

use super::err::{parse_errors, ParseError, ParseErrors, ToASTError, ToASTErrorKind};
use super::node::Node;
use super::unescape::{to_pattern, to_unescaped_string};
use super::util::{flatten_tuple_2, flatten_tuple_3, flatten_tuple_4};
use super::{cst, AsLocRef, IntoMaybeLoc, Loc, MaybeLoc};
#[cfg(feature = "tolerant-ast")]
use crate::ast::expr_allows_errors::ExprWithErrsBuilder;
use crate::ast::{
    self, ActionConstraint, CallStyle, Integer, PatternElem, PolicySetError, PrincipalConstraint,
    PrincipalOrResourceConstraint, ResourceConstraint, UnreservedId,
};
use crate::expr_builder::ExprBuilder;
use crate::fuzzy_match::fuzzy_search_limited;
use itertools::{Either, Itertools};
use nonempty::nonempty;
use nonempty::NonEmpty;
use smol_str::{format_smolstr, SmolStr, ToSmolStr};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::mem;
use std::sync::Arc;

/// Defines the function `cst::Expr::to_ref_or_refs` and other similar functions
/// for converting CST expressions into one or multiple entity UIDS. Used to
/// extract entity uids from expressions that appear in the policy scope.
mod to_ref_or_refs;
use to_ref_or_refs::OneOrMultipleRefs;

const INVALID_SNIPPET: &str = "<invalid>";

/// Type alias for convenience
type Result<T> = std::result::Result<T, ParseErrors>;

// for storing extension function names per callstyle
struct ExtStyles<'a> {
    /// All extension function names (just functions, not methods), as `Name`s
    functions: HashSet<&'a ast::Name>,
    /// All extension function methods. `UnreservedId` is appropriate because methods cannot be namespaced.
    methods: HashSet<ast::UnreservedId>,
    /// All extension function and method names (both qualified and unqualified), in their string (`Display`) form
    functions_and_methods_as_str: HashSet<SmolStr>,
}

// Store extension function call styles
lazy_static::lazy_static! {
    static ref EXTENSION_STYLES: ExtStyles<'static> = load_styles();
}
fn load_styles() -> ExtStyles<'static> {
    let mut functions = HashSet::new();
    let mut methods = HashSet::new();
    let mut functions_and_methods_as_str = HashSet::new();
    for func in crate::extensions::Extensions::all_available().all_funcs() {
        functions_and_methods_as_str.insert(func.name().to_smolstr());
        match func.style() {
            CallStyle::FunctionStyle => {
                functions.insert(func.name());
            }
            CallStyle::MethodStyle => {
                debug_assert!(func.name().is_unqualified());
                methods.insert(func.name().basename());
            }
        };
    }
    ExtStyles {
        functions,
        methods,
        functions_and_methods_as_str,
    }
}

impl Node<Option<cst::Policies>> {
    /// Iterate over the `Policy` nodes in this `cst::Policies`, with
    /// corresponding generated `PolicyID`s
    pub fn with_generated_policyids(
        &self,
    ) -> Result<impl Iterator<Item = (ast::PolicyID, &Node<Option<cst::Policy>>)>> {
        let policies = self.try_as_inner()?;

        Ok(policies.0.iter().enumerate().map(|(count, node)| {
            (
                ast::PolicyID::from_smolstr(format_smolstr!("policy{count}")),
                node,
            )
        }))
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
                Ok(Either::Left(static_policy)) => {
                    if let Err(e) = pset.add_static(static_policy) {
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

    /// convert `cst::Policies` to `ast::PolicySet`
    #[cfg(feature = "tolerant-ast")]
    pub fn to_policyset_tolerant(&self) -> Result<ast::PolicySet> {
        let mut pset = ast::PolicySet::new();
        let mut all_errs: Vec<ParseErrors> = vec![];
        // Caution: `parser::parse_policyset_and_also_return_policy_text()`
        // depends on this function returning a policy set with `PolicyID`s as
        // generated by `with_generated_policyids()` to maintain an invariant.
        for (policy_id, policy) in self.with_generated_policyids()? {
            // policy may have convert error
            match policy.to_policy_or_template_tolerant(policy_id) {
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
                Ok(Either::Left(static_policy)) => {
                    if let Err(e) = pset.add_static(static_policy) {
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
    /// Convert `cst::Policy` to `ast::Template`. Works for static policies as
    /// well, which will become templates with 0 slots
    pub fn to_template(&self, id: ast::PolicyID) -> Result<ast::Template> {
        self.to_policy_template(id)
    }

    /// Convert `cst::Policy` to `ast::Template`. Works for static policies as
    /// well, which will become templates with 0 slots
    #[cfg(feature = "tolerant-ast")]
    pub fn to_template_tolerant(&self, id: ast::PolicyID) -> Result<ast::Template> {
        self.to_policy_template_tolerant(id)
    }

    /// Convert `cst::Policy` to an AST `StaticPolicy` or `Template`
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

    /// Convert `cst::Policy` to an AST `StaticPolicy` or `Template`
    #[cfg(feature = "tolerant-ast")]
    pub fn to_policy_or_template_tolerant(
        &self,
        id: ast::PolicyID,
    ) -> Result<Either<ast::StaticPolicy, ast::Template>> {
        let t = self.to_policy_template_tolerant(id)?;
        if t.slots().count() == 0 {
            // PANIC SAFETY: A `Template` with no slots will successfully convert to a `StaticPolicy`
            #[allow(clippy::expect_used)]
            let p = ast::StaticPolicy::try_from(t).expect("internal invariant violation: a template with no slots should be a valid static policy");
            Ok(Either::Left(p))
        } else {
            Ok(Either::Right(t))
        }
    }

    /// Convert `cst::Policy` to an AST `StaticPolicy`. (Will fail if the CST is for a template)
    pub fn to_policy(&self, id: ast::PolicyID) -> Result<ast::StaticPolicy> {
        let maybe_template = self.to_policy_template(id);
        let maybe_policy = maybe_template.map(ast::StaticPolicy::try_from);
        match maybe_policy {
            // Successfully parsed a static policy
            Ok(Ok(p)) => Ok(p),
            // The source parsed as a template, but not a static policy
            Ok(Err(ast::UnexpectedSlotError::FoundSlot(slot))) => Err(ToASTError::new(
                ToASTErrorKind::expected_static_policy(slot.clone()),
                slot.loc.or_else(|| self.loc.clone()),
            )
            .into()),
            // The source failed to parse completely. If the parse errors include
            // `SlotsInConditionClause` also add an `ExpectedStaticPolicy` error.
            Err(mut errs) => {
                let new_errs = errs
                    .iter()
                    .filter_map(|err| match err {
                        ParseError::ToAST(err) => match err.kind() {
                            ToASTErrorKind::SlotsInConditionClause(inner) => Some(ToASTError::new(
                                ToASTErrorKind::expected_static_policy(inner.slot.clone()),
                                err.source_loc().into_maybe_loc(),
                            )),
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

    /// Convert `cst::Policy` to `ast::Template`. Works for static policies as
    /// well, which will become templates with 0 slots
    pub fn to_policy_template(&self, id: ast::PolicyID) -> Result<ast::Template> {
        let policy = self.try_as_inner()?;
        let policy = match policy {
            cst::Policy::Policy(policy_impl) => policy_impl,
            #[cfg(feature = "tolerant-ast")]
            cst::Policy::PolicyError => {
                // This will only happen if we use a 'tolerant' parser, otherwise errors should be caught
                // during parsing to CST
                return Err(ParseErrors::singleton(ToASTError::new(
                    ToASTErrorKind::CSTErrorNode,
                    self.loc.clone(),
                )));
            }
        };

        // convert effect
        let maybe_effect = policy.effect.to_effect();

        // convert annotations
        let maybe_annotations = policy.get_ast_annotations(|value, loc| {
            ast::Annotation::with_optional_value(value, loc.into_maybe_loc())
        });

        // convert scope
        let maybe_scope = policy.extract_scope();

        // convert conditions
        let maybe_conds = ParseErrors::transpose(policy.conds.iter().map(|c| {
            let (e, is_when) = c.to_expr::<ast::ExprBuilder<()>>()?;

            let slot_errs = e.slots().map(|slot| {
                ToASTError::new(
                    ToASTErrorKind::slots_in_condition_clause(
                        slot.clone(),
                        if is_when { "when" } else { "unless" },
                    ),
                    slot.loc.or_else(|| c.loc.clone()),
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
            annotations.into(),
            effect,
            principal,
            action,
            resource,
            conds,
            self.loc.as_loc_ref(),
        ))
    }

    /// Convert `cst::Policy` to an AST `StaticPolicy`. (Will fail if the CST is for a template)
    /// NOTE: This function allows partial parsing and can produce AST Error nodes
    /// These cannot be evaluated
    /// Should ONLY be used to examine a partially constructed AST from invalid Cedar
    #[cfg(feature = "tolerant-ast")]
    pub fn to_policy_tolerant(&self, id: ast::PolicyID) -> Result<ast::StaticPolicy> {
        let maybe_template = self.to_policy_template_tolerant(id);
        let maybe_policy = maybe_template.map(ast::StaticPolicy::try_from);
        match maybe_policy {
            // Successfully parsed a static policy
            Ok(Ok(p)) => Ok(p),
            // The source parsed as a template, but not a static policy
            Ok(Err(ast::UnexpectedSlotError::FoundSlot(slot))) => Err(ToASTError::new(
                ToASTErrorKind::expected_static_policy(slot.clone()),
                slot.loc.or_else(|| self.loc.clone()),
            )
            .into()),
            // The source failed to parse completely. If the parse errors include
            // `SlotsInConditionClause` also add an `ExpectedStaticPolicy` error.
            Err(mut errs) => {
                let new_errs = errs
                    .iter()
                    .filter_map(|err| match err {
                        ParseError::ToAST(err) => match err.kind() {
                            ToASTErrorKind::SlotsInConditionClause(inner) => Some(ToASTError::new(
                                ToASTErrorKind::expected_static_policy(inner.slot.clone()),
                                err.source_loc().into_maybe_loc(),
                            )),
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

    /// Convert `cst::Policy` to `ast::Template`. Works for static policies as
    /// well, which will become templates with 0 slots
    /// NOTE: This function allows partial parsing and can produce AST Error nodes
    /// These cannot be evaluated
    /// Should ONLY be used to examine a partially constructed AST from invalid Cedar
    #[cfg(feature = "tolerant-ast")]
    pub fn to_policy_template_tolerant(&self, id: ast::PolicyID) -> Result<ast::Template> {
        let policy = self.try_as_inner()?;
        let policy = match policy {
            cst::Policy::Policy(policy_impl) => policy_impl,
            cst::Policy::PolicyError => {
                return Ok(ast::Template::error(id, self.loc.clone()));
            }
        };
        // convert effect
        let maybe_effect = policy.effect.to_effect();

        // convert annotations
        let maybe_annotations = policy.get_ast_annotations(|value, loc| {
            ast::Annotation::with_optional_value(value, loc.into_maybe_loc())
        });

        // convert scope
        let maybe_scope = policy.extract_scope_tolerant_ast();

        // convert conditions
        let maybe_conds = ParseErrors::transpose(policy.conds.iter().map(|c| {
            let (e, is_when) = c.to_expr::<ExprWithErrsBuilder<()>>()?;
            let slot_errs = e.slots().map(|slot| {
                ToASTError::new(
                    ToASTErrorKind::slots_in_condition_clause(
                        slot.clone(),
                        if is_when { "when" } else { "unless" },
                    ),
                    slot.loc.or_else(|| c.loc.clone()),
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
            annotations.into(),
            effect,
            principal,
            action,
            resource,
            conds,
            self.loc.as_loc_ref(),
        ))
    }
}

impl cst::PolicyImpl {
    /// Get the scope constraints from the `cst::Policy`
    pub fn extract_scope(
        &self,
    ) -> Result<(PrincipalConstraint, ActionConstraint, ResourceConstraint)> {
        // Tracks where the last variable in the scope ended. We'll point to
        // this position to indicate where to fill in vars if we're missing one.
        let mut end_of_last_var = self.effect.loc.as_loc_ref().map(|loc| loc.end());

        let mut vars = self.variables.iter();
        let maybe_principal = if let Some(scope1) = vars.next() {
            end_of_last_var = scope1
                .loc
                .as_loc_ref()
                .map(|loc| loc.end())
                .or(end_of_last_var);
            scope1.to_principal_constraint(TolerantAstSetting::NotTolerant)
        } else {
            let effect_span = self
                .effect
                .loc
                .as_loc_ref()
                .and_then(|loc| end_of_last_var.map(|end| loc.span(end)))
                .into_maybe_loc();
            Err(ToASTError::new(
                ToASTErrorKind::MissingScopeVariable(ast::Var::Principal),
                effect_span,
            )
            .into())
        };
        let maybe_action = if let Some(scope2) = vars.next() {
            end_of_last_var = scope2
                .loc
                .as_loc_ref()
                .map(|loc| loc.end())
                .or(end_of_last_var);
            scope2.to_action_constraint(TolerantAstSetting::NotTolerant)
        } else {
            let effect_span = self
                .effect
                .loc
                .as_ref()
                .and_then(|loc| end_of_last_var.map(|end| loc.span(end)))
                .into_maybe_loc();
            Err(ToASTError::new(
                ToASTErrorKind::MissingScopeVariable(ast::Var::Action),
                effect_span,
            )
            .into())
        };
        let maybe_resource = if let Some(scope3) = vars.next() {
            scope3.to_resource_constraint(TolerantAstSetting::NotTolerant)
        } else {
            let effect_span = self
                .effect
                .loc
                .as_ref()
                .and_then(|loc| end_of_last_var.map(|end| loc.span(end)))
                .into_maybe_loc();
            Err(ToASTError::new(
                ToASTErrorKind::MissingScopeVariable(ast::Var::Resource),
                effect_span,
            )
            .into())
        };

        let maybe_extra_vars = if let Some(errs) = ParseErrors::from_iter(
            // Add each of the extra constraints to the error list
            vars.map(|extra_var| {
                extra_var
                    .try_as_inner()
                    .map(|def| {
                        extra_var
                            .to_ast_err(ToASTErrorKind::ExtraScopeElement(Box::new(def.clone())))
                    })
                    .unwrap_or_else(|e| e)
                    .into()
            }),
        ) {
            Err(errs)
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

    /// Get the scope constraints from the `cst::Policy`
    #[cfg(feature = "tolerant-ast")]
    pub fn extract_scope_tolerant_ast(
        &self,
    ) -> Result<(PrincipalConstraint, ActionConstraint, ResourceConstraint)> {
        // Tracks where the last variable in the scope ended. We'll point to
        // this position to indicate where to fill in vars if we're missing one.
        let mut end_of_last_var = self.effect.loc.as_loc_ref().map(|loc| loc.end());

        let mut vars = self.variables.iter();
        let maybe_principal = if let Some(scope1) = vars.next() {
            end_of_last_var = scope1
                .loc
                .as_loc_ref()
                .map(|loc| loc.end())
                .or(end_of_last_var);
            scope1.to_principal_constraint(TolerantAstSetting::Tolerant)
        } else {
            let effect_span = self
                .effect
                .loc
                .as_ref()
                .and_then(|loc| end_of_last_var.map(|end| loc.span(end)))
                .into_maybe_loc();
            Err(ToASTError::new(
                ToASTErrorKind::MissingScopeVariable(ast::Var::Principal),
                effect_span,
            )
            .into())
        };
        let maybe_action = if let Some(scope2) = vars.next() {
            end_of_last_var = scope2
                .loc
                .as_loc_ref()
                .map(|loc| loc.end())
                .or(end_of_last_var);
            scope2.to_action_constraint(TolerantAstSetting::Tolerant)
        } else {
            let effect_span = self
                .effect
                .loc
                .as_ref()
                .and_then(|loc| end_of_last_var.map(|end| loc.span(end)))
                .into_maybe_loc();
            Err(ToASTError::new(
                ToASTErrorKind::MissingScopeVariable(ast::Var::Action),
                effect_span,
            )
            .into())
        };
        let maybe_resource = if let Some(scope3) = vars.next() {
            scope3.to_resource_constraint(TolerantAstSetting::Tolerant)
        } else {
            let effect_span = self
                .effect
                .loc
                .as_ref()
                .and_then(|loc| end_of_last_var.map(|end| loc.span(end)))
                .into_maybe_loc();
            Err(ToASTError::new(
                ToASTErrorKind::MissingScopeVariable(ast::Var::Resource),
                effect_span,
            )
            .into())
        };

        let maybe_extra_vars = if let Some(errs) = ParseErrors::from_iter(
            // Add each of the extra constraints to the error list
            vars.map(|extra_var| {
                extra_var
                    .try_as_inner()
                    .map(|def| {
                        extra_var
                            .to_ast_err(ToASTErrorKind::ExtraScopeElement(Box::new(def.clone())))
                    })
                    .unwrap_or_else(|e| e)
                    .into()
            }),
        ) {
            Err(errs)
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
    pub fn get_ast_annotations<T>(
        &self,
        annotation_constructor: impl Fn(Option<SmolStr>, Option<&Loc>) -> T,
    ) -> Result<BTreeMap<ast::AnyId, T>> {
        let mut annotations = BTreeMap::new();
        let mut all_errs: Vec<ParseErrors> = vec![];
        for node in self.annotations.iter() {
            match node.to_kv_pair(&annotation_constructor) {
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
            None => Ok(annotations),
        }
    }
}

impl Node<Option<cst::Annotation>> {
    /// Get the (k, v) pair for the annotation. Critically, this checks validity
    /// for the strings and does unescaping
    pub fn to_kv_pair<T>(
        &self,
        annotation_constructor: impl Fn(Option<SmolStr>, Option<&Loc>) -> T,
    ) -> Result<(ast::AnyId, T)> {
        let anno = self.try_as_inner()?;

        let maybe_key = anno.key.to_any_ident();
        let maybe_value = anno
            .value
            .as_ref()
            .map(|a| {
                a.as_valid_string().and_then(|s| {
                    to_unescaped_string(s).map_err(|unescape_errs| {
                        ParseErrors::new_from_nonempty(
                            unescape_errs.map(|e| self.to_ast_err(e).into()),
                        )
                    })
                })
            })
            .transpose();

        let (k, v) = flatten_tuple_2(maybe_key, maybe_value)?;
        Ok((k, annotation_constructor(v, self.loc.as_loc_ref())))
    }
}

impl Node<Option<cst::Ident>> {
    /// Convert `cst::Ident` to `ast::UnreservedId`. Fails for reserved or invalid identifiers
    pub(crate) fn to_unreserved_ident(&self) -> Result<ast::UnreservedId> {
        self.to_valid_ident()
            .and_then(|id| id.try_into().map_err(|err| self.to_ast_err(err).into()))
    }
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
            cst::Ident::Ident(i) => Ok(ast::Id::new_unchecked(i.clone())),
            _ => Ok(ast::Id::new_unchecked(ident.to_smolstr())),
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
            cst::Ident::Ident(i) => Ok(ast::AnyId::new_unchecked(i.clone())),
            _ => Ok(ast::AnyId::new_unchecked(ident.to_smolstr())),
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
                .to_ast_err(ToASTErrorKind::InvalidScopeVariable(ident.clone()))
                .into()),
        }
    }
}

impl ast::UnreservedId {
    fn to_meth<Build: ExprBuilder>(
        &self,
        e: Build::Expr,
        args: Vec<Build::Expr>,
        loc: Option<&Loc>,
    ) -> Result<Build::Expr> {
        let builder = Build::new().with_maybe_source_loc(loc);
        match self.as_ref() {
            "contains" => extract_single_argument(args.into_iter(), "contains", loc)
                .map(|arg| builder.contains(e, arg)),
            "containsAll" => extract_single_argument(args.into_iter(), "containsAll", loc)
                .map(|arg| builder.contains_all(e, arg)),
            "containsAny" => extract_single_argument(args.into_iter(), "containsAny", loc)
                .map(|arg| builder.contains_any(e, arg)),
            "isEmpty" => {
                require_zero_arguments(&args.into_iter(), "isEmpty", loc)?;
                Ok(builder.is_empty(e))
            }
            "getTag" => extract_single_argument(args.into_iter(), "getTag", loc)
                .map(|arg| builder.get_tag(e, arg)),
            "hasTag" => extract_single_argument(args.into_iter(), "hasTag", loc)
                .map(|arg| builder.has_tag(e, arg)),
            _ => {
                if EXTENSION_STYLES.methods.contains(self) {
                    let args = NonEmpty {
                        head: e,
                        tail: args,
                    };
                    Ok(builder.call_extension_fn(ast::Name::unqualified_name(self.clone()), args))
                } else {
                    let unqual_name = ast::Name::unqualified_name(self.clone());
                    if EXTENSION_STYLES.functions.contains(&unqual_name) {
                        Err(ToASTError::new(
                            ToASTErrorKind::MethodCallOnFunction(unqual_name.basename()),
                            loc.into_maybe_loc(),
                        )
                        .into())
                    } else {
                        fn suggest_method(
                            name: &ast::UnreservedId,
                            methods: &HashSet<ast::UnreservedId>,
                        ) -> Option<String> {
                            const SUGGEST_METHOD_MAX_DISTANCE: usize = 3;
                            let method_names =
                                methods.iter().map(ToString::to_string).collect::<Vec<_>>();
                            let suggested_method = fuzzy_search_limited(
                                name.as_ref(),
                                method_names.as_slice(),
                                Some(SUGGEST_METHOD_MAX_DISTANCE),
                            );
                            suggested_method.map(|m| format!("did you mean `{m}`?"))
                        }
                        let hint = suggest_method(self, &EXTENSION_STYLES.methods);
                        convert_expr_error_to_parse_error::<Build>(
                            ToASTError::new(
                                ToASTErrorKind::UnknownMethod {
                                    id: self.clone(),
                                    hint,
                                },
                                loc.into_maybe_loc(),
                            )
                            .into(),
                            loc,
                        )
                    }
                }
            }
        }
    }
}

/// Return the single argument in `args` iterator, or return a wrong arity error
/// if the iterator has 0 elements or more than 1 element.
fn extract_single_argument<T>(
    args: impl ExactSizeIterator<Item = T>,
    fn_name: &'static str,
    loc: Option<&Loc>,
) -> Result<T> {
    args.exactly_one().map_err(|args| {
        ParseErrors::singleton(ToASTError::new(
            ToASTErrorKind::wrong_arity(fn_name, 1, args.len()),
            loc.into_maybe_loc(),
        ))
    })
}

/// Return a wrong arity error if the iterator has any elements.
fn require_zero_arguments<T>(
    args: &impl ExactSizeIterator<Item = T>,
    fn_name: &'static str,
    loc: Option<&Loc>,
) -> Result<()> {
    match args.len() {
        0 => Ok(()),
        n => Err(ParseErrors::singleton(ToASTError::new(
            ToASTErrorKind::wrong_arity(fn_name, 0, n),
            loc.into_maybe_loc(),
        ))),
    }
}

#[derive(Debug)]
enum PrincipalOrResource {
    Principal(PrincipalConstraint),
    Resource(ResourceConstraint),
}

#[derive(Debug, Clone, Copy)]
enum TolerantAstSetting {
    NotTolerant,
    #[cfg(feature = "tolerant-ast")]
    Tolerant,
}

impl Node<Option<cst::VariableDef>> {
    fn to_principal_constraint(
        &self,
        tolerant_setting: TolerantAstSetting,
    ) -> Result<PrincipalConstraint> {
        match self.to_principal_or_resource_constraint(ast::Var::Principal, tolerant_setting)? {
            PrincipalOrResource::Principal(p) => Ok(p),
            PrincipalOrResource::Resource(_) => Err(self
                .to_ast_err(ToASTErrorKind::IncorrectVariable {
                    expected: ast::Var::Principal,
                    got: ast::Var::Resource,
                })
                .into()),
        }
    }

    fn to_resource_constraint(
        &self,
        tolerant_setting: TolerantAstSetting,
    ) -> Result<ResourceConstraint> {
        match self.to_principal_or_resource_constraint(ast::Var::Resource, tolerant_setting)? {
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
        tolerant_ast: TolerantAstSetting,
    ) -> Result<PrincipalOrResource> {
        let vardef = self.try_as_inner()?;
        let var = vardef.variable.to_var()?;

        if let Some(unused_typename) = vardef.unused_type_name.as_ref() {
            unused_typename.to_type_constraint::<ast::ExprBuilder<()>>()?;
        }

        let c = if let Some((op, rel_expr)) = &vardef.ineq {
            // special check for the syntax `_ in _ is _`
            if op == &cst::RelOp::In {
                if let Ok(expr) = rel_expr.to_expr::<ast::ExprBuilder<()>>() {
                    if matches!(expr.expr_kind(), ast::ExprKind::Is { .. }) {
                        return Err(self.to_ast_err(ToASTErrorKind::InvertedIsIn).into());
                    }
                }
            }
            let eref = match tolerant_ast {
                TolerantAstSetting::NotTolerant => rel_expr.to_ref_or_slot(var)?,
                #[cfg(feature = "tolerant-ast")]
                TolerantAstSetting::Tolerant => rel_expr.to_ref_or_slot_tolerant_ast(var)?,
            };
            match (op, &vardef.entity_type) {
                (cst::RelOp::Eq, None) => Ok(PrincipalOrResourceConstraint::Eq(eref)),
                (cst::RelOp::Eq, Some(_)) => Err(self.to_ast_err(ToASTErrorKind::IsWithEq)),
                (cst::RelOp::In, None) => Ok(PrincipalOrResourceConstraint::In(eref)),
                (cst::RelOp::In, Some(entity_type)) => {
                    match entity_type
                        .to_expr_or_special::<ast::ExprBuilder<()>>()?
                        .into_entity_type()
                    {
                        Ok(et) => Ok(PrincipalOrResourceConstraint::IsIn(Arc::new(et), eref)),
                        Err(eos) => Err(eos.to_ast_err(ToASTErrorKind::InvalidIsType {
                            lhs: var.to_string(),
                            rhs: eos
                                .loc()
                                .map(|loc| loc.snippet().unwrap_or(INVALID_SNIPPET))
                                .unwrap_or(INVALID_SNIPPET)
                                .to_string(),
                        })),
                    }
                }
                (cst::RelOp::InvalidSingleEq, _) => {
                    Err(self.to_ast_err(ToASTErrorKind::InvalidSingleEq))
                }
                (op, _) => Err(self.to_ast_err(ToASTErrorKind::InvalidScopeOperator(*op))),
            }
        } else if let Some(entity_type) = &vardef.entity_type {
            match entity_type
                .to_expr_or_special::<ast::ExprBuilder<()>>()?
                .into_entity_type()
            {
                Ok(et) => Ok(PrincipalOrResourceConstraint::Is(Arc::new(et))),
                Err(eos) => Err(eos.to_ast_err(ToASTErrorKind::InvalidIsType {
                    lhs: var.to_string(),
                    rhs: eos
                        .loc()
                        .map(|loc| loc.snippet().unwrap_or(INVALID_SNIPPET))
                        .unwrap_or(INVALID_SNIPPET)
                        .to_string(),
                })),
            }
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

    fn to_action_constraint(
        &self,
        tolerant_setting: TolerantAstSetting,
    ) -> Result<ast::ActionConstraint> {
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
            typename.to_type_constraint::<ast::ExprBuilder<()>>()?;
        }

        if vardef.entity_type.is_some() {
            return Err(self.to_ast_err(ToASTErrorKind::IsInActionScope).into());
        }

        if let Some((op, rel_expr)) = &vardef.ineq {
            let action_constraint = match op {
                cst::RelOp::In => {
                    // special check for the syntax `_ in _ is _`
                    if let Ok(expr) = rel_expr.to_expr::<ast::ExprBuilder<()>>() {
                        if matches!(expr.expr_kind(), ast::ExprKind::Is { .. }) {
                            return Err(self.to_ast_err(ToASTErrorKind::IsInActionScope).into());
                        }
                    }
                    let one_or_multiple_refs = match tolerant_setting {
                        TolerantAstSetting::NotTolerant => rel_expr.to_refs(ast::Var::Action)?,
                        #[cfg(feature = "tolerant-ast")]
                        TolerantAstSetting::Tolerant => {
                            rel_expr.to_refs_tolerant_ast(ast::Var::Action)?
                        }
                    };
                    match one_or_multiple_refs {
                        OneOrMultipleRefs::Single(single_ref) => {
                            Ok(ActionConstraint::is_in([single_ref]))
                        }
                        OneOrMultipleRefs::Multiple(refs) => Ok(ActionConstraint::is_in(refs)),
                    }
                }
                cst::RelOp::Eq => {
                    let single_ref = match tolerant_setting {
                        TolerantAstSetting::NotTolerant => rel_expr.to_ref(ast::Var::Action)?,
                        #[cfg(feature = "tolerant-ast")]
                        TolerantAstSetting::Tolerant => {
                            rel_expr.to_ref_tolerant_ast(ast::Var::Action)?
                        }
                    };
                    Ok(ActionConstraint::is_eq(single_ref))
                }
                cst::RelOp::InvalidSingleEq => {
                    Err(self.to_ast_err(ToASTErrorKind::InvalidSingleEq))
                }
                op => Err(self.to_ast_err(ToASTErrorKind::InvalidActionScopeOperator(*op))),
            }?;

            match tolerant_setting {
                TolerantAstSetting::NotTolerant => action_constraint
                    .contains_only_action_types()
                    .map_err(|non_action_euids| {
                        rel_expr
                            .to_ast_err(parse_errors::InvalidActionType {
                                euids: non_action_euids,
                            })
                            .into()
                    }),
                #[cfg(feature = "tolerant-ast")]
                TolerantAstSetting::Tolerant => {
                    let action_constraint_res = action_constraint.contains_only_action_types();
                    // With 'tolerant-ast' feature enabled, we store invalid action constraints as an ErrorConstraint
                    Ok(action_constraint_res.unwrap_or(ActionConstraint::ErrorConstraint))
                }
            }
        } else {
            Ok(ActionConstraint::Any)
        }
    }
}

impl Node<Option<cst::Cond>> {
    /// to expr. Also returns, for informational purposes, a `bool` which is
    /// `true` if the cond is a `when` clause, `false` if it is an `unless`
    /// clause. (The returned `expr` is already adjusted for this, the `bool` is
    /// for information only.)
    fn to_expr<Build: ExprBuilder>(&self) -> Result<(Build::Expr, bool)> {
        let cond = self.try_as_inner()?;
        let is_when = cond.cond.to_cond_is_when()?;

        let maybe_expr = match &cond.expr {
            Some(expr) => expr.to_expr::<Build>(),
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
                convert_expr_error_to_parse_error::<Build>(
                    self.to_ast_err(ToASTErrorKind::EmptyClause(Some(ident)))
                        .into(),
                    self.loc.as_loc_ref(),
                )
            }
        };

        maybe_expr.map(|e| {
            if is_when {
                (e, true)
            } else {
                (
                    Build::new()
                        .with_maybe_source_loc(self.loc.as_loc_ref())
                        .not(e),
                    false,
                )
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

#[cfg(feature = "tolerant-ast")]
fn build_ast_error_node_if_possible<Build: ExprBuilder>(
    error: ParseErrors,
    loc: Option<&Loc>,
) -> Result<Build::Expr> {
    let res = Build::new().with_maybe_source_loc(loc).error(error.clone());
    match res {
        Ok(r) => Ok(r),
        Err(_) => Err(error),
    }
}

/// Since ExprBuilder ErrorType can be Infallible or ParseErrors, if we get an error from building the node pass the ParseErrors along
#[cfg_attr(not(feature = "tolerant-ast"), allow(unused_variables))]
fn convert_expr_error_to_parse_error<Build: ExprBuilder>(
    error: ParseErrors,
    loc: Option<&Loc>,
) -> Result<Build::Expr> {
    #[cfg(feature = "tolerant-ast")]
    return build_ast_error_node_if_possible::<Build>(error, loc);
    #[allow(unreachable_code)]
    Err(error)
}

/// Result type of conversion when we expect an Expr, Var, Name, or String.
///
/// During conversion it is useful to keep track of expression that may be used
/// as function names, record names, or record attributes. This prevents parsing these
/// terms to a general Expr expression and then immediately unwrapping them.
#[derive(Debug)]
pub(crate) enum ExprOrSpecial<'a, Expr> {
    /// Any expression except a variable, name, string literal, or boolean literal
    Expr { expr: Expr, loc: MaybeLoc },
    /// Variables, which act as expressions or names
    Var { var: ast::Var, loc: MaybeLoc },
    /// Name that isn't an expr and couldn't be converted to var
    Name { name: ast::Name, loc: MaybeLoc },
    /// String literal, not yet unescaped
    /// Must be processed with to_unescaped_string or to_pattern before inclusion in the AST
    StrLit { lit: &'a SmolStr, loc: MaybeLoc },
    /// A boolean literal
    BoolLit { val: bool, loc: MaybeLoc },
}

impl<Expr> ExprOrSpecial<'_, Expr>
where
    Expr: std::fmt::Display,
{
    fn loc(&self) -> Option<&Loc> {
        match self {
            Self::Expr { loc, .. } => loc.as_loc_ref(),
            Self::Var { loc, .. } => loc.as_loc_ref(),
            Self::Name { loc, .. } => loc.as_loc_ref(),
            Self::StrLit { loc, .. } => loc.as_loc_ref(),
            Self::BoolLit { loc, .. } => loc.as_loc_ref(),
        }
    }

    fn to_ast_err(&self, kind: impl Into<ToASTErrorKind>) -> ToASTError {
        ToASTError::new(kind.into(), self.loc().into_maybe_loc())
    }

    fn into_expr<Build: ExprBuilder<Expr = Expr>>(self) -> Result<Expr> {
        match self {
            Self::Expr { expr, .. } => Ok(expr),
            Self::Var { var, loc } => Ok(Build::new()
                .with_maybe_source_loc(loc.as_loc_ref())
                .var(var)),
            Self::Name { name, loc } => convert_expr_error_to_parse_error::<Build>(
                ToASTError::new(
                    ToASTErrorKind::ArbitraryVariable(name.to_string().into()),
                    loc.clone(),
                )
                .into(),
                loc.as_loc_ref(),
            ),
            Self::StrLit { lit, loc } => {
                match to_unescaped_string(lit) {
                    Ok(s) => Ok(Build::new().with_maybe_source_loc(loc.as_loc_ref()).val(s)),
                    Err(escape_errs) => Err(ParseErrors::new_from_nonempty(escape_errs.map(|e| {
                        ToASTError::new(ToASTErrorKind::Unescape(e), loc.clone()).into()
                    }))),
                }
            }
            Self::BoolLit { val, loc } => Ok(Build::new()
                .with_maybe_source_loc(loc.as_loc_ref())
                .val(val)),
        }
    }

    /// Variables, names (with no prefixes), and string literals can all be used as record attributes
    pub(crate) fn into_valid_attr(self) -> Result<SmolStr> {
        match self {
            Self::Var { var, .. } => Ok(construct_string_from_var(var)),
            Self::Name { name, loc } => name.into_valid_attr(loc),
            Self::StrLit { lit, loc } => to_unescaped_string(lit).map_err(|escape_errs| {
                ParseErrors::new_from_nonempty(
                    escape_errs
                        .map(|e| ToASTError::new(ToASTErrorKind::Unescape(e), loc.clone()).into()),
                )
            }),
            Self::Expr { expr, loc } => Err(ToASTError::new(
                ToASTErrorKind::InvalidAttribute(expr.to_string().into()),
                loc,
            )
            .into()),
            Self::BoolLit { val, loc } => Err(ToASTError::new(
                ToASTErrorKind::ReservedIdentifier(if val {
                    cst::Ident::True
                } else {
                    cst::Ident::False
                }),
                loc,
            )
            .into()),
        }
    }

    pub(crate) fn into_pattern(self) -> Result<Vec<PatternElem>> {
        match &self {
            Self::StrLit { lit, .. } => to_pattern(lit).map_err(|escape_errs| {
                ParseErrors::new_from_nonempty(
                    escape_errs.map(|e| self.to_ast_err(ToASTErrorKind::Unescape(e)).into()),
                )
            }),
            Self::Var { var, .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidPattern(var.to_string()))
                .into()),
            Self::Name { name, .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidPattern(name.to_string()))
                .into()),
            Self::Expr { expr, .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidPattern(expr.to_string()))
                .into()),
            Self::BoolLit { val, .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidPattern(val.to_string()))
                .into()),
        }
    }
    /// to string literal
    fn into_string_literal(self) -> Result<SmolStr> {
        match &self {
            Self::StrLit { lit, .. } => to_unescaped_string(lit).map_err(|escape_errs| {
                ParseErrors::new_from_nonempty(
                    escape_errs.map(|e| self.to_ast_err(ToASTErrorKind::Unescape(e)).into()),
                )
            }),
            Self::Var { var, .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidString(var.to_string()))
                .into()),
            Self::Name { name, .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidString(name.to_string()))
                .into()),
            Self::Expr { expr, .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidString(expr.to_string()))
                .into()),
            Self::BoolLit { val, .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidString(val.to_string()))
                .into()),
        }
    }

    /// Returns `Err` if `self` is not an `ast::EntityType`. The `Err` will give you the `self` reference back
    fn into_entity_type(self) -> std::result::Result<ast::EntityType, Self> {
        self.into_name().map(ast::EntityType::from)
    }

    /// Returns `Err` if `self` is not an `ast::Name`. The `Err` will give you the `self` reference back
    fn into_name(self) -> std::result::Result<ast::Name, Self> {
        match self {
            Self::Var { var, .. } => Ok(ast::Name::unqualified_name(var.into())),
            Self::Name { name, .. } => Ok(name),
            _ => Err(self),
        }
    }
}

impl Node<Option<cst::Expr>> {
    /// convert `cst::Expr` to `ast::Expr`
    pub fn to_expr<Build: ExprBuilder>(&self) -> Result<Build::Expr> {
        self.to_expr_or_special::<Build>()?.into_expr::<Build>()
    }
    pub(crate) fn to_expr_or_special<Build: ExprBuilder>(
        &self,
    ) -> Result<ExprOrSpecial<'_, Build::Expr>> {
        let expr_opt = self.try_as_inner()?;

        let expr = match expr_opt {
            cst::Expr::Expr(expr_impl) => expr_impl,
            #[cfg(feature = "tolerant-ast")]
            cst::Expr::ErrorExpr => {
                let e = ToASTError::new(ToASTErrorKind::CSTErrorNode, self.loc.clone());
                return Ok(ExprOrSpecial::Expr {
                    expr: convert_expr_error_to_parse_error::<Build>(
                        e.into(),
                        self.loc.as_loc_ref(),
                    )?,
                    loc: self.loc.clone(),
                });
            }
        };

        match &*expr.expr {
            cst::ExprData::Or(or) => or.to_expr_or_special::<Build>(),
            cst::ExprData::If(i, t, e) => {
                let maybe_guard = i.to_expr::<Build>();
                let maybe_then = t.to_expr::<Build>();
                let maybe_else = e.to_expr::<Build>();

                let (i, t, e) = flatten_tuple_3(maybe_guard, maybe_then, maybe_else)?;
                Ok(ExprOrSpecial::Expr {
                    expr: Build::new()
                        .with_maybe_source_loc(self.loc.as_loc_ref())
                        .ite(i, t, e),
                    loc: self.loc.clone(),
                })
            }
        }
    }
}

impl Node<Option<cst::Or>> {
    fn to_expr_or_special<Build: ExprBuilder>(&self) -> Result<ExprOrSpecial<'_, Build::Expr>> {
        let or = self.try_as_inner()?;

        let maybe_first = or.initial.to_expr_or_special::<Build>();
        let maybe_rest = ParseErrors::transpose(or.extended.iter().map(|i| i.to_expr::<Build>()));

        let (first, rest) = flatten_tuple_2(maybe_first, maybe_rest)?;
        if rest.is_empty() {
            // This case is required so the "special" expression variants are
            // not converted into a plain `ExprOrSpecial::Expr`.
            Ok(first)
        } else {
            first.into_expr::<Build>().map(|first| ExprOrSpecial::Expr {
                expr: Build::new()
                    .with_maybe_source_loc(self.loc.as_loc_ref())
                    .or_nary(first, rest),
                loc: self.loc.clone(),
            })
        }
    }
}

impl Node<Option<cst::And>> {
    pub(crate) fn to_expr<Build: ExprBuilder>(&self) -> Result<Build::Expr> {
        self.to_expr_or_special::<Build>()?.into_expr::<Build>()
    }
    fn to_expr_or_special<Build: ExprBuilder>(&self) -> Result<ExprOrSpecial<'_, Build::Expr>> {
        let and = self.try_as_inner()?;

        let maybe_first = and.initial.to_expr_or_special::<Build>();
        let maybe_rest = ParseErrors::transpose(and.extended.iter().map(|i| i.to_expr::<Build>()));

        let (first, rest) = flatten_tuple_2(maybe_first, maybe_rest)?;
        if rest.is_empty() {
            // This case is required so the "special" expression variants are
            // not converted into a plain `ExprOrSpecial::Expr`.
            Ok(first)
        } else {
            first.into_expr::<Build>().map(|first| ExprOrSpecial::Expr {
                expr: Build::new()
                    .with_maybe_source_loc(self.loc.as_loc_ref())
                    .and_nary(first, rest),
                loc: self.loc.clone(),
            })
        }
    }
}

impl Node<Option<cst::Relation>> {
    fn to_expr<Build: ExprBuilder>(&self) -> Result<Build::Expr> {
        self.to_expr_or_special::<Build>()?.into_expr::<Build>()
    }
    fn to_expr_or_special<Build: ExprBuilder>(&self) -> Result<ExprOrSpecial<'_, Build::Expr>> {
        let rel = self.try_as_inner()?;

        match rel {
            cst::Relation::Common { initial, extended } => {
                let maybe_first = initial.to_expr_or_special::<Build>();
                let maybe_rest = ParseErrors::transpose(
                    extended
                        .iter()
                        .map(|(op, i)| i.to_expr::<Build>().map(|e| (op, e))),
                );
                let maybe_extra_elmts = if extended.len() > 1 {
                    Err(self.to_ast_err(ToASTErrorKind::AmbiguousOperators).into())
                } else {
                    Ok(())
                };
                let (first, rest, _) = flatten_tuple_3(maybe_first, maybe_rest, maybe_extra_elmts)?;
                let mut rest = rest.into_iter();
                let second = rest.next();
                match second {
                    None => Ok(first),
                    Some((&op, second)) => first.into_expr::<Build>().and_then(|first| {
                        Ok(ExprOrSpecial::Expr {
                            expr: construct_expr_rel::<Build>(first, op, second, self.loc.clone())?,
                            loc: self.loc.clone(),
                        })
                    }),
                }
            }
            cst::Relation::Has { target, field } => {
                let maybe_target = target.to_expr::<Build>();
                let maybe_field = Ok(match field.to_has_rhs::<Build>()? {
                    Either::Left(s) => nonempty![s],
                    Either::Right(ids) => ids.map(|id| id.into_smolstr()),
                });
                let (target, field) = flatten_tuple_2(maybe_target, maybe_field)?;
                Ok(ExprOrSpecial::Expr {
                    expr: construct_exprs_extended_has::<Build>(
                        target,
                        &field,
                        self.loc.as_loc_ref(),
                    ),
                    loc: self.loc.clone(),
                })
            }
            cst::Relation::Like { target, pattern } => {
                let maybe_target = target.to_expr::<Build>();
                let maybe_pattern = pattern.to_expr_or_special::<Build>()?.into_pattern();
                let (target, pattern) = flatten_tuple_2(maybe_target, maybe_pattern)?;
                Ok(ExprOrSpecial::Expr {
                    expr: Build::new()
                        .with_maybe_source_loc(self.loc.as_loc_ref())
                        .like(target, pattern.into()),
                    loc: self.loc.clone(),
                })
            }
            cst::Relation::IsIn {
                target,
                entity_type,
                in_entity,
            } => {
                let maybe_target = target.to_expr::<Build>();
                let maybe_entity_type = entity_type
                    .to_expr_or_special::<Build>()?
                    .into_entity_type()
                    .map_err(|eos| {
                        eos.to_ast_err(ToASTErrorKind::InvalidIsType {
                            lhs: maybe_target
                                .as_ref()
                                .map(|expr| expr.to_string())
                                .unwrap_or_else(|_| "..".to_string()),
                            rhs: eos
                                .loc()
                                .map(|loc| loc.snippet().unwrap_or(INVALID_SNIPPET))
                                .unwrap_or(INVALID_SNIPPET)
                                .to_string(),
                        })
                        .into()
                    });
                let (t, n) = flatten_tuple_2(maybe_target, maybe_entity_type)?;
                match in_entity {
                    Some(in_entity) => {
                        let in_expr = in_entity.to_expr::<Build>()?;
                        Ok(ExprOrSpecial::Expr {
                            expr: Build::new()
                                .with_maybe_source_loc(self.loc.as_loc_ref())
                                .is_in_entity_type(t, n, in_expr),
                            loc: self.loc.clone(),
                        })
                    }
                    None => Ok(ExprOrSpecial::Expr {
                        expr: Build::new()
                            .with_maybe_source_loc(self.loc.as_loc_ref())
                            .is_entity_type(t, n),
                        loc: self.loc.clone(),
                    }),
                }
            }
        }
    }
}

impl Node<Option<cst::Add>> {
    fn to_expr<Build: ExprBuilder>(&self) -> Result<Build::Expr> {
        self.to_expr_or_special::<Build>()?.into_expr::<Build>()
    }

    // Peel the grammar onion until we see valid RHS
    // This function is added to implement RFC 62 (extended `has` operator).
    // We could modify existing code instead of having this function. However,
    // the former requires adding a weird variant to `ExprOrSpecial` to
    // accommodate a sequence of identifiers as RHS, which greatly complicates
    // the conversion from CSTs to `ExprOrSpecial`. Hence, this function is
    // added to directly tackle the CST to AST conversion for the has operator,
    // This design choice should be noninvasive to existing CST to AST logic,
    // despite producing deadcode.
    pub(crate) fn to_has_rhs<Build: ExprBuilder>(
        &self,
    ) -> Result<Either<SmolStr, NonEmpty<UnreservedId>>> {
        let inner @ cst::Add { initial, extended } = self.try_as_inner()?;
        let err = |loc| {
            ToASTError::new(ToASTErrorKind::InvalidHasRHS(inner.to_string().into()), loc).into()
        };
        let construct_attrs =
            |first, rest: &[Node<Option<cst::MemAccess>>]| -> Result<NonEmpty<UnreservedId>> {
                let mut acc = nonempty![first];
                rest.iter().try_for_each(|ma_node| {
                    let ma = ma_node.try_as_inner()?;
                    match ma {
                        cst::MemAccess::Field(id) => {
                            acc.push(id.to_unreserved_ident()?);
                            Ok(())
                        }
                        _ => Err(err(ma_node.loc.clone())),
                    }
                })?;
                Ok(acc)
            };
        if !extended.is_empty() {
            return Err(err(self.loc.clone()));
        }
        let cst::Mult { initial, extended } = initial.try_as_inner()?;
        if !extended.is_empty() {
            return Err(err(self.loc.clone()));
        }
        if let cst::Unary {
            op: None,
            item: item_node,
        } = initial.try_as_inner()?
        {
            let cst::Member { item, access } = item_node.try_as_inner()?;
            // Among successful conversion from `Primary` to `ExprOrSpecial`,
            // an `Ident` or `Str` becomes `ExprOrSpecial::StrLit`,
            // `ExprOrSpecial::Var`, and `ExprOrSpecial::Name`. Other
            // syntactical variants become `ExprOrSpecial::Expr`.
            match item.try_as_inner()? {
                cst::Primary::EList(_)
                | cst::Primary::Expr(_)
                | cst::Primary::RInits(_)
                | cst::Primary::Ref(_)
                | cst::Primary::Slot(_) => Err(err(item.loc.clone())),
                cst::Primary::Literal(_) | cst::Primary::Name(_) => {
                    let item = item.to_expr_or_special::<Build>()?;
                    match (item, access.as_slice()) {
                        (ExprOrSpecial::StrLit { lit, loc }, []) => Ok(Either::Left(
                            to_unescaped_string(lit).map_err(|escape_errs| {
                                ParseErrors::new_from_nonempty(escape_errs.map(|e| {
                                    ToASTError::new(ToASTErrorKind::Unescape(e), loc.clone()).into()
                                }))
                            })?,
                        )),
                        (ExprOrSpecial::Var { var, .. }, rest) => {
                            // PANIC SAFETY: any variable should be a valid identifier
                            #[allow(clippy::unwrap_used)]
                            let first = construct_string_from_var(var).parse().unwrap();
                            Ok(Either::Right(construct_attrs(first, rest)?))
                        }
                        (ExprOrSpecial::Name { name, loc }, rest) => {
                            if name.is_unqualified() {
                                let first = name.basename();

                                Ok(Either::Right(construct_attrs(first, rest)?))
                            } else {
                                Err(ToASTError::new(
                                    ToASTErrorKind::PathAsAttribute(inner.to_string()),
                                    loc,
                                )
                                .into())
                            }
                        }
                        // Attempt to return a precise error message for RHS like `true.<...>` and `false.<...>`
                        (ExprOrSpecial::BoolLit { val, loc }, _) => Err(ToASTError::new(
                            ToASTErrorKind::ReservedIdentifier(if val {
                                cst::Ident::True
                            } else {
                                cst::Ident::False
                            }),
                            loc,
                        )
                        .into()),
                        (ExprOrSpecial::Expr { loc, .. }, _) => Err(err(loc)),
                        _ => Err(err(self.loc.clone())),
                    }
                }
            }
        } else {
            Err(err(self.loc.clone()))
        }
    }

    pub(crate) fn to_expr_or_special<Build: ExprBuilder>(
        &self,
    ) -> Result<ExprOrSpecial<'_, Build::Expr>> {
        let add = self.try_as_inner()?;

        let maybe_first = add.initial.to_expr_or_special::<Build>();
        let maybe_rest = ParseErrors::transpose(
            add.extended
                .iter()
                .map(|&(op, ref i)| i.to_expr::<Build>().map(|e| (op, e))),
        );
        let (first, rest) = flatten_tuple_2(maybe_first, maybe_rest)?;
        if !rest.is_empty() {
            // in this case, `first` must be an expr, we should check for errors there as well
            let first = first.into_expr::<Build>()?;
            Ok(ExprOrSpecial::Expr {
                expr: Build::new()
                    .with_maybe_source_loc(self.loc.as_loc_ref())
                    .add_nary(first, rest),
                loc: self.loc.clone(),
            })
        } else {
            Ok(first)
        }
    }
}

impl Node<Option<cst::Mult>> {
    fn to_expr<Build: ExprBuilder>(&self) -> Result<Build::Expr> {
        self.to_expr_or_special::<Build>()?.into_expr::<Build>()
    }
    fn to_expr_or_special<Build: ExprBuilder>(&self) -> Result<ExprOrSpecial<'_, Build::Expr>> {
        let mult = self.try_as_inner()?;

        let maybe_first = mult.initial.to_expr_or_special::<Build>();
        let maybe_rest = ParseErrors::transpose(mult.extended.iter().map(|&(op, ref i)| {
            i.to_expr::<Build>().and_then(|e| match op {
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
            let first = first.into_expr::<Build>()?;
            Ok(ExprOrSpecial::Expr {
                expr: Build::new()
                    .with_maybe_source_loc(self.loc.as_loc_ref())
                    .mul_nary(first, rest),
                loc: self.loc.clone(),
            })
        } else {
            Ok(first)
        }
    }
}

impl Node<Option<cst::Unary>> {
    fn to_expr<Build: ExprBuilder>(&self) -> Result<Build::Expr> {
        self.to_expr_or_special::<Build>()?.into_expr::<Build>()
    }
    fn to_expr_or_special<Build: ExprBuilder>(&self) -> Result<ExprOrSpecial<'_, Build::Expr>> {
        let unary = self.try_as_inner()?;

        match unary.op {
            None => unary.item.to_expr_or_special::<Build>(),
            Some(cst::NegOp::Bang(n)) => {
                (0..n).fold(unary.item.to_expr_or_special::<Build>(), |inner, _| {
                    inner
                        .and_then(|e| e.into_expr::<Build>())
                        .map(|expr| ExprOrSpecial::Expr {
                            expr: Build::new()
                                .with_maybe_source_loc(self.loc.as_loc_ref())
                                .not(expr),
                            loc: self.loc.clone(),
                        })
                })
            }
            Some(cst::NegOp::Dash(0)) => unary.item.to_expr_or_special::<Build>(),
            Some(cst::NegOp::Dash(c)) => {
                // Test if there is a negative numeric literal.
                // A negative numeric literal should match regex pattern
                // `-\d+` which is parsed into a `Unary(_, Member(Primary(Literal(Num(_))), []))`.
                // Given a successful match, the number of negation operations
                // decreases by one.
                let (last, rc) = if let Some(cst::Literal::Num(n)) = unary.item.to_lit() {
                    match n.cmp(&(i64::MAX as u64 + 1)) {
                        Ordering::Equal => (
                            Ok(Build::new()
                                .with_maybe_source_loc(unary.item.loc.as_loc_ref())
                                .val(i64::MIN)),
                            c - 1,
                        ),
                        Ordering::Less => (
                            Ok(Build::new()
                                .with_maybe_source_loc(unary.item.loc.as_loc_ref())
                                .val(-(*n as i64))),
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
                    (
                        unary
                            .item
                            .to_expr_or_special::<Build>()
                            .and_then(|i| i.into_expr::<Build>()),
                        c,
                    )
                };
                // Fold the expression into a series of negation operations.
                (0..rc)
                    .fold(last, |r, _| {
                        r.map(|e| {
                            Build::new()
                                .with_maybe_source_loc(self.loc.as_loc_ref())
                                .neg(e)
                        })
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
enum AstAccessor<Expr> {
    Field(ast::UnreservedId),
    Call(Vec<Expr>),
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

    /// Construct an attribute access or method call on an expression. This also
    /// handles function calls, but a function call of an arbitrary expression
    /// is always an error.
    ///
    /// The input `head` is an arbitrary expression, while `next` and `tail` are
    /// togther a non-empty list of accesses applied to that expression.
    ///
    /// Returns a tuple where the first element is the expression built for the
    /// `next` access applied to `head`, and the second element is the new tail of
    /// acessors. In most cases, `tail` is returned unmodified, but in the method
    /// call case we need to pull off the `Call` element containing the arguments.
    #[allow(clippy::type_complexity)]
    fn build_expr_accessor<'a, Build: ExprBuilder>(
        &self,
        head: Build::Expr,
        next: &mut AstAccessor<Build::Expr>,
        tail: &'a mut [AstAccessor<Build::Expr>],
    ) -> Result<(Build::Expr, &'a mut [AstAccessor<Build::Expr>])> {
        use AstAccessor::*;
        match (next, tail) {
            // trying to "call" an expression as a function like `(1 + 1)("foo")`. Always an error.
            (Call(_), _) => Err(self.to_ast_err(ToASTErrorKind::ExpressionCall).into()),

            // method call on arbitrary expression like `[].contains(1)`
            (Field(id), [Call(args), rest @ ..]) => {
                // move the expr and args out of the slice
                let args = std::mem::take(args);
                // move the id out of the slice as well, to avoid cloning the internal string
                let id = mem::replace(id, ast::UnreservedId::empty());
                Ok((
                    id.to_meth::<Build>(head, args, self.loc.as_loc_ref())?,
                    rest,
                ))
            }

            // field of arbitrary expr like `(principal.foo).bar`
            (Field(id), rest) => {
                let id = mem::replace(id, ast::UnreservedId::empty());
                Ok((
                    Build::new()
                        .with_maybe_source_loc(self.loc.as_loc_ref())
                        .get_attr(head, id.into_smolstr()),
                    rest,
                ))
            }

            // index into arbitrary expr like `(principal.foo)["bar"]`
            (Index(i), rest) => {
                let i = mem::take(i);
                Ok((
                    Build::new()
                        .with_maybe_source_loc(self.loc.as_loc_ref())
                        .get_attr(head, i),
                    rest,
                ))
            }
        }
    }

    fn to_expr_or_special<Build: ExprBuilder>(&self) -> Result<ExprOrSpecial<'_, Build::Expr>> {
        let mem = self.try_as_inner()?;

        let maybe_prim = mem.item.to_expr_or_special::<Build>();
        let maybe_accessors =
            ParseErrors::transpose(mem.access.iter().map(|a| a.to_access::<Build>()));

        // Return errors in case parsing failed for any element
        let (prim, mut accessors) = flatten_tuple_2(maybe_prim, maybe_accessors)?;

        let (mut head, mut tail) = {
            use AstAccessor::*;
            use ExprOrSpecial::*;
            match (prim, accessors.as_mut_slice()) {
                // no accessors, return head immediately.
                (prim, []) => return Ok(prim),

                // Any access on an arbitrary expression (or string or boolean
                // literal). We will handle the possibility of multiple chained
                // accesses on this expression in the loop at the end of this
                // function.
                (prim @ (Expr { .. } | StrLit { .. } | BoolLit { .. }), [next, rest @ ..]) => {
                    self.build_expr_accessor::<Build>(prim.into_expr::<Build>()?, next, rest)?
                }

                // function call
                (Name { name, .. }, [Call(args), rest @ ..]) => {
                    // move the vec out of the slice, we won't use the slice after
                    let args = std::mem::take(args);
                    (name.into_func::<Build>(args, self.loc.clone())?, rest)
                }
                // variable function call - error
                (Var { var, .. }, [Call(_), ..]) => {
                    return Err(self.to_ast_err(ToASTErrorKind::VariableCall(var)).into());
                }

                // method call on name - error
                (Name { name, .. }, [Field(f), Call(_), ..]) => {
                    return Err(self
                        .to_ast_err(ToASTErrorKind::NoMethods(name, f.clone()))
                        .into());
                }
                // method call on variable
                (Var { var, loc: var_loc }, [Field(id), Call(args), rest @ ..]) => {
                    let args = std::mem::take(args);
                    // move the id out of the slice as well, to avoid cloning the internal string
                    let id = mem::replace(id, ast::UnreservedId::empty());
                    (
                        id.to_meth::<Build>(
                            Build::new()
                                .with_maybe_source_loc(var_loc.as_loc_ref())
                                .var(var),
                            args,
                            self.loc.as_loc_ref(),
                        )?,
                        rest,
                    )
                }

                // attribute access on a variable
                (Var { var, loc: var_loc }, [Field(i), rest @ ..]) => {
                    let id = mem::replace(i, ast::UnreservedId::empty());
                    (
                        Build::new()
                            .with_maybe_source_loc(self.loc.as_loc_ref())
                            .get_attr(
                                Build::new()
                                    .with_maybe_source_loc(var_loc.as_loc_ref())
                                    .var(var),
                                id.into_smolstr(),
                            ),
                        rest,
                    )
                }
                // attribute access on an arbitrary name - error
                (Name { name, .. }, [Field(f), ..]) => {
                    return Err(self
                        .to_ast_err(ToASTErrorKind::InvalidAccess {
                            lhs: name,
                            field: f.clone().into_smolstr(),
                        })
                        .into());
                }
                // index style attribute access on an arbitrary name - error
                (Name { name, .. }, [Index(i), ..]) => {
                    return Err(self
                        .to_ast_err(ToASTErrorKind::InvalidIndex {
                            lhs: name,
                            field: i.clone(),
                        })
                        .into());
                }

                // index style attribute access on a variable
                (Var { var, loc: var_loc }, [Index(i), rest @ ..]) => {
                    let i = mem::take(i);
                    (
                        Build::new()
                            .with_maybe_source_loc(self.loc.as_loc_ref())
                            .get_attr(
                                Build::new()
                                    .with_maybe_source_loc(var_loc.as_loc_ref())
                                    .var(var),
                                i,
                            ),
                        rest,
                    )
                }
            }
        };

        // After processing the first element, we know that `head` is always an
        // expression, so we repeatedly apply `build_expr_access` on head
        // without need to consider the other cases until we've consumed the
        // list of accesses.
        while let [next, rest @ ..] = tail {
            (head, tail) = self.build_expr_accessor::<Build>(head, next, rest)?;
        }
        Ok(ExprOrSpecial::Expr {
            expr: head,
            loc: self.loc.clone(),
        })
    }
}

impl Node<Option<cst::MemAccess>> {
    fn to_access<Build: ExprBuilder>(&self) -> Result<AstAccessor<Build::Expr>> {
        let acc = self.try_as_inner()?;

        match acc {
            cst::MemAccess::Field(i) => {
                let maybe_ident = i.to_unreserved_ident();
                maybe_ident.map(AstAccessor::Field)
            }
            cst::MemAccess::Call(args) => {
                let maybe_args = ParseErrors::transpose(args.iter().map(|e| e.to_expr::<Build>()));
                maybe_args.map(AstAccessor::Call)
            }
            cst::MemAccess::Index(index) => {
                let maybe_index = index.to_expr_or_special::<Build>()?.into_string_literal();
                maybe_index.map(AstAccessor::Index)
            }
        }
    }
}

impl Node<Option<cst::Primary>> {
    pub(crate) fn to_expr<Build: ExprBuilder>(&self) -> Result<Build::Expr> {
        self.to_expr_or_special::<Build>()?.into_expr::<Build>()
    }
    fn to_expr_or_special<Build: ExprBuilder>(&self) -> Result<ExprOrSpecial<'_, Build::Expr>> {
        let prim = self.try_as_inner()?;

        match prim {
            cst::Primary::Literal(lit) => lit.to_expr_or_special::<Build>(),
            cst::Primary::Ref(r) => r.to_expr::<Build>().map(|expr| ExprOrSpecial::Expr {
                expr,
                loc: r.loc.clone(),
            }),
            cst::Primary::Slot(s) => {
                s.clone()
                    .into_expr::<Build>()
                    .map(|expr| ExprOrSpecial::Expr {
                        expr,
                        loc: s.loc.clone(),
                    })
            }
            #[allow(clippy::manual_map)]
            cst::Primary::Name(n) => {
                // ignore errors in the case where `n` isn't a var - we'll get them elsewhere
                if let Some(var) = n.maybe_to_var() {
                    Ok(ExprOrSpecial::Var {
                        var,
                        loc: self.loc.clone(),
                    })
                } else {
                    n.to_internal_name().and_then(|name| match name.try_into() {
                        Ok(name) => Ok(ExprOrSpecial::Name {
                            name,
                            loc: self.loc.clone(),
                        }),
                        Err(err) => Err(ParseErrors::singleton(err)),
                    })
                }
            }
            cst::Primary::Expr(e) => e.to_expr::<Build>().map(|expr| ExprOrSpecial::Expr {
                expr,
                loc: e.loc.clone(),
            }),
            cst::Primary::EList(es) => {
                let maybe_list = ParseErrors::transpose(es.iter().map(|e| e.to_expr::<Build>()));
                maybe_list.map(|list| ExprOrSpecial::Expr {
                    expr: Build::new()
                        .with_maybe_source_loc(self.loc.as_loc_ref())
                        .set(list),
                    loc: self.loc.clone(),
                })
            }
            cst::Primary::RInits(is) => {
                let rec = ParseErrors::transpose(is.iter().map(|i| i.to_init::<Build>()))?;
                let expr = Build::new()
                    .with_maybe_source_loc(self.loc.as_loc_ref())
                    .record(rec)
                    .map_err(|e| {
                        Into::<ParseErrors>::into(ToASTError::new(e.into(), self.loc.clone()))
                    })?;
                Ok(ExprOrSpecial::Expr {
                    expr,
                    loc: self.loc.clone(),
                })
            }
        }
    }

    /// convert `cst::Primary` representing a string literal to a `SmolStr`.
    pub fn to_string_literal<Build: ExprBuilder>(&self) -> Result<SmolStr> {
        let prim = self.try_as_inner()?;

        match prim {
            cst::Primary::Literal(lit) => lit.to_expr_or_special::<Build>()?.into_string_literal(),
            _ => Err(self
                .to_ast_err(ToASTErrorKind::InvalidString(prim.to_string()))
                .into()),
        }
    }
}

impl Node<Option<cst::Slot>> {
    fn into_expr<Build: ExprBuilder>(self) -> Result<Build::Expr> {
        match self.try_as_inner()?.try_into() {
            Ok(slot_id) => Ok(Build::new()
                .with_maybe_source_loc(self.loc.as_loc_ref())
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
    fn to_type_constraint<Build: ExprBuilder>(&self) -> Result<Build::Expr> {
        match self.as_inner() {
            Some(_) => Err(self.to_ast_err(ToASTErrorKind::TypeConstraints).into()),
            None => Ok(Build::new()
                .with_maybe_source_loc(self.loc.as_loc_ref())
                .val(true)),
        }
    }

    pub(crate) fn to_name(&self) -> Result<ast::Name> {
        self.to_internal_name()
            .and_then(|n| n.try_into().map_err(ParseErrors::singleton))
    }

    pub(crate) fn to_internal_name(&self) -> Result<ast::InternalName> {
        let name = self.try_as_inner()?;

        let maybe_path = ParseErrors::transpose(name.path.iter().map(|i| i.to_valid_ident()));
        let maybe_name = name.name.to_valid_ident();

        // computation and error generation is complete, so fail or construct
        let (name, path) = flatten_tuple_2(maybe_name, maybe_path)?;
        Ok(construct_name(path, name, self.loc.clone()))
    }

    // Errors from this function are ignored (because they are detected elsewhere)
    // so it's fine to return an `Option` instead of a `Result`.
    fn maybe_to_var(&self) -> Option<ast::Var> {
        let name = self.as_inner()?;
        let ident = if name.path.is_empty() {
            name.name.as_inner()
        } else {
            // The path should be empty for a variable
            None
        }?;

        match ident {
            cst::Ident::Principal => Some(ast::Var::Principal),
            cst::Ident::Action => Some(ast::Var::Action),
            cst::Ident::Resource => Some(ast::Var::Resource),
            cst::Ident::Context => Some(ast::Var::Context),
            _ => None,
        }
    }
}

/// If this [`ast::Name`] is a known extension function/method name or not
pub(crate) fn is_known_extension_func_name(name: &ast::Name) -> bool {
    EXTENSION_STYLES.functions.contains(name)
        || (name.0.path.is_empty() && EXTENSION_STYLES.methods.contains(&name.basename()))
}

/// If this [`SmolStr`] is a known extension function/method name or not. Works
/// with both qualified and unqualified `s`. (As of this writing, there are no
/// qualified extension function/method names, so qualified `s` always results
/// in `false`.)
pub(crate) fn is_known_extension_func_str(s: &SmolStr) -> bool {
    EXTENSION_STYLES.functions_and_methods_as_str.contains(s)
}

impl ast::Name {
    /// Convert the `Name` into a `String` attribute, which fails if it had any namespaces
    fn into_valid_attr(self, loc: MaybeLoc) -> Result<SmolStr> {
        if !self.0.path.is_empty() {
            Err(ToASTError::new(ToASTErrorKind::PathAsAttribute(self.to_string()), loc).into())
        } else {
            Ok(self.0.id.into_smolstr())
        }
    }

    fn into_func<Build: ExprBuilder>(
        self,
        args: Vec<Build::Expr>,
        loc: MaybeLoc,
    ) -> Result<Build::Expr> {
        // error on standard methods
        if self.0.path.is_empty() {
            let id = self.basename();
            if EXTENSION_STYLES.methods.contains(&id)
                || matches!(
                    id.as_ref(),
                    "contains" | "containsAll" | "containsAny" | "isEmpty" | "getTag" | "hasTag"
                )
            {
                return Err(ToASTError::new(
                    ToASTErrorKind::FunctionCallOnMethod(self.basename()),
                    loc,
                )
                .into());
            }
        }
        if EXTENSION_STYLES.functions.contains(&self) {
            Ok(Build::new()
                .with_maybe_source_loc(loc.as_loc_ref())
                .call_extension_fn(self, args))
        } else {
            fn suggest_function(name: &ast::Name, funs: &HashSet<&ast::Name>) -> Option<String> {
                const SUGGEST_FUNCTION_MAX_DISTANCE: usize = 3;
                let fnames = funs.iter().map(ToString::to_string).collect::<Vec<_>>();
                let suggested_function = fuzzy_search_limited(
                    &name.to_string(),
                    fnames.as_slice(),
                    Some(SUGGEST_FUNCTION_MAX_DISTANCE),
                );
                suggested_function.map(|f| format!("did you mean `{f}`?"))
            }
            let hint = suggest_function(&self, &EXTENSION_STYLES.functions);
            Err(ToASTError::new(ToASTErrorKind::UnknownFunction { id: self, hint }, loc).into())
        }
    }
}

impl Node<Option<cst::Ref>> {
    /// convert `cst::Ref` to `ast::EntityUID`
    pub fn to_ref(&self) -> Result<ast::EntityUID> {
        let refr = self.try_as_inner()?;

        match refr {
            cst::Ref::Uid { path, eid } => {
                let maybe_path = path.to_name().map(ast::EntityType::from);
                let maybe_eid = eid.as_valid_string().and_then(|s| {
                    to_unescaped_string(s).map_err(|escape_errs| {
                        ParseErrors::new_from_nonempty(
                            escape_errs
                                .map(|e| self.to_ast_err(ToASTErrorKind::Unescape(e)).into()),
                        )
                    })
                });

                let (p, e) = flatten_tuple_2(maybe_path, maybe_eid)?;
                Ok({
                    let loc = self.loc.clone();
                    ast::EntityUID::from_components(p, ast::Eid::new(e), loc)
                })
            }
            r @ cst::Ref::Ref { .. } => Err(self
                .to_ast_err(ToASTErrorKind::InvalidEntityLiteral(r.to_string()))
                .into()),
        }
    }
    fn to_expr<Build: ExprBuilder>(&self) -> Result<Build::Expr> {
        self.to_ref().map(|euid| {
            Build::new()
                .with_maybe_source_loc(self.loc.as_loc_ref())
                .val(euid)
        })
    }
}

impl Node<Option<cst::Literal>> {
    fn to_expr_or_special<Build: ExprBuilder>(&self) -> Result<ExprOrSpecial<'_, Build::Expr>> {
        let lit = self.try_as_inner()?;

        match lit {
            cst::Literal::True => Ok(ExprOrSpecial::BoolLit {
                val: true,
                loc: self.loc.clone(),
            }),
            cst::Literal::False => Ok(ExprOrSpecial::BoolLit {
                val: false,
                loc: self.loc.clone(),
            }),
            cst::Literal::Num(n) => match Integer::try_from(*n) {
                Ok(i) => Ok(ExprOrSpecial::Expr {
                    expr: Build::new()
                        .with_maybe_source_loc(self.loc.as_loc_ref())
                        .val(i),
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
    fn to_init<Build: ExprBuilder>(&self) -> Result<(SmolStr, Build::Expr)> {
        let lit = self.try_as_inner()?;

        let maybe_attr = lit.0.to_expr_or_special::<Build>()?.into_valid_attr();
        let maybe_value = lit.1.to_expr::<Build>();

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
    loc: Option<&Loc>,
) -> ast::Template {
    let construct_template = |non_scope_constraint| {
        ast::Template::new(
            id,
            loc.into_maybe_loc(),
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
        construct_template(
            ast::ExprBuilder::new()
                .with_maybe_source_loc(loc)
                .and_nary(first_expr, conds_iter),
        )
    } else {
        // use `true` to mark the absence of non-scope constraints
        construct_template(ast::ExprBuilder::new().with_maybe_source_loc(loc).val(true))
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
fn construct_name(path: Vec<ast::Id>, id: ast::Id, loc: MaybeLoc) -> ast::InternalName {
    ast::InternalName {
        id,
        path: Arc::new(path),
        loc,
    }
}

fn construct_expr_rel<Build: ExprBuilder>(
    f: Build::Expr,
    rel: cst::RelOp,
    s: Build::Expr,
    loc: MaybeLoc,
) -> Result<Build::Expr> {
    let builder = Build::new().with_maybe_source_loc(loc.as_loc_ref());
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

fn construct_exprs_extended_has<Build: ExprBuilder>(
    t: Build::Expr,
    attrs: &NonEmpty<SmolStr>,
    loc: Option<&Loc>,
) -> Build::Expr {
    let (first, rest) = attrs.split_first();
    let has_expr = Build::new()
        .with_maybe_source_loc(loc)
        .has_attr(t.clone(), first.to_owned());
    let get_expr = Build::new()
        .with_maybe_source_loc(loc)
        .get_attr(t, first.to_owned());
    // Foldl on the attribute list
    // It produces the following for `principal has contactInfo.address.zip`
    //     Expr.and
    //   (Expr.and
    //     (Expr.hasAttr (Expr.var .principal) "contactInfo")
    //     (Expr.hasAttr
    //       (Expr.getAttr (Expr.var .principal) "contactInfo")
    //       "address"))
    //   (Expr.hasAttr
    //     (Expr.getAttr
    //       (Expr.getAttr (Expr.var .principal) "contactInfo")
    //       "address")
    //     "zip")
    // This is sound. However, the evaluator has to recur multiple times to the
    // left-most node to evaluate the existence of the first attribute. The
    // desugared expression should be the following to avoid the issue above,
    // Expr.and
    //   Expr.hasAttr (Expr.var .principal) "contactInfo"
    //   (Expr.and
    //      (Expr.hasAttr (Expr.getAttr (Expr.var .principal) "contactInfo")"address")
    //      (Expr.hasAttr ..., "zip"))
    rest.iter()
        .fold((has_expr, get_expr), |(has_expr, get_expr), attr| {
            (
                Build::new().with_maybe_source_loc(loc).and(
                    has_expr,
                    Build::new()
                        .with_maybe_source_loc(loc)
                        .has_attr(get_expr.clone(), attr.to_owned()),
                ),
                Build::new()
                    .with_maybe_source_loc(loc)
                    .get_attr(get_expr, attr.to_owned()),
            )
        })
        .0
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
// PANIC SAFETY: Unit Test Code
#[allow(clippy::indexing_slicing)]
#[allow(clippy::cognitive_complexity)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ast::{EntityUID, Expr},
        parser::{err::ParseErrors, test_utils::*, *},
        test_utils::*,
    };
    use ast::{InternalName, ReservedNameError};
    use cool_asserts::assert_matches;

    #[track_caller]
    fn assert_parse_expr_succeeds(text: &str) -> Expr {
        text_to_cst::parse_expr(text)
            .expect("failed parser")
            .to_expr::<ast::ExprBuilder<()>>()
            .unwrap_or_else(|errs| {
                panic!("failed conversion to AST:\n{:?}", miette::Report::new(errs))
            })
    }

    #[track_caller]
    fn assert_parse_expr_fails(text: &str) -> ParseErrors {
        let result = text_to_cst::parse_expr(text)
            .expect("failed parser")
            .to_expr::<ast::ExprBuilder<()>>();
        match result {
            Ok(expr) => {
                panic!("conversion to AST should have failed, but succeeded with:\n{expr}")
            }
            Err(errs) => errs,
        }
    }

    #[track_caller]
    fn assert_parse_policy_succeeds(text: &str) -> ast::StaticPolicy {
        text_to_cst::parse_policy(text)
            .expect("failed parser")
            .to_policy(ast::PolicyID::from_string("id"))
            .unwrap_or_else(|errs| {
                panic!("failed conversion to AST:\n{:?}", miette::Report::new(errs))
            })
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
        expect_n_errors(src, &errs, 4);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("invalid variable: a")
                .help("the valid Cedar variables are `principal`, `action`, `resource`, and `context`; did you mean to enclose `a` in quotes to make a string?")
                .exactly_one_underline("a")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("invalid variable: b")
                .help("the valid Cedar variables are `principal`, `action`, `resource`, and `context`; did you mean to enclose `b` in quotes to make a string?")
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
                "this identifier is reserved and cannot be used: true",
            )
            .exactly_one_underline("true")
            .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: false",
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
        expect_n_errors(src, &errs, 2);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: if",
            )
            .exactly_one_underline("if: true")
            .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: if",
            )
            .exactly_one_underline("if")
            .build(),
        );
    }

    #[test]
    fn reserved_idents3() {
        let src = r#"
            if {where: true}.like || {has:false}.in then {"like":false}["in"] else {then:true}.else
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 5);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: has",
            )
            .exactly_one_underline("has")
            .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: like",
            )
            .exactly_one_underline("like")
            .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: in",
            )
            .exactly_one_underline("in")
            .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: then",
            )
            .exactly_one_underline("then")
            .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "this identifier is reserved and cannot be used: else",
            )
            .exactly_one_underline("else")
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
            &ExpectedErrorMessageBuilder::error("invalid variable: w")
                .help("the valid Cedar variables are `principal`, `action`, `resource`, and `context`; did you mean to enclose `w` in quotes to make a string?")
                .exactly_one_underline("w")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("invalid variable: u")
                .help("the valid Cedar variables are `principal`, `action`, `resource`, and `context`; did you mean to enclose `u` in quotes to make a string?")
                .exactly_one_underline("u")
                .build(),
        );
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("invalid policy condition: advice")
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
    fn single_annotation() {
        // common use-case
        let policy = assert_parse_policy_succeeds(
            r#"
            @anno("good annotation")permit(principal,action,resource);
        "#,
        );
        assert_matches!(
            policy.annotation(&ast::AnyId::new_unchecked("anno")),
            Some(annotation) => assert_eq!(annotation.as_ref(), "good annotation")
        );
    }

    #[test]
    fn duplicate_annotations_error() {
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
    }

    #[test]
    fn multiple_policys_and_annotations_ok() {
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
            Some(annotation) => assert_eq!(annotation.as_ref(), "first")
        );
        assert_matches!(
            policyset
                .get(&ast::PolicyID::from_string("policy1"))
                .expect("should be a policy")
                .annotation(&ast::AnyId::new_unchecked("anno2")),
            Some(annotation) => assert_eq!(annotation.as_ref(), "second")
        );
        assert_matches!(
            policyset
                .get(&ast::PolicyID::from_string("policy2"))
                .expect("should be a policy")
                .annotation(&ast::AnyId::new_unchecked("anno3a")),
            Some(annotation) => assert_eq!(annotation.as_ref(), "third-a")
        );
        assert_matches!(
            policyset
                .get(&ast::PolicyID::from_string("policy2"))
                .expect("should be a policy")
                .annotation(&ast::AnyId::new_unchecked("anno3b")),
            Some(annotation) => assert_eq!(annotation.as_ref(), "third-b")
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
    }

    #[test]
    fn reserved_word_annotations_ok() {
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
            Some(annotation) => assert_eq!(annotation.as_ref(), "this is the annotation for `if`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("then")),
            Some(annotation) => assert_eq!(annotation.as_ref(), "this is the annotation for `then`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("else")),
            Some(annotation) => assert_eq!(annotation.as_ref(), "this is the annotation for `else`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("true")),
            Some(annotation) => assert_eq!(annotation.as_ref(), "this is the annotation for `true`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("false")),
            Some(annotation) => assert_eq!(annotation.as_ref(), "this is the annotation for `false`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("in")),
            Some(annotation) => assert_eq!(annotation.as_ref(), "this is the annotation for `in`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("is")),
            Some(annotation) => assert_eq!(annotation.as_ref(), "this is the annotation for `is`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("like")),
            Some(annotation) => assert_eq!(annotation.as_ref(), "this is the annotation for `like`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("has")),
            Some(annotation) => assert_eq!(annotation.as_ref(), "this is the annotation for `has`")
        );
        assert_matches!(
            policy0.annotation(&ast::AnyId::new_unchecked("principal")),
            Some(annotation) => assert_eq!(annotation.as_ref(), "this is the annotation for `principal`")
        );
    }

    #[test]
    fn single_annotation_without_value() {
        let policy = assert_parse_policy_succeeds(r#"@anno permit(principal,action,resource);"#);
        assert_matches!(
            policy.annotation(&ast::AnyId::new_unchecked("anno")),
            Some(annotation) => assert_eq!(annotation.as_ref(), ""),
        );
    }

    #[test]
    fn duplicate_annotations_without_value() {
        let src = "@anno @anno permit(principal,action,resource);";
        let errs = assert_parse_policy_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("duplicate annotation: @anno")
                .exactly_one_underline("@anno")
                .build(),
        );
    }

    #[test]
    fn multiple_annotation_without_value() {
        let policy =
            assert_parse_policy_succeeds(r#"@foo @bar permit(principal,action,resource);"#);
        assert_matches!(
            policy.annotation(&ast::AnyId::new_unchecked("foo")),
            Some(annotation) => assert_eq!(annotation.as_ref(), ""),
        );
        assert_matches!(
            policy.annotation(&ast::AnyId::new_unchecked("bar")),
            Some(annotation) => assert_eq!(annotation.as_ref(), ""),
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
                "expected single entity uid or template slot, found set of entity uids",
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
                "this policy has an extra element in the scope: context",
            )
            .help("policy scopes must contain a `principal`, `action`, and `resource` element in that order")
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
                .help("use a method-style call `e.contains(..)`")
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
            &ExpectedErrorMessageBuilder::error("invalid string literal: 0")
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
            &ExpectedErrorMessageBuilder::error("invalid string literal: (-1)")
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
            &ExpectedErrorMessageBuilder::error("invalid string literal: true")
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
            &ExpectedErrorMessageBuilder::error("invalid string literal: one")
                .exactly_one_underline("one")
                .build(),
        );
    }

    #[test]
    fn construct_invalid_get_var() {
        let src = r#"
            {"principal":1, "two":"two"}[principal]
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("invalid string literal: principal")
                .exactly_one_underline("principal")
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
            &ExpectedErrorMessageBuilder::error("invalid RHS of a `has` operation: 1")
                .help("valid RHS of a `has` operation is either a sequence of identifiers separated by `.` or a string literal")
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
    fn construct_like_var() {
        let src = r#"
            "principal" like principal
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "right hand side of a `like` expression must be a pattern literal, but got `principal`",
            )
            .exactly_one_underline("principal")
            .build(),
        );
    }

    #[test]
    fn construct_like_name() {
        let src = r#"
            "foo::bar::baz" like foo::bar
        "#;
        let errs = assert_parse_expr_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "right hand side of a `like` expression must be a pattern literal, but got `foo::bar`",
            )
            .exactly_one_underline("foo::bar")
            .build(),
        );
    }

    #[test]
    fn pattern_roundtrip() {
        let test_pattern = ast::Pattern::from(vec![
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
        ]);
        let e1 = ast::Expr::like(ast::Expr::val("hello"), test_pattern.clone());
        let s1 = format!("{e1}");
        // Char('\\') prints to r#"\\"# and Char('*') prints to r#"\*"#.
        assert_eq!(s1, r#""hello" like "hello\\0\*\\\*""#);
        let e2 = assert_parse_expr_succeeds(&s1);
        assert_matches!(e2.expr_kind(), ast::ExprKind::Like { pattern, .. } => {
            assert_eq!(pattern.get_elems(), test_pattern.get_elems());
        });
        let s2 = format!("{e2}");
        assert_eq!(s1, s2);
    }

    #[test]
    fn issue_wf_5046() {
        let policy = parse_policy(
            Some(ast::PolicyID::from_string("WF-5046")),
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
            &ExpectedErrorMessageBuilder::error("invalid RHS of a `has` operation: 1")
                .help("valid RHS of a `has` operation is either a sequence of identifiers separated by `.` or a string literal")
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
            &ExpectedErrorMessageBuilder::error("invalid string literal: age")
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
                .to_template(ast::PolicyID::from_string("i0"))
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
            assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
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
            r#""\q""#,
        );
        assert_invalid_escape(
            r#"permit(principal, action, resource) when { "\q".bar };"#,
            r#""\q""#,
        );
        assert_invalid_escape(
            r#"permit(principal, action, resource) when { "\q"["a"] };"#,
            r#""\q""#,
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
    fn expect_action_error(test: &str, msg: &str, underline: &str) {
        assert_matches!(parse_policyset(test), Err(es) => {
            expect_some_error_matches(
                test,
                &es,
                &ExpectedErrorMessageBuilder::error(msg)
                    .help("action entities must have type `Action`, optionally in a namespace")
                    .exactly_one_underline(underline)
                    .build(),
            );
        });
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
            "expected an entity uid with type `Action` but got `Foo::\"view\"`",
            "Foo::\"view\"",
        );
        expect_action_error(
            r#"permit(principal, action == Action::Foo::"view", resource);"#,
            "expected an entity uid with type `Action` but got `Action::Foo::\"view\"`",
            "Action::Foo::\"view\"",
        );
        expect_action_error(
            r#"permit(principal, action == Bar::Action::Foo::"view", resource);"#,
            "expected an entity uid with type `Action` but got `Bar::Action::Foo::\"view\"`",
            "Bar::Action::Foo::\"view\"",
        );
        expect_action_error(
            r#"permit(principal, action in Bar::Action::Foo::"view", resource);"#,
            "expected an entity uid with type `Action` but got `Bar::Action::Foo::\"view\"`",
            "Bar::Action::Foo::\"view\"",
        );
        expect_action_error(
            r#"permit(principal, action in [Bar::Action::Foo::"view"], resource);"#,
            "expected an entity uid with type `Action` but got `Bar::Action::Foo::\"view\"`",
            "[Bar::Action::Foo::\"view\"]",
        );
        expect_action_error(
            r#"permit(principal, action in [Bar::Action::Foo::"view", Action::"check"], resource);"#,
            "expected an entity uid with type `Action` but got `Bar::Action::Foo::\"view\"`",
            "[Bar::Action::Foo::\"view\", Action::\"check\"]",
        );
        expect_action_error(
            r#"permit(principal, action in [Bar::Action::Foo::"view", Foo::"delete", Action::"check"], resource);"#,
            "expected entity uids with type `Action` but got `Bar::Action::Foo::\"view\"` and `Foo::\"delete\"`",
            "[Bar::Action::Foo::\"view\", Foo::\"delete\", Action::\"check\"]",
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
                "use a method-style call `e.contains(..)`",
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
                    Expr::add(Expr::not(Expr::not(Expr::not(Expr::val(1)))), Expr::val(2)),
                    Expr::val(3),
                ),
            ),
            (
                "!!!!1 + 2 == 3",
                Expr::is_eq(
                    Expr::add(
                        Expr::not(Expr::not(Expr::not(Expr::not(Expr::val(1))))),
                        Expr::val(2),
                    ),
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
                "{e:?} and {expr:?} should have the same shape."
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
                "{e:?} and {expr:?} should have the same shape."
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
                "{e:?} and {expr:?} should have the same shape."
            );
        }
    }

    #[test]
    fn is_scope() {
        for (src, p, a, r) in [
            (
                r#"permit(principal is User, action, resource);"#,
                PrincipalConstraint::is_entity_type(Arc::new("User".parse().unwrap())),
                ActionConstraint::any(),
                ResourceConstraint::any(),
            ),
            (
                r#"permit(principal is principal, action, resource);"#,
                PrincipalConstraint::is_entity_type(Arc::new("principal".parse().unwrap())),
                ActionConstraint::any(),
                ResourceConstraint::any(),
            ),
            (
                r#"permit(principal is A::User, action, resource);"#,
                PrincipalConstraint::is_entity_type(Arc::new("A::User".parse().unwrap())),
                ActionConstraint::any(),
                ResourceConstraint::any(),
            ),
            (
                r#"permit(principal is User in Group::"thing", action, resource);"#,
                PrincipalConstraint::is_entity_type_in(
                    Arc::new("User".parse().unwrap()),
                    Arc::new(r#"Group::"thing""#.parse().unwrap()),
                ),
                ActionConstraint::any(),
                ResourceConstraint::any(),
            ),
            (
                r#"permit(principal is principal in Group::"thing", action, resource);"#,
                PrincipalConstraint::is_entity_type_in(
                    Arc::new("principal".parse().unwrap()),
                    Arc::new(r#"Group::"thing""#.parse().unwrap()),
                ),
                ActionConstraint::any(),
                ResourceConstraint::any(),
            ),
            (
                r#"permit(principal is A::User in Group::"thing", action, resource);"#,
                PrincipalConstraint::is_entity_type_in(
                    Arc::new("A::User".parse().unwrap()),
                    Arc::new(r#"Group::"thing""#.parse().unwrap()),
                ),
                ActionConstraint::any(),
                ResourceConstraint::any(),
            ),
            (
                r#"permit(principal is User in ?principal, action, resource);"#,
                PrincipalConstraint::is_entity_type_in_slot(Arc::new("User".parse().unwrap())),
                ActionConstraint::any(),
                ResourceConstraint::any(),
            ),
            (
                r#"permit(principal, action, resource is Folder);"#,
                PrincipalConstraint::any(),
                ActionConstraint::any(),
                ResourceConstraint::is_entity_type(Arc::new("Folder".parse().unwrap())),
            ),
            (
                r#"permit(principal, action, resource is Folder in Folder::"inner");"#,
                PrincipalConstraint::any(),
                ActionConstraint::any(),
                ResourceConstraint::is_entity_type_in(
                    Arc::new("Folder".parse().unwrap()),
                    Arc::new(r#"Folder::"inner""#.parse().unwrap()),
                ),
            ),
            (
                r#"permit(principal, action, resource is Folder in ?resource);"#,
                PrincipalConstraint::any(),
                ActionConstraint::any(),
                ResourceConstraint::is_entity_type_in_slot(Arc::new("Folder".parse().unwrap())),
            ),
        ] {
            let policy = parse_policy_or_template(None, src).unwrap();
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
                ExpectedErrorMessageBuilder::error("when `is` and `in` are used together, `is` must come first")
                    .help("try `_ is _ in _`")
                    .exactly_one_underline(r#"principal in Group::"friends" is User"#)
                    .build(),
            ),
            (
                r#"permit(principal, action in Group::"action_group" is Action, resource);"#,
                ExpectedErrorMessageBuilder::error("`is` cannot appear in the action scope")
                    .help("try moving `action is ..` into a `when` condition")
                    .exactly_one_underline(r#"action in Group::"action_group" is Action"#)
                    .build(),
            ),
            (
                r#"permit(principal, action, resource in Folder::"folder" is File);"#,
                ExpectedErrorMessageBuilder::error("when `is` and `in` are used together, `is` must come first")
                    .help("try `_ is _ in _`")
                    .exactly_one_underline(r#"resource in Folder::"folder" is File"#)
                    .build(),
            ),
            (
                r#"permit(principal is User == User::"Alice", action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    "`is` cannot be used together with `==`",
                ).help(
                    "try using `_ is _ in _`"
                ).exactly_one_underline("principal is User == User::\"Alice\"").build(),
            ),
            (
                r#"permit(principal, action, resource is Doc == Doc::"a");"#,
                ExpectedErrorMessageBuilder::error(
                    "`is` cannot be used together with `==`",
                ).help(
                    "try using `_ is _ in _`"
                ).exactly_one_underline("resource is Doc == Doc::\"a\"").build(),
            ),
            (
                r#"permit(principal is User::"alice", action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `User::"alice"`"#,
                ).help(r#"try using `==` to test for equality: `principal == User::"alice"`"#)
                .exactly_one_underline("User::\"alice\"").build(),
            ),
            (
                r#"permit(principal, action, resource is File::"f");"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `File::"f"`"#,
                ).help(r#"try using `==` to test for equality: `resource == File::"f"`"#)
                .exactly_one_underline("File::\"f\"").build(),
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
                )
                .help(
                    "try using `is` to test for an entity type or including an identifier string if you intended this name to be an entity uid"
                )
                .exactly_one_underline("User").build(),
            ),
            (
                r#"permit(principal is User::"Alice" in Group::"f", action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `User::"Alice"`"#,
                ).help(r#"try using `==` to test for equality: `principal == User::"Alice"`"#)
                .exactly_one_underline("User::\"Alice\"").build(),
            ),
            (
                r#"permit(principal, action, resource is File in File);"#,
                ExpectedErrorMessageBuilder::error(
                    "expected an entity uid or matching template slot, found name `File`",
                )
                .help(
                    "try using `is` to test for an entity type or including an identifier string if you intended this name to be an entity uid"
                )
                .exactly_one_underline("File").build(),
            ),
            (
                r#"permit(principal, action, resource is File::"file" in Folder::"folder");"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `File::"file"`"#,
                ).help(
                    r#"try using `==` to test for equality: `resource == File::"file"`"#
                ).exactly_one_underline("File::\"file\"").build(),
            ),
            (
                r#"permit(principal is 1, action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `1`"#,
                ).help(
                    "try using `==` to test for equality: `principal == 1`"
                ).exactly_one_underline("1").build(),
            ),
            (
                r#"permit(principal, action, resource is 1);"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `1`"#,
                ).help(
                    "try using `==` to test for equality: `resource == 1`"
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
                    "try using `==` to test for equality: `principal == ?principal`"
                ).exactly_one_underline("?principal").build(),
            ),
            (
                r#"permit(principal, action, resource is ?resource);"#,
                ExpectedErrorMessageBuilder::error(
                    "right hand side of an `is` expression must be an entity type name, but got `?resource`",
                ).help(
                    "try using `==` to test for equality: `resource == ?resource`"
                ).exactly_one_underline("?resource").build(),
            ),
            (
                r#"permit(principal, action, resource) when { principal is 1 };"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `1`"#,
                ).help(
                    "try using `==` to test for equality: `principal == 1`"
                ).exactly_one_underline("1").build(),
            ),
            (
                r#"permit(principal, action, resource) when { principal is User::"alice" in Group::"friends" };"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `User::"alice"`"#,
                ).help(
                    r#"try using `==` to test for equality: `principal == User::"alice"`"#
                ).exactly_one_underline("User::\"alice\"").build(),
            ),
            (
                r#"permit(principal, action, resource) when { principal is ! User::"alice" in Group::"friends" };"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `! User::"alice"`"#,
                ).help(
                    r#"try using `==` to test for equality: `principal == ! User::"alice"`"#
                ).exactly_one_underline("! User::\"alice\"").build(),
            ),
            (
                r#"permit(principal, action, resource) when { principal is User::"alice" + User::"alice" in Group::"friends" };"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `User::"alice" + User::"alice"`"#,
                ).help(
                    r#"try using `==` to test for equality: `principal == User::"alice" + User::"alice"`"#
                ).exactly_one_underline("User::\"alice\" + User::\"alice\"").build(),
            ),
            (
                r#"permit(principal, action, resource) when { principal is User in User::"alice" in Group::"friends" };"#,
                ExpectedErrorMessageBuilder::error("unexpected token `in`")
                    .exactly_one_underline_with_label("in", "expected `&&`, `||`, or `}`")
                    .build(),
            ),
            (
                r#"permit(principal, action, resource) when { principal is User == User::"alice" in Group::"friends" };"#,
                ExpectedErrorMessageBuilder::error("unexpected token `==`")
                    .exactly_one_underline_with_label("==", "expected `&&`, `||`, `}`, or `in`")
                    .build(),
            ),
            (
                // `_ in _ is _` in the policy condition is an error in the text->CST parser
                r#"permit(principal, action, resource) when { principal in Group::"friends" is User };"#,
                ExpectedErrorMessageBuilder::error("unexpected token `is`")
                    .exactly_one_underline_with_label(r#"is"#, "expected `!=`, `&&`, `<`, `<=`, `==`, `>`, `>=`, `||`, `}`, or `in`")
                    .build(),
            ),
            (
                r#"permit(principal is "User", action, resource);"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `"User"`"#,
                ).help(
                    "try removing the quotes: `principal is User`"
                ).exactly_one_underline("\"User\"").build(),
            ),
            (
                r#"permit(principal, action, resource) when { principal is "User" };"#,
                ExpectedErrorMessageBuilder::error(
                    r#"right hand side of an `is` expression must be an entity type name, but got `"User"`"#,
                ).help(
                    "try removing the quotes: `principal is User`"
                ).exactly_one_underline("\"User\"").build(),
            ),
        ];
        for (p_src, expected) in invalid_is_policies {
            assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
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
                    .help("use a method-style call `e.contains(..)`")
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
                r#"[].isEmpty([])"#,
                ExpectedErrorMessageBuilder::error(
                    "call to `isEmpty` requires exactly 0 arguments, but got 1 argument",
                )
                .exactly_one_underline("[].isEmpty([])")
                .build(),
            ),
            (
                r#""1.1.1.1".ip()"#,
                ExpectedErrorMessageBuilder::error("`ip` is a function, not a method")
                    .help("use a function-style call `ip(..)`")
                    .exactly_one_underline(r#""1.1.1.1".ip()"#)
                    .build(),
            ),
            (
                r#"greaterThan(1, 2)"#,
                ExpectedErrorMessageBuilder::error("`greaterThan` is a method, not a function")
                    .help("use a method-style call `e.greaterThan(..)`")
                    .exactly_one_underline("greaterThan(1, 2)")
                    .build(),
            ),
            (
                "[].bar()",
                ExpectedErrorMessageBuilder::error("`bar` is not a valid method")
                    .exactly_one_underline("[].bar()")
                    .build(),
            ),
            (
                "principal.addr.isipv4()",
                ExpectedErrorMessageBuilder::error("`isipv4` is not a valid method")
                    .exactly_one_underline("principal.addr.isipv4()")
                    .help("did you mean `isIpv4`?")
                    .build(),
            ),
            (
                "bar([])",
                ExpectedErrorMessageBuilder::error("`bar` is not a valid function")
                    .exactly_one_underline("bar([])")
                    .help("did you mean `ip`?")
                    .build(),
            ),
            (
                r#"Ip("1.1.1.1/24")"#,
                ExpectedErrorMessageBuilder::error("`Ip` is not a valid function")
                    .exactly_one_underline(r#"Ip("1.1.1.1/24")"#)
                    .help("did you mean `ip`?")
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
                    "function calls must be of the form `<name>(arg1, arg2, ...)`",
                )
                .exactly_one_underline("(1+1)()")
                .build(),
            ),
            (
                "foo.bar()",
                ExpectedErrorMessageBuilder::error(
                    "attempted to call `foo.bar(...)`, but `foo` does not have any methods",
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
                ExpectedErrorMessageBuilder::error("expected single entity uid, found template slot").exactly_one_underline("?action").build(),
            ),
            (
                r#"permit(principal, action in ?action, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid or set of entity uids, found template slot").exactly_one_underline("?action").build(),
            ),
            (
                r#"permit(principal, action == ?principal, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid, found template slot").exactly_one_underline("?principal").build(),
            ),
            (
                r#"permit(principal, action in ?principal, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid or set of entity uids, found template slot").exactly_one_underline("?principal").build(),
            ),
            (
                r#"permit(principal, action == ?resource, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid, found template slot").exactly_one_underline("?resource").build(),
            ),
            (
                r#"permit(principal, action in ?resource, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid or set of entity uids, found template slot").exactly_one_underline("?resource").build(),
            ),
            (
                r#"permit(principal, action in [?bar], resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid, found template slot").exactly_one_underline("?bar").build(),
            ),
        ];

        for (p_src, expected) in invalid_policies {
            assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
                expect_err(p_src, &miette::Report::new(e), &expected);
            });
            let forbid_src = format!("forbid{}", &p_src[6..]);
            assert_matches!(parse_policy_or_template(None, &forbid_src), Err(e) => {
                expect_err(forbid_src.as_str(), &miette::Report::new(e), &expected);
            });
        }
    }

    #[test]
    fn missing_scope_constraint() {
        let p_src = "permit();";
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(
                p_src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("this policy is missing the `principal` variable in the scope")
                    .exactly_one_underline("")
                    .help("policy scopes must contain a `principal`, `action`, and `resource` element in that order")
                    .build()
            );
        });
        let p_src = "permit(principal);";
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(
                p_src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("this policy is missing the `action` variable in the scope")
                    .exactly_one_underline("")
                    .help("policy scopes must contain a `principal`, `action`, and `resource` element in that order")
                    .build()
            );
        });
        let p_src = "permit(principal, action);";
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(
                p_src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("this policy is missing the `resource` variable in the scope")
                    .exactly_one_underline("")
                    .help("policy scopes must contain a `principal`, `action`, and `resource` element in that order")
                    .build()
            );
        });
    }

    #[test]
    fn invalid_scope_constraint() {
        let p_src = "permit(foo, action, resource);";
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found an invalid variable in the policy scope: foo",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("foo").build());
        });
        let p_src = "permit(foo::principal, action, resource);";
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(
                p_src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("unexpected token `::`")
                    .exactly_one_underline_with_label("::", "expected `!=`, `)`, `,`, `:`, `<`, `<=`, `==`, `>`, `>=`, `in`, or `is`")
                    .build()
            );
        });
        let p_src = "permit(resource, action, resource);";
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found the variable `resource` where the variable `principal` must be used",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("resource").build());
        });

        let p_src = "permit(principal, principal, resource);";
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found the variable `principal` where the variable `action` must be used",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("principal").build());
        });
        let p_src = "permit(principal, if, resource);";
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found an invalid variable in the policy scope: if",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("if").build());
        });

        let p_src = "permit(principal, action, like);";
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found an invalid variable in the policy scope: like",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("like").build());
        });
        let p_src = "permit(principal, action, principal);";
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found the variable `principal` where the variable `resource` must be used",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("principal").build());
        });
        let p_src = "permit(principal, action, action);";
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
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
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "invalid operator in the policy scope: >",
                ).help(
                "policy scope clauses can only use `==`, `in`, `is`, or `_ is _ in _`"
            ).exactly_one_underline("principal > User::\"alice\"").build());
        });
        let p_src = r#"permit(principal, action != Action::"view", resource);"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "invalid operator in the action scope: !=",
                ).help(
                "action scope clauses can only use `==` or `in`"
            ).exactly_one_underline("action != Action::\"view\"").build());
        });
        let p_src = r#"permit(principal, action, resource <= Folder::"things");"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "invalid operator in the policy scope: <=",
                ).help(
                "policy scope clauses can only use `==`, `in`, `is`, or `_ is _ in _`"
            ).exactly_one_underline("resource <= Folder::\"things\"").build());
        });
        let p_src = r#"permit(principal = User::"alice", action, resource);"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "'=' is not a valid operator in Cedar",
                ).help(
                "try using '==' instead",
            ).exactly_one_underline("principal = User::\"alice\"").build());
        });
        let p_src = r#"permit(principal, action = Action::"act", resource);"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "'=' is not a valid operator in Cedar",
                ).help(
                "try using '==' instead",
            ).exactly_one_underline("action = Action::\"act\"").build());
        });
        let p_src = r#"permit(principal, action, resource = Photo::"photo");"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "'=' is not a valid operator in Cedar",
                ).help(
                "try using '==' instead",
            ).exactly_one_underline("resource = Photo::\"photo\"").build());
        });
    }

    #[test]
    fn scope_action_eq_set() {
        let p_src = r#"permit(principal, action == [Action::"view", Action::"edit"], resource);"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("expected single entity uid, found set of entity uids").exactly_one_underline(r#"[Action::"view", Action::"edit"]"#).build());
        });
    }

    #[test]
    fn scope_compare_to_string() {
        let p_src = r#"permit(principal == "alice", action, resource);"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"expected an entity uid or matching template slot, found literal `"alice"`"#
            ).help(
                "try including the entity type if you intended this string to be an entity uid"
            ).exactly_one_underline(r#""alice""#).build());
        });
        let p_src = r#"permit(principal in "bob_friends", action, resource);"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"expected an entity uid or matching template slot, found literal `"bob_friends"`"#
            ).help(
                "try including the entity type if you intended this string to be an entity uid"
            ).exactly_one_underline(r#""bob_friends""#).build());
        });
        let p_src = r#"permit(principal, action, resource in "jane_photos");"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"expected an entity uid or matching template slot, found literal `"jane_photos"`"#
            ).help(
                "try including the entity type if you intended this string to be an entity uid"
            ).exactly_one_underline(r#""jane_photos""#).build());
        });
        let p_src = r#"permit(principal, action in ["view_actions"], resource);"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"expected an entity uid, found literal `"view_actions"`"#
            ).help(
                "try including the entity type if you intended this string to be an entity uid"
            ).exactly_one_underline(r#""view_actions""#).build());
        });
    }

    #[test]
    fn scope_compare_to_name() {
        let p_src = r#"permit(principal == User, action, resource);"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "expected an entity uid or matching template slot, found name `User`"
            ).help(
                    "try using `is` to test for an entity type or including an identifier string if you intended this name to be an entity uid"
            ).exactly_one_underline("User").build());
        });
        let p_src = r#"permit(principal in Group, action, resource);"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "expected an entity uid or matching template slot, found name `Group`"
            ).help(
                "try using `is` to test for an entity type or including an identifier string if you intended this name to be an entity uid"
            ).exactly_one_underline("Group").build());
        });
        let p_src = r#"permit(principal, action, resource in Album);"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "expected an entity uid or matching template slot, found name `Album`"
            ).help(
                "try using `is` to test for an entity type or including an identifier string if you intended this name to be an entity uid"
            ).exactly_one_underline("Album").build());
        });
        let p_src = r#"permit(principal, action == Action, resource);"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "expected an entity uid, found name `Action`"
            ).help(
                "try including an identifier string if you intended this name to be an entity uid"
            ).exactly_one_underline("Action").build());
        });
    }

    #[test]
    fn scope_and() {
        let p_src = r#"permit(principal == User::"alice" && principal in Group::"jane_friends", action, resource);"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "expected an entity uid or matching template slot, found a `&&` expression"
            ).help(
                "the policy scope can only contain one constraint per variable. Consider moving the second operand of this `&&` into a `when` condition",
            ).exactly_one_underline(r#"User::"alice" && principal in Group::"jane_friends""#).build());
        });
    }

    #[test]
    fn scope_or() {
        let p_src =
            r#"permit(principal == User::"alice" || principal == User::"bob", action, resource);"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "expected an entity uid or matching template slot, found a `||` expression"
            ).help(
                "the policy scope can only contain one constraint per variable. Consider moving the second operand of this `||` into a new policy",
            ).exactly_one_underline(r#"User::"alice" || principal == User::"bob""#).build());
        });
    }

    #[test]
    fn scope_action_in_set_set() {
        let p_src = r#"permit(principal, action in [[Action::"view"]], resource);"#;
        assert_matches!(parse_policy_or_template(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("expected single entity uid, found set of entity uids").exactly_one_underline(r#"[Action::"view"]"#).build());
        });
    }

    #[test]
    fn scope_unexpected_nested_sets() {
        let policy = r#"
            permit (
                principal == [[User::"alice"]],
                action,
                resource
            );
        "#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "expected single entity uid or template slot, found set of entity uids",
                ).exactly_one_underline(r#"[[User::"alice"]]"#).build());
            }
        );

        let policy = r#"
            permit (
                principal,
                action,
                resource == [[?resource]]
            );
        "#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "expected single entity uid or template slot, found set of entity uids",
                ).exactly_one_underline("[[?resource]]").build());
            }
        );

        let policy = r#"
            permit (
                principal,
                action in [[[Action::"act"]]],
                resource
            );
        "#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "expected single entity uid, found set of entity uids",
                ).exactly_one_underline(r#"[[Action::"act"]]"#).build());
            }
        );
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
        let src = "7 = 3";
        assert_matches!(parse_expr(src), Err(e) => {
            expect_err(src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("'=' is not a valid operator in Cedar").exactly_one_underline("7 = 3").help("try using '==' instead").build());
        });
    }

    #[test]
    fn over_unary() {
        let src = "!!!!!!false";
        assert_matches!(parse_expr(src), Err(e) => {
            expect_err(src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "too many occurrences of `!`",
                ).help(
                "cannot chain more the 4 applications of a unary operator"
            ).exactly_one_underline("!!!!!!false").build());
        });
        let src = "-------0";
        assert_matches!(parse_expr(src), Err(e) => {
            expect_err(src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "too many occurrences of `-`",
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
                    &format!("invalid variable: {name}"),
                ).help(
                    &format!("the valid Cedar variables are `principal`, `action`, `resource`, and `context`; did you mean to enclose `{name}` in quotes to make a string?"),
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
            assert_matches!(parse_policy_or_template(None, policy), Err(e) => {
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
                "this identifier is reserved and cannot be used: if"
            ).exactly_one_underline("if").build());
        })
    }

    #[test]
    fn reserved_ident_var() {
        #[track_caller]
        fn expect_reserved_ident(name: &str, reserved: &str) {
            assert_matches!(parse_expr(name), Err(e) => {
                expect_err(name, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                    &format!("this identifier is reserved and cannot be used: {reserved}"),
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

    #[test]
    fn reserved_namespace() {
        assert_matches!(parse_expr(r#"__cedar::"""#),
            Err(errs) if matches!(errs.as_ref().first(),
                ParseError::ToAST(to_ast_err) if matches!(to_ast_err.kind(),
                    ToASTErrorKind::ReservedNamespace(ReservedNameError(n)) if *n == "__cedar".parse::<InternalName>().unwrap())));
        assert_matches!(parse_expr(r#"__cedar::A::"""#),
            Err(errs) if matches!(errs.as_ref().first(),
                ParseError::ToAST(to_ast_err) if matches!(to_ast_err.kind(),
                    ToASTErrorKind::ReservedNamespace(ReservedNameError(n)) if *n == "__cedar::A".parse::<InternalName>().unwrap())));
        assert_matches!(parse_expr(r#"A::__cedar::B::"""#),
            Err(errs) if matches!(errs.as_ref().first(),
                ParseError::ToAST(to_ast_err) if matches!(to_ast_err.kind(),
                    ToASTErrorKind::ReservedNamespace(ReservedNameError(n)) if *n == "A::__cedar::B".parse::<InternalName>().unwrap())));
        assert_matches!(parse_expr(r#"[A::"", __cedar::Action::"action"]"#),
            Err(errs) if matches!(errs.as_ref().first(),
                ParseError::ToAST(to_ast_err) if matches!(to_ast_err.kind(),
                    ToASTErrorKind::ReservedNamespace(ReservedNameError(n)) if *n == "__cedar::Action".parse::<InternalName>().unwrap())));
        assert_matches!(parse_expr(r#"principal is __cedar::A"#),
            Err(errs) if matches!(errs.as_ref().first(),
                ParseError::ToAST(to_ast_err) if matches!(to_ast_err.kind(),
                    ToASTErrorKind::ReservedNamespace(ReservedNameError(n)) if *n == "__cedar::A".parse::<InternalName>().unwrap())));
        assert_matches!(parse_expr(r#"__cedar::decimal("0.0")"#),
            Err(errs) if matches!(errs.as_ref().first(),
                ParseError::ToAST(to_ast_err) if matches!(to_ast_err.kind(),
                    ToASTErrorKind::ReservedNamespace(ReservedNameError(n)) if *n == "__cedar::decimal".parse::<InternalName>().unwrap())));
        assert_matches!(parse_expr(r#"ip("").__cedar()"#),
            Err(errs) if matches!(errs.as_ref().first(),
                ParseError::ToAST(to_ast_err) if matches!(to_ast_err.kind(),
                    ToASTErrorKind::ReservedNamespace(ReservedNameError(n)) if *n == "__cedar".parse::<InternalName>().unwrap())));
        assert_matches!(parse_expr(r#"{__cedar: 0}"#),
            Err(errs) if matches!(errs.as_ref().first(),
                ParseError::ToAST(to_ast_err) if matches!(to_ast_err.kind(),
                    ToASTErrorKind::ReservedNamespace(ReservedNameError(n)) if *n == "__cedar".parse::<InternalName>().unwrap())));
        assert_matches!(parse_expr(r#"{a: 0}.__cedar"#),
            Err(errs) if matches!(errs.as_ref().first(),
                ParseError::ToAST(to_ast_err) if matches!(to_ast_err.kind(),
                    ToASTErrorKind::ReservedNamespace(ReservedNameError(n)) if *n == "__cedar".parse::<InternalName>().unwrap())));
        // We allow `__cedar` as an annotation identifier
        assert_matches!(
            parse_policy(
                None,
                r#"@__cedar("foo") permit(principal, action, resource);"#
            ),
            Ok(_)
        );
    }

    #[test]
    fn arbitrary_name_attr_access() {
        let src = "foo.attr";
        assert_matches!(parse_expr(src), Err(e) => {
            expect_err(src, &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("invalid member access `foo.attr`, `foo` has no fields or methods")
                    .exactly_one_underline("foo.attr")
                    .build()
            );
        });

        let src = r#"foo["attr"]"#;
        assert_matches!(parse_expr(src), Err(e) => {
            expect_err(src, &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"invalid indexing expression `foo["attr"]`, `foo` has no fields"#)
                    .exactly_one_underline(r#"foo["attr"]"#)
                    .build()
            );
        });

        let src = r#"foo["\n"]"#;
        assert_matches!(parse_expr(src), Err(e) => {
            expect_err(src, &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"invalid indexing expression `foo["\n"]`, `foo` has no fields"#)
                    .exactly_one_underline(r#"foo["\n"]"#)
                    .build()
            );
        });
    }

    #[test]
    fn extended_has() {
        assert_matches!(
            parse_policy(
                None,
                r#"
        permit(
  principal is User,
  action == Action::"preview",
  resource == Movie::"Blockbuster"
) when {
  principal has contactInfo.address.zip &&
  principal.contactInfo.address.zip == "90210"
};
        "#
            ),
            Ok(_)
        );

        assert_matches!(parse_expr(r#"context has a.b"#), Ok(e) => {
            assert!(e.eq_shape(&parse_expr(r#"(context has a) && (context.a has b)"#).unwrap()));
        });

        assert_matches!(parse_expr(r#"context has a.b.c"#), Ok(e) => {
            assert!(e.eq_shape(&parse_expr(r#"((context has a) && (context.a has b)) && (context.a.b has c)"#).unwrap()));
        });

        let policy = r#"permit(principal, action, resource) when {
            principal has a.if
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "this identifier is reserved and cannot be used: if",
                ).exactly_one_underline(r#"if"#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has if.a
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "this identifier is reserved and cannot be used: if",
                ).exactly_one_underline(r#"if"#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has true.if
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "this identifier is reserved and cannot be used: true",
                ).exactly_one_underline(r#"true"#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has a.__cedar
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "The name `__cedar` contains `__cedar`, which is reserved",
                ).exactly_one_underline(r#"__cedar"#).build());
            }
        );

        let help_msg = "valid RHS of a `has` operation is either a sequence of identifiers separated by `.` or a string literal";

        let policy = r#"permit(principal, action, resource) when {
            principal has 1 + 1
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "invalid RHS of a `has` operation: 1 + 1",
                ).help(help_msg).
                exactly_one_underline(r#"1 + 1"#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has a - 1
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "invalid RHS of a `has` operation: a - 1",
                ).help(help_msg).exactly_one_underline(r#"a - 1"#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has a*3 + 1
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "invalid RHS of a `has` operation: a * 3 + 1",
                ).help(help_msg).exactly_one_underline(r#"a*3 + 1"#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has 3*a
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "invalid RHS of a `has` operation: 3 * a",
                ).help(help_msg).exactly_one_underline(r#"3*a"#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has -a.b
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "invalid RHS of a `has` operation: -a.b",
                ).help(help_msg).exactly_one_underline(r#"-a.b"#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has !a.b
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "invalid RHS of a `has` operation: !a.b",
                ).help(help_msg).exactly_one_underline(r#"!a.b"#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has a::b.c
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "`a::b.c` cannot be used as an attribute as it contains a namespace",
                ).exactly_one_underline(r#"a::b"#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has A::""
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "invalid RHS of a `has` operation: A::\"\"",
                ).help(help_msg).exactly_one_underline(r#"A::"""#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has A::"".a
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "invalid RHS of a `has` operation: A::\"\".a",
                ).help(help_msg).exactly_one_underline(r#"A::"""#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has ?principal
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "invalid RHS of a `has` operation: ?principal",
                ).help(help_msg).exactly_one_underline(r#"?principal"#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has ?principal.a
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "invalid RHS of a `has` operation: ?principal.a",
                ).help(help_msg).exactly_one_underline(r#"?principal"#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has (b).a
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "invalid RHS of a `has` operation: (b).a",
                ).help(help_msg).exactly_one_underline(r#"(b)"#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has [b].a
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "invalid RHS of a `has` operation: [b].a",
                ).help(help_msg).exactly_one_underline(r#"[b]"#).build());
            }
        );
        let policy = r#"permit(principal, action, resource) when {
            principal has {b:1}.a
          };"#;
        assert_matches!(
            parse_policy(None, policy),
            Err(e) => {
                expect_n_errors(policy, &e, 1);
                expect_some_error_matches(policy, &e, &ExpectedErrorMessageBuilder::error(
                    "invalid RHS of a `has` operation: {b: 1}.a",
                ).help(help_msg).exactly_one_underline(r#"{b:1}"#).build());
            }
        );
    }

    #[cfg(feature = "tolerant-ast")]
    #[track_caller]
    fn assert_parse_policy_allows_errors(text: &str) -> ast::StaticPolicy {
        text_to_cst::parse_policy_tolerant(text)
            .expect("failed parser")
            .to_policy_tolerant(ast::PolicyID::from_string("id"))
            .unwrap_or_else(|errs| {
                panic!("failed conversion to AST:\n{:?}", miette::Report::new(errs))
            })
    }

    #[cfg(feature = "tolerant-ast")]
    #[track_caller]
    fn assert_parse_policy_allows_errors_fails(text: &str) -> ParseErrors {
        let result = text_to_cst::parse_policy_tolerant(text)
            .expect("failed parser")
            .to_policy_tolerant(ast::PolicyID::from_string("id"));
        match result {
            Ok(policy) => {
                panic!("conversion to AST should have failed, but succeeded with:\n{policy}")
            }
            Err(errs) => errs,
        }
    }

    // Test parsing AST that allows Error nodes
    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn parsing_with_errors_succeeds_with_empty_when() {
        let src = r#"
            permit(principal, action, resource) when {};
        "#;
        assert_parse_policy_allows_errors(src);
    }

    // Test parsing AST that allows Error nodes
    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn parsing_with_errors_succeeds_with_invalid_variable_in_when() {
        let src = r#"
            permit(principal, action, resource) when { pri };
        "#;
        assert_parse_policy_allows_errors(src);
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn parsing_with_errors_succeeds_with_invalid_method() {
        let src = r#"
            permit(principal, action, resource) when { ip(principal.ip).i() };
        "#;
        assert_parse_policy_allows_errors(src);
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn parsing_with_errors_succeeds_with_invalid_uid_resource_constraint() {
        let src = r#"
            permit (
                principal,
                action,
                resource in H
            )
            when { true };
        "#;
        assert_parse_policy_allows_errors(src);
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn parsing_with_errors_succeeds_with_invalid_uid_principal_constraint() {
        let src = r#"
            permit (
                principal in J,
                action,
                resource
            )
            when { true };
        "#;
        assert_parse_policy_allows_errors(src);
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn invalid_action_constraint_in_a_list() {
        let src = r#"
            permit (
                principal,
                action in [A],
                resource
            )
            when { true };
        "#;
        assert_parse_policy_allows_errors(src);
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn parsing_with_errors_succeeds_with_invalid_bracket_for_in() {
        let src = r#"
            permit (
                principal,
                action,
                resource in [
            )
            when { true };
        "#;
        assert_parse_policy_allows_errors(src);
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn parsing_with_errors_succeeds_with_missing_second_operand_eq_and_in() {
        // Test for == operator
        let src_eq_cases = [
            r#"permit(principal ==, action, resource);"#,
            r#"permit(principal, action ==, resource);"#,
            r#"permit(principal, action, resource ==);"#,
            r#"permit(principal ==, action ==, resource);"#,
            r#"permit(principal, action ==, resource ==);"#,
            r#"permit(principal ==, action, resource ==);"#,
            r#"permit(principal ==, action ==, resource ==);"#,
        ];

        for src in src_eq_cases.iter() {
            assert_parse_policy_allows_errors(src);
        }

        // Test for in operator
        let src_in_cases = [
            r#"permit(principal in, action, resource);"#,
            r#"permit(principal, action in, resource);"#,
            r#"permit(principal, action, resource in);"#,
            r#"permit(principal in, action in, resource);"#,
            r#"permit(principal, action in, resource in);"#,
            r#"permit(principal in, action, resource in);"#,
            r#"permit(principal in, action in, resource in);"#,
        ];

        for src in src_in_cases.iter() {
            assert_parse_policy_allows_errors(src);
        }

        // Cases with "is" and missing operands
        let src_in_cases = [
            r#"permit(principal is something in, action, resource);"#,
            r#"permit(principal, action, resource is something in);"#,
        ];
        for src in src_in_cases.iter() {
            assert_parse_policy_allows_errors(src);
        }
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn parsing_with_errors_succeeds_with_invalid_variable_in_when_missing_operand() {
        let src = r#"
            permit(principal, action, resource) when { principal == };
        "#;
        assert_parse_policy_allows_errors(src);

        let src = r#"
        permit(principal, action, resource) when { resource == };
        "#;
        assert_parse_policy_allows_errors(src);

        let src = r#"
        permit(principal, action, resource) when { action == };
        "#;
        assert_parse_policy_allows_errors(src);

        let src = r#"
        permit(principal, action, resource) when { principal == User::test && action == };
        "#;
        assert_parse_policy_allows_errors(src);

        let src = r#"
        permit(principal, action, resource) when { action == &&  principal == User::test};
        "#;
        assert_parse_policy_allows_errors(src);
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn parsing_with_errors_succeeds_with_missing_second_operand_is() {
        let src = r#"
            permit(principal is something in, action, resource);
        "#;
        assert_parse_policy_allows_errors(src);
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn show_policy1_errors_enabled() {
        let src = r#"
            permit(principal:p,action:a,resource:r)when{w}unless{u}advice{"doit"};
        "#;
        let errs = assert_parse_policy_allows_errors_fails(src);
        expect_n_errors(src, &errs, 4);
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
            &ExpectedErrorMessageBuilder::error("invalid policy condition: advice")
                .help("condition must be either `when` or `unless`")
                .exactly_one_underline("advice")
                .build(),
        );
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn show_policy2_errors_enabled() {
        let src = r#"
            permit(principal,action,resource)when{true};
        "#;
        assert_parse_policy_allows_errors(src);
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn show_policy3_errors_enabled() {
        let src = r#"
            permit(principal in User::"jane",action,resource);
        "#;
        assert_parse_policy_allows_errors(src);
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn show_policy4_errors_enabled() {
        let src = r#"
            forbid(principal in User::"jane",action,resource)unless{
                context.group != "friends"
            };
        "#;
        assert_parse_policy_allows_errors(src);
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn invalid_policy_errors_enabled() {
        let src = r#"
            permit(principal,;
        "#;
        assert_parse_policy_allows_errors(src);
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn invalid_policy_with_trailing_dot_errors_enabled() {
        let src = r#"
            permit(principal, action, resource) { principal. };
        "#;
        assert_parse_policy_allows_errors(src);
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn missing_entity_identifier_errors_enabled() {
        let src = r#"
            permit(principal, action == Action::, resource);
        "#;
        assert_parse_policy_allows_errors(src);
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn single_annotation_errors_enabled() {
        // common use-case
        let policy = assert_parse_policy_allows_errors(
            r#"
            @anno("good annotation")permit(principal,action,resource);
        "#,
        );
        assert_matches!(
            policy.annotation(&ast::AnyId::new_unchecked("anno")),
            Some(annotation) => assert_eq!(annotation.as_ref(), "good annotation")
        );
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn duplicate_annotations_error_errors_enabled() {
        // duplication is error
        let src = r#"
            @anno("good annotation")
            @anno2("good annotation")
            @anno("oops, duplicate")
            permit(principal,action,resource);
        "#;
        let errs = assert_parse_policy_allows_errors_fails(src);
        // annotation duplication (anno)
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("duplicate annotation: @anno")
                .exactly_one_underline("@anno(\"oops, duplicate\")")
                .build(),
        );
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn multiple_policys_with_unparsable_policy_ok() {
        // When we have a malformed policy, it should become an error node but the rest of the policies should parse
        let policyset = text_to_cst::parse_policies_tolerant(
            r#"
            // POLICY 1 
            @id("Photo.owner")
            permit (
            principal,
            action in
                [PhotoApp::Action::"viewPhoto",
                PhotoApp::Action::"editPhoto",
                PhotoApp::Action::"deletePhoto"],
            resource in PhotoApp::Application::"PhotoApp"
            )
            when { resource.owner == principal };

            // POLICY2 - unparsable
            @id("label_private")
            forbid (
            principal,
            acti

            // POLICY3 - unparsable because previous policy is missing a ";"
            @id("Photo.subjects")
            permit (
            principal,
            action == PhotoApp::Action::"viewPhoto",
            resource in PhotoApp::Application::"PhotoApp"
            )
            when { resource has subjects && resource.subjects.contains(principal) };

            // POLICY 4
            @id("PhotoJudge")
            permit (
            principal in PhotoApp::Role::"PhotoJudge",
            action == PhotoApp::Action::"viewPhoto",
            resource in PhotoApp::Application::"PhotoApp"
            )
            when { resource.labels.contains("contest") }
            when { context has judgingSession && context.judgingSession == true };
        "#,
        )
        .expect("should parse")
        .to_policyset_tolerant()
        .unwrap_or_else(|errs| panic!("failed convert to AST:\n{:?}", miette::Report::new(errs)));
        policyset
            .get(&ast::PolicyID::from_string("policy0"))
            .expect("should be a policy");
        policyset
            .get(&ast::PolicyID::from_string("policy1"))
            .expect("should be a policy");
        policyset
            .get(&ast::PolicyID::from_string("policy2"))
            .expect("should be a policy");
        assert!(policyset
            .get(&ast::PolicyID::from_string("policy3"))
            .is_none());
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn fail_scope1_tolerant_ast() {
        let src = r#"
            permit(
                principal in [User::"jane",Group::"friends"],
                action,
                resource
            );
        "#;
        let errs = assert_parse_policy_allows_errors_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error(
                "expected single entity uid or template slot, found set of entity uids",
            )
            .exactly_one_underline(r#"[User::"jane",Group::"friends"]"#)
            .build(),
        );
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn fail_scope2_tolerant_ast() {
        let src = r#"
            permit(
                principal in User::"jane",
                action == if true then Photo::"view" else Photo::"edit",
                resource
            );
        "#;
        let errs = assert_parse_policy_allows_errors_fails(src);
        expect_n_errors(src, &errs, 1);
        expect_some_error_matches(
            src,
            &errs,
            &ExpectedErrorMessageBuilder::error("expected an entity uid, found an `if` expression")
                .exactly_one_underline(r#"if true then Photo::"view" else Photo::"edit""#)
                .build(),
        );
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn invalid_slot_tolerant_ast() {
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
                ExpectedErrorMessageBuilder::error("expected single entity uid, found template slot").exactly_one_underline("?action").build(),
            ),
            (
                r#"permit(principal, action in ?action, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid or set of entity uids, found template slot").exactly_one_underline("?action").build(),
            ),
            (
                r#"permit(principal, action == ?principal, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid, found template slot").exactly_one_underline("?principal").build(),
            ),
            (
                r#"permit(principal, action in ?principal, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid or set of entity uids, found template slot").exactly_one_underline("?principal").build(),
            ),
            (
                r#"permit(principal, action == ?resource, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid, found template slot").exactly_one_underline("?resource").build(),
            ),
            (
                r#"permit(principal, action in ?resource, resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid or set of entity uids, found template slot").exactly_one_underline("?resource").build(),
            ),
            (
                r#"permit(principal, action in [?bar], resource);"#,
                ExpectedErrorMessageBuilder::error("expected single entity uid, found template slot").exactly_one_underline("?bar").build(),
            ),
        ];

        for (p_src, expected) in invalid_policies {
            assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
                expect_err(p_src, &miette::Report::new(e), &expected);
            });
            let forbid_src = format!("forbid{}", &p_src[6..]);
            assert_matches!(parse_policy_or_template_tolerant(None, &forbid_src), Err(e) => {
                expect_err(forbid_src.as_str(), &miette::Report::new(e), &expected);
            });
        }
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn missing_scope_constraint_tolerant_ast() {
        let p_src = "permit();";
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(
                p_src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("this policy is missing the `principal` variable in the scope")
                    .exactly_one_underline("")
                    .help("policy scopes must contain a `principal`, `action`, and `resource` element in that order")
                    .build()
            );
        });
        let p_src = "permit(principal);";
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(
                p_src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("this policy is missing the `action` variable in the scope")
                    .exactly_one_underline("")
                    .help("policy scopes must contain a `principal`, `action`, and `resource` element in that order")
                    .build()
            );
        });
        let p_src = "permit(principal, action);";
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(
                p_src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("this policy is missing the `resource` variable in the scope")
                    .exactly_one_underline("")
                    .help("policy scopes must contain a `principal`, `action`, and `resource` element in that order")
                    .build()
            );
        });
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn invalid_scope_constraint_tolerant() {
        let p_src = "permit(foo, action, resource);";
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found an invalid variable in the policy scope: foo",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("foo").build());
        });

        let p_src = "permit(resource, action, resource);";
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found the variable `resource` where the variable `principal` must be used",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("resource").build());
        });

        let p_src = "permit(principal, principal, resource);";
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found the variable `principal` where the variable `action` must be used",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("principal").build());
        });
        let p_src = "permit(principal, if, resource);";
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found an invalid variable in the policy scope: if",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("if").build());
        });

        let p_src = "permit(principal, action, like);";
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found an invalid variable in the policy scope: like",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("like").build());
        });
        let p_src = "permit(principal, action, principal);";
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found the variable `principal` where the variable `resource` must be used",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("principal").build());
        });
        let p_src = "permit(principal, action, action);";
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "found the variable `action` where the variable `resource` must be used",
                ).help(
                "policy scopes must contain a `principal`, `action`, and `resource` element in that order",
            ).exactly_one_underline("action").build());
        });
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn invalid_scope_operator_tolerant() {
        let p_src = r#"permit(principal > User::"alice", action, resource);"#;
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "invalid operator in the policy scope: >",
                ).help(
                "policy scope clauses can only use `==`, `in`, `is`, or `_ is _ in _`"
            ).exactly_one_underline("principal > User::\"alice\"").build());
        });
        let p_src = r#"permit(principal, action != Action::"view", resource);"#;
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "invalid operator in the action scope: !=",
                ).help(
                "action scope clauses can only use `==` or `in`"
            ).exactly_one_underline("action != Action::\"view\"").build());
        });
        let p_src = r#"permit(principal, action, resource <= Folder::"things");"#;
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "invalid operator in the policy scope: <=",
                ).help(
                "policy scope clauses can only use `==`, `in`, `is`, or `_ is _ in _`"
            ).exactly_one_underline("resource <= Folder::\"things\"").build());
        });
        let p_src = r#"permit(principal = User::"alice", action, resource);"#;
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "'=' is not a valid operator in Cedar",
                ).help(
                "try using '==' instead",
            ).exactly_one_underline("principal = User::\"alice\"").build());
        });
        let p_src = r#"permit(principal, action = Action::"act", resource);"#;
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "'=' is not a valid operator in Cedar",
                ).help(
                "try using '==' instead",
            ).exactly_one_underline("action = Action::\"act\"").build());
        });
        let p_src = r#"permit(principal, action, resource = Photo::"photo");"#;
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "'=' is not a valid operator in Cedar",
                ).help(
                "try using '==' instead",
            ).exactly_one_underline("resource = Photo::\"photo\"").build());
        });
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn scope_action_eq_set_tolerant() {
        let p_src = r#"permit(principal, action == [Action::"view", Action::"edit"], resource);"#;
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("expected single entity uid, found set of entity uids").exactly_one_underline(r#"[Action::"view", Action::"edit"]"#).build());
        });
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn scope_compare_to_string_tolerant() {
        let p_src = r#"permit(principal == "alice", action, resource);"#;
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"expected an entity uid or matching template slot, found literal `"alice"`"#
            ).help(
                "try including the entity type if you intended this string to be an entity uid"
            ).exactly_one_underline(r#""alice""#).build());
        });
        let p_src = r#"permit(principal in "bob_friends", action, resource);"#;
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"expected an entity uid or matching template slot, found literal `"bob_friends"`"#
            ).help(
                "try including the entity type if you intended this string to be an entity uid"
            ).exactly_one_underline(r#""bob_friends""#).build());
        });
        let p_src = r#"permit(principal, action, resource in "jane_photos");"#;
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"expected an entity uid or matching template slot, found literal `"jane_photos"`"#
            ).help(
                "try including the entity type if you intended this string to be an entity uid"
            ).exactly_one_underline(r#""jane_photos""#).build());
        });
        let p_src = r#"permit(principal, action in ["view_actions"], resource);"#;
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"expected an entity uid, found literal `"view_actions"`"#
            ).help(
                "try including the entity type if you intended this string to be an entity uid"
            ).exactly_one_underline(r#""view_actions""#).build());
        });
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn scope_and_tolerant() {
        let p_src = r#"permit(principal == User::"alice" && principal in Group::"jane_friends", action, resource);"#;
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "expected an entity uid or matching template slot, found a `&&` expression"
            ).help(
                "the policy scope can only contain one constraint per variable. Consider moving the second operand of this `&&` into a `when` condition",
            ).exactly_one_underline(r#"User::"alice" && principal in Group::"jane_friends""#).build());
        });
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn scope_or_tolerant() {
        let p_src =
            r#"permit(principal == User::"alice" || principal == User::"bob", action, resource);"#;
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                "expected an entity uid or matching template slot, found a `||` expression"
            ).help(
                "the policy scope can only contain one constraint per variable. Consider moving the second operand of this `||` into a new policy",
            ).exactly_one_underline(r#"User::"alice" || principal == User::"bob""#).build());
        });
    }

    #[cfg(feature = "tolerant-ast")]
    #[test]
    fn scope_action_in_set_set_tolerant() {
        let p_src = r#"permit(principal, action in [[Action::"view"]], resource);"#;
        assert_matches!(parse_policy_or_template_tolerant(None, p_src), Err(e) => {
            expect_err(p_src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error("expected single entity uid, found set of entity uids").exactly_one_underline(r#"[Action::"view"]"#).build());
        });
    }

    #[cfg(feature = "tolerant-ast")]
    fn parse_policy_or_template_tolerant(
        id: Option<ast::PolicyID>,
        text: &str,
    ) -> Result<ast::Template> {
        let id = id.unwrap_or_else(|| ast::PolicyID::from_string("policy0"));
        let cst = text_to_cst::parse_policy_tolerant(text)?;
        cst.to_template_tolerant(id)
    }
}
