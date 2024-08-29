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

use std::sync::Arc;

use super::Result;
use crate::{
    ast::{self, EntityReference, EntityUID},
    parser::{
        cst::{self, Literal},
        err::{self, ParseErrors, ToASTError, ToASTErrorKind},
        Loc, Node,
    },
};

/// Type level marker for parsing sets of entity uids or single uids
/// This presents having either a large level of code duplication
/// or runtime data.
/// This marker is (currently) only used for translating entity references
/// in the policy scope.
trait RefKind: Sized {
    fn err_str() -> &'static str;
    fn create_single_ref(e: EntityUID, loc: &Loc) -> Result<Self>;
    fn create_multiple_refs(loc: &Loc) -> Result<fn(Vec<EntityUID>) -> Self>;
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

    fn create_multiple_refs(loc: &Loc) -> Result<fn(Vec<EntityUID>) -> Self> {
        Err(ToASTError::new(
            ToASTErrorKind::wrong_entity_argument_one_expected(
                err::parse_errors::Ref::Single,
                err::parse_errors::Ref::Set,
            ),
            loc.clone(),
        )
        .into())
    }

    fn create_slot(loc: &Loc) -> Result<Self> {
        Err(ToASTError::new(
            ToASTErrorKind::wrong_entity_argument_one_expected(
                err::parse_errors::Ref::Single,
                err::parse_errors::Ref::Template,
            ),
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
        Ok(EntityReference::euid(Arc::new(e)))
    }

    fn create_multiple_refs(loc: &Loc) -> Result<fn(Vec<EntityUID>) -> Self> {
        Err(ToASTError::new(
            ToASTErrorKind::wrong_entity_argument_two_expected(
                err::parse_errors::Ref::Single,
                err::parse_errors::Ref::Template,
                err::parse_errors::Ref::Set,
            ),
            loc.clone(),
        )
        .into())
    }
}

/// Simple utility enum for parsing lists/individual entityuids
#[derive(Debug)]
pub enum OneOrMultipleRefs {
    Single(EntityUID),
    Multiple(Vec<EntityUID>),
}

impl RefKind for OneOrMultipleRefs {
    fn err_str() -> &'static str {
        "an entity uid or set of entity uids"
    }

    fn create_slot(loc: &Loc) -> Result<Self> {
        Err(ToASTError::new(
            ToASTErrorKind::wrong_entity_argument_two_expected(
                err::parse_errors::Ref::Single,
                err::parse_errors::Ref::Set,
                err::parse_errors::Ref::Template,
            ),
            loc.clone(),
        )
        .into())
    }

    fn create_single_ref(e: EntityUID, _loc: &Loc) -> Result<Self> {
        Ok(OneOrMultipleRefs::Single(e))
    }

    fn create_multiple_refs(_loc: &Loc) -> Result<fn(Vec<EntityUID>) -> Self> {
        fn create_multiple_refs(es: Vec<EntityUID>) -> OneOrMultipleRefs {
            OneOrMultipleRefs::Multiple(es)
        }
        Ok(create_multiple_refs)
    }
}

impl Node<Option<cst::Expr>> {
    /// Extract a single `EntityUID` from this expression. The expression must
    /// be exactly a single entity literal expression.
    pub fn to_ref(&self, var: ast::Var) -> Result<EntityUID> {
        self.to_ref_or_refs::<SingleEntity>(var).map(|x| x.0)
    }

    /// Extract a single `EntityUID` or a template slot from this expression.
    /// The expression must be exactly a single entity literal expression or
    /// a single template slot.
    pub fn to_ref_or_slot(&self, var: ast::Var) -> Result<EntityReference> {
        self.to_ref_or_refs::<EntityReference>(var)
    }

    /// Extract a single `EntityUID` or set of `EntityUID`s from this
    /// expression. The expression must either be exactly a single entity
    /// literal expression a single set literal expression, containing some
    /// number of entity literals.
    pub fn to_refs(&self, var: ast::Var) -> Result<OneOrMultipleRefs> {
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
                let lit = lit.try_as_inner()?;
                let found = format!("literal `{lit}`");
                Err(self
                    .to_ast_err(ToASTErrorKind::wrong_node(
                        T::err_str(),
                        found,
                        match lit {
                            Literal::Str(_) => Some("try including the entity type if you intended this string to be an entity uid"),
                            _ => None,
                        }
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
                        if var != ast::Var::Action {
                            Some("try using `is` to test for an entity type or including an identifier string if you intended this name to be an entity uid".to_string())
                        } else {
                            // We don't allow `is` in the action scope, so we won't suggest trying it.
                            Some("try including an identifier string if you intended this name to be an entity uid".to_string())
                        },
                    ))
                    .into())
            }
            cst::Primary::Expr(x) => x.to_ref_or_refs::<T>(var),
            cst::Primary::EList(lst) => {
                // Calling `create_multiple_refs` first so that we error
                // immediately if we see a set when we don't expect one.
                let create_multiple_refs = T::create_multiple_refs(&self.loc)?;
                let v = ParseErrors::transpose(lst.iter().map(|expr| expr.to_ref(var)))?;
                Ok(create_multiple_refs(v))
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
}

impl Node<Option<cst::Member>> {
    fn to_ref_or_refs<T: RefKind>(&self, var: ast::Var) -> Result<T> {
        let mem = self.try_as_inner()?;

        match mem.access.len() {
            0 => mem.item.to_ref_or_refs::<T>(var),
            _n => {
                Err(self.to_ast_err(ToASTErrorKind::wrong_node(T::err_str(), "a `.` expression", Some("entity types and namespaces cannot use `.` characters -- perhaps try `_` or `::` instead?"))).into())
            }
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
}

impl Node<Option<cst::Or>> {
    fn to_ref_or_refs<T: RefKind>(&self, var: ast::Var) -> Result<T> {
        let or = self.try_as_inner()?;

        match or.extended.len() {
            0 => or.initial.to_ref_or_refs::<T>(var),
            _n => Err(self
                .to_ast_err(ToASTErrorKind::wrong_node(
                    T::err_str(),
                    "a `||` expression",
                    Some("the policy scope can only contain one constraint per variable. Consider moving the second operand of this `||` into a new policy"),
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
                    Some("the policy scope can only contain one constraint per variable. Consider moving the second operand of this `&&` into a `when` condition"),
                ))
                .into()),
        }
    }
}
