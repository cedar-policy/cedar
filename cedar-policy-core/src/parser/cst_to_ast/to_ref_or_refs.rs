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
use crate::ast;
use crate::ast::EntityReference;
use crate::ast::EntityUID;
use crate::parser::{
    cst::{self, Literal},
    err::{self, ParseErrors, ToASTError, ToASTErrorKind},
    AsLocRef, IntoMaybeLoc, Loc, Node,
};

/// Type level marker for parsing sets of entity uids or single uids
/// This presents having either a large level of code duplication
/// or runtime data.
/// This marker is (currently) only used for translating entity references
/// in the policy scope.
trait RefKind: Sized {
    fn err_str() -> &'static str;
    fn create_single_ref(e: EntityUID) -> Result<Self>;
    fn create_multiple_refs(loc: Option<&Loc>) -> Result<fn(Vec<EntityUID>) -> Self>;
    fn create_slot(loc: Option<&Loc>) -> Result<Self>;
    #[cfg(feature = "tolerant-ast")]
    fn error_node() -> Self;
}
struct SingleEntity(pub EntityUID);

impl RefKind for SingleEntity {
    fn err_str() -> &'static str {
        "an entity uid"
    }

    fn create_single_ref(e: EntityUID) -> Result<Self> {
        Ok(SingleEntity(e))
    }

    fn create_multiple_refs(loc: Option<&Loc>) -> Result<fn(Vec<EntityUID>) -> Self> {
        Err(ToASTError::new(
            ToASTErrorKind::wrong_entity_argument_one_expected(
                err::parse_errors::Ref::Single,
                err::parse_errors::Ref::Set,
            ),
            loc.into_maybe_loc(),
        )
        .into())
    }

    fn create_slot(loc: Option<&Loc>) -> Result<Self> {
        Err(ToASTError::new(
            ToASTErrorKind::wrong_entity_argument_one_expected(
                err::parse_errors::Ref::Single,
                err::parse_errors::Ref::Template,
            ),
            loc.into_maybe_loc(),
        )
        .into())
    }
    #[cfg(feature = "tolerant-ast")]
    fn error_node() -> Self {
        SingleEntity(EntityUID::Error)
    }
}

impl RefKind for EntityReference {
    fn err_str() -> &'static str {
        "an entity uid or matching template slot"
    }

    fn create_slot(loc: Option<&Loc>) -> Result<Self> {
        Ok(EntityReference::Slot(loc.into_maybe_loc()))
    }

    fn create_single_ref(e: EntityUID) -> Result<Self> {
        Ok(EntityReference::euid(Arc::new(e)))
    }

    fn create_multiple_refs(loc: Option<&Loc>) -> Result<fn(Vec<EntityUID>) -> Self> {
        Err(ToASTError::new(
            ToASTErrorKind::wrong_entity_argument_two_expected(
                err::parse_errors::Ref::Single,
                err::parse_errors::Ref::Template,
                err::parse_errors::Ref::Set,
            ),
            loc.into_maybe_loc(),
        )
        .into())
    }
    #[cfg(feature = "tolerant-ast")]
    fn error_node() -> Self {
        EntityReference::EUID(Arc::new(EntityUID::Error))
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

    fn create_slot(loc: Option<&Loc>) -> Result<Self> {
        Err(ToASTError::new(
            ToASTErrorKind::wrong_entity_argument_two_expected(
                err::parse_errors::Ref::Single,
                err::parse_errors::Ref::Set,
                err::parse_errors::Ref::Template,
            ),
            loc.into_maybe_loc(),
        )
        .into())
    }

    fn create_single_ref(e: EntityUID) -> Result<Self> {
        Ok(OneOrMultipleRefs::Single(e))
    }

    fn create_multiple_refs(_loc: Option<&Loc>) -> Result<fn(Vec<EntityUID>) -> Self> {
        fn create_multiple_refs(es: Vec<EntityUID>) -> OneOrMultipleRefs {
            OneOrMultipleRefs::Multiple(es)
        }
        Ok(create_multiple_refs)
    }
    #[cfg(feature = "tolerant-ast")]
    fn error_node() -> Self {
        OneOrMultipleRefs::Single(EntityUID::Error)
    }
}

impl Node<Option<cst::Expr>> {
    /// Extract a single `EntityUID` from this expression. The expression must
    /// be exactly a single entity literal expression.
    pub fn to_ref(&self, var: ast::Var) -> Result<EntityUID> {
        self.to_ref_or_refs::<SingleEntity>(var, TolerantAstSetting::NotTolerant)
            .map(|x| x.0)
    }

    /// Extract a single `EntityUID` from this expression. The expression must
    /// be exactly a single entity literal expression.
    #[cfg(feature = "tolerant-ast")]
    pub fn to_ref_tolerant_ast(&self, var: ast::Var) -> Result<EntityUID> {
        self.to_ref_or_refs::<SingleEntity>(var, TolerantAstSetting::Tolerant)
            .map(|x| x.0)
    }

    /// Extract a single `EntityUID` or a template slot from this expression.
    /// The expression must be exactly a single entity literal expression or
    /// a single template slot.
    pub fn to_ref_or_slot(&self, var: ast::Var) -> Result<EntityReference> {
        self.to_ref_or_refs::<EntityReference>(var, TolerantAstSetting::NotTolerant)
    }

    /// Extract a single `EntityUID` or a template slot from this expression.
    /// The expression must be exactly a single entity literal expression or
    /// a single template slot.
    #[cfg(feature = "tolerant-ast")]
    pub fn to_ref_or_slot_tolerant_ast(&self, var: ast::Var) -> Result<EntityReference> {
        self.to_ref_or_refs::<EntityReference>(var, TolerantAstSetting::Tolerant)
    }

    /// Extract a single `EntityUID` or set of `EntityUID`s from this
    /// expression. The expression must either be exactly a single entity
    /// literal expression a single set literal expression, containing some
    /// number of entity literals.
    pub fn to_refs(&self, var: ast::Var) -> Result<OneOrMultipleRefs> {
        self.to_ref_or_refs::<OneOrMultipleRefs>(var, TolerantAstSetting::NotTolerant)
    }

    /// Extract a single `EntityUID` or set of `EntityUID`s from this
    /// expression. The expression must either be exactly a single entity
    /// literal expression a single set literal expression, containing some
    /// number of entity literals.
    #[cfg(feature = "tolerant-ast")]
    pub fn to_refs_tolerant_ast(&self, var: ast::Var) -> Result<OneOrMultipleRefs> {
        self.to_ref_or_refs::<OneOrMultipleRefs>(var, TolerantAstSetting::Tolerant)
    }

    fn to_ref_or_refs<T: RefKind>(
        &self,
        var: ast::Var,
        tolerant_setting: TolerantAstSetting,
    ) -> Result<T> {
        let expr_opt = self.try_as_inner()?;

        let expr = match expr_opt {
            cst::Expr::Expr(expr_impl) => expr_impl,
            #[cfg(feature = "tolerant-ast")]
            cst::Expr::ErrorExpr => return T::create_single_ref(EntityUID::Error),
        };

        match &*expr.expr {
            cst::ExprData::Or(o) => match tolerant_setting {
                TolerantAstSetting::NotTolerant => o.to_ref_or_refs::<T>(var, tolerant_setting),
                #[cfg(feature = "tolerant-ast")]
                TolerantAstSetting::Tolerant => o.to_ref_or_refs::<T>(var, tolerant_setting),
            },
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
use super::TolerantAstSetting;
impl Node<Option<cst::Primary>> {
    fn to_ref_or_refs<T: RefKind>(
        &self,
        var: ast::Var,
        tolerant_setting: TolerantAstSetting,
    ) -> Result<T> {
        let prim = self.try_as_inner()?;

        match prim {
            cst::Primary::Slot(s) => {
                // Call `create_slot` first so that we fail immediately if the
                // `RefKind` does not permit slots, and only then complain if
                // it's the wrong slot. This avoids getting an error
                // `found ?action instead of ?action` when `action` doesn't
                // support slots.
                let slot_ref = T::create_slot(self.loc.as_loc_ref())?;
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
            cst::Primary::Ref(x) => T::create_single_ref(x.to_ref()?),
            cst::Primary::Name(name) => {
                match tolerant_setting {
                    TolerantAstSetting::NotTolerant => {
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
                    #[cfg(feature = "tolerant-ast")]
                    TolerantAstSetting::Tolerant => Ok(T::error_node()),
                }
            }
            cst::Primary::Expr(x) => x.to_ref_or_refs::<T>(var, tolerant_setting),
            cst::Primary::EList(lst) => {
                // Calling `create_multiple_refs` first so that we error
                // immediately if we see a set when we don't expect one.
                let create_multiple_refs = T::create_multiple_refs(self.loc.as_loc_ref())?;
                let v = match tolerant_setting {
                    TolerantAstSetting::NotTolerant => {
                        ParseErrors::transpose(lst.iter().map(|expr| expr.to_ref(var)))?
                    }
                    #[cfg(feature = "tolerant-ast")]
                    TolerantAstSetting::Tolerant => ParseErrors::transpose(
                        lst.iter().map(|expr| expr.to_ref_tolerant_ast(var)),
                    )?,
                };
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
    fn to_ref_or_refs<T: RefKind>(
        &self,
        var: ast::Var,
        tolerant_setting: TolerantAstSetting,
    ) -> Result<T> {
        let mem = self.try_as_inner()?;

        match mem.access.len() {
            0 => mem.item.to_ref_or_refs::<T>(var, tolerant_setting),
            _n => {
                Err(self.to_ast_err(ToASTErrorKind::wrong_node(T::err_str(), "a `.` expression", Some("entity types and namespaces cannot use `.` characters -- perhaps try `_` or `::` instead?"))).into())
            }
        }
    }
}

impl Node<Option<cst::Unary>> {
    fn to_ref_or_refs<T: RefKind>(
        &self,
        var: ast::Var,
        tolerant_setting: TolerantAstSetting,
    ) -> Result<T> {
        let unary = self.try_as_inner()?;

        match &unary.op {
            Some(op) => Err(self
                .to_ast_err(ToASTErrorKind::wrong_node(
                    T::err_str(),
                    format!("a `{op}` expression"),
                    None::<String>,
                ))
                .into()),
            None => unary.item.to_ref_or_refs::<T>(var, tolerant_setting),
        }
    }
}

impl Node<Option<cst::Mult>> {
    fn to_ref_or_refs<T: RefKind>(
        &self,
        var: ast::Var,
        tolerant_setting: TolerantAstSetting,
    ) -> Result<T> {
        let mult = self.try_as_inner()?;

        match mult.extended.len() {
            0 => mult.initial.to_ref_or_refs::<T>(var, tolerant_setting),
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
    fn to_ref_or_refs<T: RefKind>(
        &self,
        var: ast::Var,
        tolerant_setting: TolerantAstSetting,
    ) -> Result<T> {
        let add = self.try_as_inner()?;

        match add.extended.len() {
            0 => add.initial.to_ref_or_refs::<T>(var, tolerant_setting),
            _n => {
                Err(self.to_ast_err(ToASTErrorKind::wrong_node(T::err_str(), "a `+/-` expression", Some("entity types and namespaces cannot use `+` or `-` characters -- perhaps try `_` or `::` instead?"))).into())
            }
        }
    }
}

impl Node<Option<cst::Relation>> {
    fn to_ref_or_refs<T: RefKind>(
        &self,
        var: ast::Var,
        tolerant_setting: TolerantAstSetting,
    ) -> Result<T> {
        let rel = self.try_as_inner()?;

        match rel {
            cst::Relation::Common { initial, extended } => match extended.len() {
                0 => initial.to_ref_or_refs::<T>(var, tolerant_setting),
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
    fn to_ref_or_refs<T: RefKind>(
        &self,
        var: ast::Var,
        tolerant_ast: TolerantAstSetting,
    ) -> Result<T> {
        let or = self.try_as_inner()?;

        match or.extended.len() {
            0 => or.initial.to_ref_or_refs::<T>(var, tolerant_ast),
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
    fn to_ref_or_refs<T: RefKind>(
        &self,
        var: ast::Var,
        tolerant_setting: TolerantAstSetting,
    ) -> Result<T> {
        let and = self.try_as_inner()?;

        match and.extended.len() {
            0 => and.initial.to_ref_or_refs::<T>(var, tolerant_setting),
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

#[cfg(feature = "tolerant-ast")]
#[cfg(test)]
mod test {
    use crate::ast;
    use crate::ast::EntityUID;
    use crate::parser::cst;
    use crate::parser::cst::Name;
    use crate::parser::cst_to_ast::to_ref_or_refs::SingleEntity;
    use crate::parser::cst_to_ast::TolerantAstSetting;
    use crate::parser::IntoMaybeLoc;
    use crate::parser::Loc;
    use crate::parser::Node;

    #[test]
    fn to_ref_or_refs_tolerant_ast() {
        let n = test_primary_name_node();
        let result =
            n.to_ref_or_refs::<SingleEntity>(ast::Var::Principal, TolerantAstSetting::Tolerant);
        assert!(matches!(result.unwrap().0, EntityUID::Error));

        let n = test_primary_literal_node();
        let result =
            n.to_ref_or_refs::<SingleEntity>(ast::Var::Principal, TolerantAstSetting::Tolerant);
        assert!(result.is_err());

        let n = test_primary_slot_node();
        let result =
            n.to_ref_or_refs::<SingleEntity>(ast::Var::Principal, TolerantAstSetting::Tolerant);
        assert!(result.is_err());

        let n = test_primary_expr_error_node();
        let result =
            n.to_ref_or_refs::<SingleEntity>(ast::Var::Principal, TolerantAstSetting::Tolerant);
        assert!(matches!(result.unwrap().0, EntityUID::Error));

        let n = test_primary_expr_node();
        let result =
            n.to_ref_or_refs::<SingleEntity>(ast::Var::Principal, TolerantAstSetting::Tolerant);
        assert!(matches!(result.unwrap().0, EntityUID::EntityUID(_)));

        let n = test_primary_ref_node();
        let result =
            n.to_ref_or_refs::<SingleEntity>(ast::Var::Principal, TolerantAstSetting::Tolerant);
        assert!(matches!(result.unwrap().0, EntityUID::EntityUID(_)));

        let n = test_primary_elist_node();
        let result =
            n.to_ref_or_refs::<SingleEntity>(ast::Var::Principal, TolerantAstSetting::Tolerant);
        assert!(result.is_err());

        let n = test_primary_rinits_node();
        let result =
            n.to_ref_or_refs::<SingleEntity>(ast::Var::Principal, TolerantAstSetting::Tolerant);
        assert!(result.is_err());
    }

    fn test_primary_rinits_node() -> Node<Option<cst::Primary>> {
        Node {
            node: Some(cst::Primary::RInits(vec![])),
            loc: Loc::new(0..1, "This is also a test".into()).into_maybe_loc(),
        }
    }

    fn test_primary_expr_error_node() -> Node<Option<cst::Primary>> {
        Node {
            node: Some(cst::Primary::Expr(Node {
                node: Some(cst::Expr::ErrorExpr),
                loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
            })),
            loc: Loc::new(0..1, "This is also a test".into()).into_maybe_loc(),
        }
    }

    fn test_primary_elist_node() -> Node<Option<cst::Primary>> {
        Node {
            node: Some(cst::Primary::EList(vec![
                Node {
                    node: Some(test_expr()),
                    loc: Loc::new(0..1, "This is also a test".into()).into_maybe_loc(),
                },
                Node {
                    node: Some(test_expr()),
                    loc: Loc::new(0..1, "This is also a test".into()).into_maybe_loc(),
                },
            ])),
            loc: Loc::new(0..1, "This is also a test".into()).into_maybe_loc(),
        }
    }

    fn test_unary_node() -> Node<Option<cst::Unary>> {
        Node {
            node: Some(cst::Unary {
                op: None,
                item: Node {
                    node: Some(cst::Member {
                        item: test_primary_ref_node(),
                        access: vec![],
                    }),
                    loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
                },
            }),
            loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
        }
    }

    fn test_mult_node() -> Node<Option<cst::Mult>> {
        Node {
            node: Some(cst::Mult {
                initial: test_unary_node(),
                extended: vec![],
            }),
            loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
        }
    }

    fn test_add_node() -> Node<Option<cst::Add>> {
        Node {
            node: Some(cst::Add {
                initial: test_mult_node(),
                extended: vec![],
            }),
            loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
        }
    }

    fn test_relation_node() -> Node<Option<cst::Relation>> {
        Node {
            node: Some(cst::Relation::Common {
                initial: test_add_node(),
                extended: vec![],
            }),
            loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
        }
    }

    fn test_expr_or_node() -> cst::ExprData {
        cst::ExprData::Or(Node {
            node: Some(cst::Or {
                extended: vec![],
                initial: Node {
                    node: Some(cst::And {
                        initial: test_relation_node(),
                        extended: vec![],
                    }),
                    loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
                },
            }),
            loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
        })
    }

    fn test_expr() -> cst::Expr {
        cst::Expr::Expr(cst::ExprImpl {
            expr: Box::new(test_expr_or_node()),
        })
    }

    fn test_primary_expr_node() -> Node<Option<cst::Primary>> {
        Node {
            node: Some(cst::Primary::Expr(Node {
                node: Some(test_expr()),
                loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
            })),
            loc: Loc::new(0..1, "This is also a test".into()).into_maybe_loc(),
        }
    }

    fn test_primary_name_node() -> Node<Option<cst::Primary>> {
        Node {
            node: Some(cst::Primary::Name(Node {
                node: Some(Name {
                    path: vec![],
                    name: Node {
                        loc: Loc::new(0..1, "So much testing".into()).into_maybe_loc(),
                        node: Some(cst::Ident::Ident("test".into())),
                    },
                }),
                loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
            })),
            loc: Loc::new(0..1, "This is also a test".into()).into_maybe_loc(),
        }
    }

    fn test_primary_literal_node() -> Node<Option<cst::Primary>> {
        Node {
            node: Some(cst::Primary::Literal(Node {
                node: Some(cst::Literal::True),
                loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
            })),
            loc: Loc::new(0..1, "This is also a test".into()).into_maybe_loc(),
        }
    }

    fn test_primary_slot_node() -> Node<Option<cst::Primary>> {
        Node {
            node: Some(cst::Primary::Slot(Node {
                node: Some(cst::Slot::Principal),
                loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
            })),
            loc: Loc::new(0..1, "This is also a test".into()).into_maybe_loc(),
        }
    }

    fn test_primary_ref_node() -> Node<Option<cst::Primary>> {
        Node {
            node: Some(cst::Primary::Ref(Node {
                node: Some(cst::Ref::Uid {
                    path: Node {
                        node: Some(Name {
                            path: vec![],
                            name: Node {
                                loc: Loc::new(0..1, "So much testing".into()).into_maybe_loc(),
                                node: Some(cst::Ident::Ident("test".into())),
                            },
                        }),
                        loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
                    },
                    eid: Node {
                        node: Some(cst::Str::String("test".into())),
                        loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
                    },
                }),
                loc: Loc::new(0..1, "This is a test".into()).into_maybe_loc(),
            })),
            loc: Loc::new(0..1, "This is also a test".into()).into_maybe_loc(),
        }
    }
}
