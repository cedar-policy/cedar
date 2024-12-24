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

//! This module contains the Cedar evaluator.

use crate::ast::*;
use crate::extensions::Extensions;
use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::HashMap;
use std::sync::Arc;

mod err;
pub use err::evaluation_errors;
pub use err::EvaluationError;
pub(crate) use err::*;
use evaluation_errors::*;
use smol_str::SmolStr;

mod concrete;
pub use concrete::Evaluator;
mod partial;
pub use partial::PartialEvaluator;

#[cfg(not(target_arch = "wasm32"))]
const REQUIRED_STACK_SPACE: usize = 1024 * 100;

// PANIC SAFETY `Name`s in here are valid `Name`s
#[allow(clippy::expect_used)]
mod names {
    use super::Name;
    lazy_static::lazy_static! {
        pub static ref ANY_ENTITY_TYPE : Name = Name::parse_unqualified_name("any_entity_type").expect("valid identifier");
    }
}

/// Evaluator for "restricted" expressions. See notes on `RestrictedExpr`.
#[derive(Debug)]
pub struct RestrictedEvaluator<'e> {
    /// Extensions which are active for this evaluation
    extensions: &'e Extensions<'e>,
}

impl<'e> RestrictedEvaluator<'e> {
    /// Create a fresh evaluator for evaluating "restricted" expressions
    pub fn new(extensions: &'e Extensions<'e>) -> Self {
        Self { extensions }
    }
}

impl<'e> Evaluator<'e> {
    /// Evaluate the given `Policy`, returning either a bool or an error.
    /// The bool indicates whether the policy applies, ie, "is satisfied" for the
    /// current `request`.
    /// This is _different than_ "if the current `request` should be allowed" --
    /// it doesn't consider whether we're processing a `Permit` policy or a
    /// `Forbid` policy.
    pub fn evaluate(&self, p: &Policy) -> Result<bool> {
        self.interpret(&p.condition(), p.env())?.get_as_bool()
    }

    /// Interpret an `Expr` in an empty `SlotEnv`. Also checks that the source
    /// location is propagated to the result.
    #[cfg(test)]
    pub fn interpret_inline_policy(&self, e: &Expr) -> Result<Value> {
        let v = self.interpret(e, &HashMap::new())?;
        debug_assert!(e.source_loc().is_some() == v.source_loc().is_some());
        Ok(v)
    }
}

impl Value {
    /// Convert the `Value` to a boolean, or throw a type error if it's not a
    /// boolean.
    pub(crate) fn get_as_bool(&self) -> Result<bool> {
        match &self.value {
            ValueKind::Lit(Literal::Bool(b)) => Ok(*b),
            _ => Err(EvaluationError::type_error_single(Type::Bool, self)),
        }
    }

    /// Convert the `Value` to a Long, or throw a type error if it's not a
    /// Long.
    pub(crate) fn get_as_long(&self) -> Result<Integer> {
        match &self.value {
            ValueKind::Lit(Literal::Long(i)) => Ok(*i),
            _ => Err(EvaluationError::type_error_single(Type::Long, self)),
        }
    }

    /// Convert the `Value` to a String, or throw a type error if it's not a
    /// String.
    pub(crate) fn get_as_string(&self) -> Result<&SmolStr> {
        match &self.value {
            ValueKind::Lit(Literal::String(s)) => Ok(s),
            _ => Err(EvaluationError::type_error_single(Type::String, self)),
        }
    }

    /// Convert the `Value` to a Set, or throw a type error if it's not a Set.
    pub(crate) fn get_as_set(&self) -> Result<&Set> {
        match &self.value {
            ValueKind::Set(set) => Ok(set),
            _ => Err(EvaluationError::type_error_single(Type::Set, self)),
        }
    }

    /// Convert the `Value` to a Record, or throw a type error if it's not a Record.
    pub(crate) fn get_as_record(&self) -> Result<&Arc<BTreeMap<SmolStr, Value>>> {
        match &self.value {
            ValueKind::Record(rec) => Ok(rec),
            _ => Err(EvaluationError::type_error_single(Type::Record, self)),
        }
    }

    /// Convert the `Value` to an Entity, or throw a type error if it's not a
    /// Entity.
    pub(crate) fn get_as_entity(&self) -> Result<&EntityUID> {
        match &self.value {
            ValueKind::Lit(Literal::EntityUID(uid)) => Ok(uid.as_ref()),
            _ => Err(EvaluationError::type_error_single(
                Type::entity_type(names::ANY_ENTITY_TYPE.clone()),
                self,
            )),
        }
    }
}

#[inline(always)]
fn stack_size_check() -> Result<()> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        if stacker::remaining_stack().unwrap_or(0) < REQUIRED_STACK_SPACE {
            return Err(EvaluationError::recursion_limit(None));
        }
    }
    Ok(())
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
#[cfg(test)]
pub(crate) mod test {
    use nonempty::nonempty;
    use std::str::FromStr;

    use super::*;

    use crate::{
        entities::{Entities, EntityJsonParser, NoEntitiesSchema, TCComputation},
        parser::{parse_expr, parse_policy_or_template},
        test_utils::{expect_err, ExpectedErrorMessageBuilder},
    };

    use cool_asserts::assert_matches;

    /// Many of these tests use this Request
    pub fn basic_request() -> Request {
        Request::new(
            (EntityUID::with_eid("test_principal"), None),
            (EntityUID::with_eid("test_action"), None),
            (EntityUID::with_eid("test_resource"), None),
            Context::from_pairs(
                [
                    ("cur_time".into(), RestrictedExpr::val("03:22:11")),
                    (
                        "device_properties".into(),
                        RestrictedExpr::record(vec![
                            ("os_name".into(), RestrictedExpr::val("Windows")),
                            ("manufacturer".into(), RestrictedExpr::val("ACME Corp")),
                        ])
                        .unwrap(),
                    ),
                    ("violations".into(), RestrictedExpr::set([])),
                ],
                Extensions::none(),
            )
            .unwrap(),
            Some(&RequestSchemaAllPass),
            Extensions::none(),
        )
        .unwrap()
    }

    /// Many of these tests use this basic `Entities`
    pub fn basic_entities() -> Entities {
        Entities::from_entities(
            vec![
                Entity::with_uid(EntityUID::with_eid("foo")),
                Entity::with_uid(EntityUID::with_eid("test_principal")),
                Entity::with_uid(EntityUID::with_eid("test_action")),
                Entity::with_uid(EntityUID::with_eid("test_resource")),
            ],
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::none(),
        )
        .expect("failed to create basic entities")
    }

    /// This `Entities` has richer Entities
    pub fn rich_entities() -> Entities {
        let entity_no_attrs_no_parents =
            Entity::with_uid(EntityUID::with_eid("entity_no_attrs_no_parents"));

        let mut entity_with_attrs = Entity::with_uid(EntityUID::with_eid("entity_with_attrs"));
        entity_with_attrs
            .set_attr("spoon".into(), RestrictedExpr::val(787), Extensions::none())
            .unwrap();
        entity_with_attrs
            .set_attr(
                "fork".into(),
                RestrictedExpr::val("spoon"),
                Extensions::none(),
            )
            .unwrap();
        entity_with_attrs
            .set_attr(
                "tags".into(),
                RestrictedExpr::set(vec![
                    RestrictedExpr::val("fun"),
                    RestrictedExpr::val("good"),
                    RestrictedExpr::val("useful"),
                ]),
                Extensions::none(),
            )
            .unwrap();
        entity_with_attrs
            .set_attr(
                "address".into(),
                RestrictedExpr::record(vec![
                    ("street".into(), RestrictedExpr::val("234 magnolia")),
                    ("town".into(), RestrictedExpr::val("barmstadt")),
                    ("country".into(), RestrictedExpr::val("amazonia")),
                ])
                .unwrap(),
                Extensions::none(),
            )
            .unwrap();

        let mut entity_with_tags = Entity::with_uid(EntityUID::with_eid("entity_with_tags"));
        entity_with_tags
            .set_tag(
                "spoon".into(),
                RestrictedExpr::val(-121),
                Extensions::none(),
            )
            .unwrap();

        let mut entity_with_tags_and_attrs = entity_with_attrs.clone();
        entity_with_tags_and_attrs.set_uid(EntityUID::with_eid("entity_with_tags_and_attrs"));
        entity_with_tags_and_attrs
            .set_tag(
                "spoon".into(),
                RestrictedExpr::val(-121),
                Extensions::none(),
            )
            .unwrap();

        let mut child = Entity::with_uid(EntityUID::with_eid("child"));
        let mut parent = Entity::with_uid(EntityUID::with_eid("parent"));
        let grandparent = Entity::with_uid(EntityUID::with_eid("grandparent"));
        let mut sibling = Entity::with_uid(EntityUID::with_eid("sibling"));
        let unrelated = Entity::with_uid(EntityUID::with_eid("unrelated"));
        child.add_ancestor(parent.uid().clone());
        sibling.add_ancestor(parent.uid().clone());
        parent.add_ancestor(grandparent.uid().clone());
        let mut child_diff_type = Entity::with_uid(
            EntityUID::with_eid_and_type("other_type", "other_child")
                .expect("should be a valid identifier"),
        );
        child_diff_type.add_ancestor(parent.uid().clone());
        child_diff_type.add_ancestor(grandparent.uid().clone());

        Entities::from_entities(
            vec![
                entity_no_attrs_no_parents,
                entity_with_attrs,
                entity_with_tags,
                entity_with_tags_and_attrs,
                child,
                child_diff_type,
                parent,
                grandparent,
                sibling,
                unrelated,
            ],
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::all_available(),
        )
        .expect("Failed to create rich entities")
    }

    #[test]
    fn interpret_primitives() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // The below `assert_eq`s don't actually check the value's source location,
        // because `PartialEq` and `Eq` for `Value` don't compare source locations,
        // but checking the value's source location would not be an interesting
        // test, because these tests don't invoke the parser and there's no way
        // they could produce any source location other than `None`
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val(false)),
            Ok(Value {
                value: ValueKind::Lit(Literal::Bool(false)),
                loc: None,
            }),
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val(true)),
            Ok(Value {
                value: ValueKind::Lit(Literal::Bool(true)),
                loc: None,
            }),
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val(57)),
            Ok(Value {
                value: ValueKind::Lit(Literal::Long(57)),
                loc: None,
            }),
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val(-3)),
            Ok(Value {
                value: ValueKind::Lit(Literal::Long(-3)),
                loc: None,
            }),
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val("")),
            Ok(Value {
                value: ValueKind::Lit(Literal::String("".into())),
                loc: None,
            }),
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val("Hello")),
            Ok(Value {
                value: ValueKind::Lit(Literal::String("Hello".into())),
                loc: None,
            }),
        );
    }

    #[test]
    fn interpret_entities() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // The below `assert_eq`s don't actually check the value's source location,
        // because `PartialEq` and `Eq` for `Value` don't compare source locations,
        // but checking the value's source location would not be an interesting
        // test, because these tests don't invoke the parser and there's no way
        // they could produce any source location other than `None`
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val(EntityUID::with_eid("foo"))),
            Ok(Value {
                value: ValueKind::Lit(Literal::EntityUID(Arc::new(EntityUID::with_eid("foo")))),
                loc: None,
            }),
        );
        // should be no error here even for entities that do not exist.
        // (for instance, A == B is allowed even when A and/or B do not exist.)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::val(EntityUID::with_eid("doesnotexist"))),
            Ok(Value {
                value: ValueKind::Lit(Literal::EntityUID(Arc::new(EntityUID::with_eid(
                    "doesnotexist"
                )))),
                loc: None,
            }),
        );
    }

    #[test]
    fn interpret_builtin_vars() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        assert_eq!(
            eval.interpret_inline_policy(&Expr::var(Var::Principal)),
            Ok(Value::from(EntityUID::with_eid("test_principal")))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::var(Var::Action)),
            Ok(Value::from(EntityUID::with_eid("test_action")))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::var(Var::Resource)),
            Ok(Value::from(EntityUID::with_eid("test_resource")))
        );
    }

    #[test]
    fn interpret_entity_attrs() {
        let request = basic_request();
        let entities = rich_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // has_attr on an entity with no attrs
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::val(EntityUID::with_eid("entity_no_attrs_no_parents")),
                "doesnotexist".into()
            )),
            Ok(Value::from(false))
        );
        // has_attr on an entity that has attrs, but not that one
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::val(EntityUID::with_eid("entity_with_attrs")),
                "doesnotexist".into()
            )),
            Ok(Value::from(false))
        );
        // has_attr where the response is true
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::val(EntityUID::with_eid("entity_with_attrs")),
                "tags".into()
            )),
            Ok(Value::from(true))
        );
        // get_attr on an attr which doesn't exist (and no tags exist)
        assert_matches!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::val(EntityUID::with_eid("entity_with_attrs")),
                "doesnotexist".into()
            )),
            Err(EvaluationError::EntityAttrDoesNotExist(e)) => {
                let report = miette::Report::new(e.clone());
                assert_eq!(e.entity.as_ref(), &EntityUID::with_eid("entity_with_attrs"));
                assert_eq!(&e.attr_or_tag, "doesnotexist");
                let available_attrs = e.available_attrs_or_tags;
                assert_eq!(available_attrs.len(), 4);
                assert!(available_attrs.contains(&"spoon".into()));
                assert!(available_attrs.contains(&"address".into()));
                assert!(available_attrs.contains(&"tags".into()));
                expect_err(
                    "",
                    &report,
                    &ExpectedErrorMessageBuilder::error(r#"`test_entity_type::"entity_with_attrs"` does not have the attribute `doesnotexist`"#)
                        .help("available attributes: [address,fork,spoon,tags]")
                        .build()
                );
            }
        );
        // get_attr on an attr which doesn't exist (but the corresponding tag does)
        assert_matches!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::val(EntityUID::with_eid("entity_with_tags")),
                "spoon".into()
            )),
            Err(EvaluationError::EntityAttrDoesNotExist(e)) => {
                let report = miette::Report::new(e.clone());
                assert_eq!(e.entity.as_ref(), &EntityUID::with_eid("entity_with_tags"));
                assert_eq!(&e.attr_or_tag, "spoon");
                let available_attrs = e.available_attrs_or_tags;
                assert_eq!(available_attrs.len(), 0);
                let expected_error_message =
                    ExpectedErrorMessageBuilder::error(r#"`test_entity_type::"entity_with_tags"` does not have the attribute `spoon`"#)
                        .help(r#"`test_entity_type::"entity_with_tags"` does not have any attributes; note that a tag (not an attribute) named `spoon` does exist"#)
                        .build();
                expect_err("", &report, &expected_error_message);
            }
        );
        // get_attr on an attr which does exist (and has integer type)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::val(EntityUID::with_eid("entity_with_attrs")),
                "spoon".into()
            )),
            Ok(Value::from(787))
        );
        // get_attr on an attr which does exist (and has Set type)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::get_attr(
                    Expr::val(EntityUID::with_eid("entity_with_tags_and_attrs")),
                    "tags".into()
                ),
                Expr::val("useful")
            )),
            Ok(Value::from(true))
        );
        // has_attr on an entity which doesn't exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::val(EntityUID::with_eid("doesnotexist")),
                "foo".into()
            )),
            Ok(Value::from(false))
        );
        // get_attr on an entity which doesn't exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::val(EntityUID::with_eid("doesnotexist")),
                "foo".into()
            )),
            Err(EvaluationError::entity_does_not_exist(
                Arc::new(EntityUID::with_eid("doesnotexist")),
                None
            ))
        );
    }

    #[test]
    fn interpret_entity_tags() {
        let request = basic_request();
        let entities = rich_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // hasTag on an entity with no tags
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_tag(
                Expr::val(EntityUID::with_eid("entity_no_attrs_no_parents")),
                Expr::val("doesnotexist"),
            )),
            Ok(Value::from(false))
        );
        // hasTag on an entity that has tags, but not that one (and no attrs exist)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_tag(
                Expr::val(EntityUID::with_eid("entity_with_tags")),
                Expr::val("doesnotexist"),
            )),
            Ok(Value::from(false))
        );
        // hasTag on an entity that has tags, but not that one (but does have an attr of that name)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_tag(
                Expr::val(EntityUID::with_eid("entity_with_tags_and_attrs")),
                Expr::val("address"),
            )),
            Ok(Value::from(false))
        );
        // hasTag where the response is true
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_tag(
                Expr::val(EntityUID::with_eid("entity_with_tags")),
                Expr::val("spoon"),
            )),
            Ok(Value::from(true))
        );
        // hasTag, with a computed key, where the response is true
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_tag(
                Expr::val(EntityUID::with_eid("entity_with_tags")),
                Expr::get_attr(
                    Expr::val(EntityUID::with_eid("entity_with_tags_and_attrs")),
                    "fork".into()
                ),
            )),
            Ok(Value::from(true))
        );
        // getTag on a tag which doesn't exist (and no attrs exist)
        assert_matches!(
            eval.interpret_inline_policy(&Expr::get_tag(
                Expr::val(EntityUID::with_eid("entity_with_tags")),
                Expr::val("doesnotexist"),
            )),
            Err(EvaluationError::EntityAttrDoesNotExist(e)) => {
                let report = miette::Report::new(e.clone());
                assert_eq!(e.entity.as_ref(), &EntityUID::with_eid("entity_with_tags"));
                assert_eq!(&e.attr_or_tag, "doesnotexist");
                let available_attrs = e.available_attrs_or_tags;
                assert_eq!(available_attrs.len(), 1);
                assert!(available_attrs.contains(&"spoon".into()));
                expect_err(
                    "",
                    &report,
                    &ExpectedErrorMessageBuilder::error(r#"`test_entity_type::"entity_with_tags"` does not have the tag `doesnotexist`"#)
                        .help("available tags: [spoon]")
                        .build()
                );
            }
        );
        // getTag on a tag which doesn't exist (but the corresponding attr does)
        assert_matches!(
            eval.interpret_inline_policy(&Expr::get_tag(
                Expr::val(EntityUID::with_eid("entity_with_tags_and_attrs")),
                Expr::val("address"),
            )),
            Err(EvaluationError::EntityAttrDoesNotExist(e)) => {
                let report = miette::Report::new(e.clone());
                assert_eq!(e.entity.as_ref(), &EntityUID::with_eid("entity_with_tags_and_attrs"));
                assert_eq!(&e.attr_or_tag, "address");
                let available_attrs = e.available_attrs_or_tags;
                assert_eq!(available_attrs.len(), 1);
                assert!(available_attrs.contains(&"spoon".into()));
                expect_err(
                    "",
                    &report,
                    &ExpectedErrorMessageBuilder::error(r#"`test_entity_type::"entity_with_tags_and_attrs"` does not have the tag `address`"#)
                        .help("available tags: [spoon]; note that an attribute (not a tag) named `address` does exist")
                        .build()
                );
            }
        );
        // getTag on a tag which does exist (and has integer type)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_tag(
                Expr::val(EntityUID::with_eid("entity_with_tags")),
                Expr::val("spoon"),
            )),
            Ok(Value::from(-121))
        );
        // getTag with a computed key on a tag which does exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_tag(
                Expr::val(EntityUID::with_eid("entity_with_tags")),
                Expr::get_attr(
                    Expr::val(EntityUID::with_eid("entity_with_attrs")),
                    "fork".into()
                ),
            )),
            Ok(Value::from(-121))
        );
        // getTag with a computed key on a tag which doesn't exist
        assert_matches!(
            eval.interpret_inline_policy(&Expr::get_tag(
                Expr::val(EntityUID::with_eid("entity_with_tags")),
                Expr::get_attr(
                    Expr::get_attr(
                        Expr::val(EntityUID::with_eid("entity_with_attrs")),
                        "address".into()
                    ),
                    "country".into()
                ),
            )),
            Err(e) => {
                expect_err(
                    "",
                    &miette::Report::new(e),
                    &ExpectedErrorMessageBuilder::error(r#"`test_entity_type::"entity_with_tags"` does not have the tag `amazonia`"#)
                        .help("available tags: [spoon]")
                        .build(),
                )
            }
        );
        // hasTag on an entity which doesn't exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_tag(
                Expr::val(EntityUID::with_eid("doesnotexist")),
                Expr::val("foo"),
            )),
            Ok(Value::from(false))
        );
        // getTag on an entity which doesn't exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_tag(
                Expr::val(EntityUID::with_eid("doesnotexist")),
                Expr::val("foo"),
            )),
            Err(EvaluationError::entity_does_not_exist(
                Arc::new(EntityUID::with_eid("doesnotexist")),
                None
            ))
        );
        // getTag on something that's not an entity
        assert_matches!(
            eval.interpret_inline_policy(&Expr::get_tag(
                Expr::record([
                    ("spoon".into(), Expr::val(78)),
                ]).unwrap(),
                Expr::val("spoon"),
            )),
            Err(e) => {
                expect_err(
                    "",
                    &miette::Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type error: expected (entity of type `any_entity_type`), got record")
                        .build()
                );
            }
        );
        // hasTag on something that's not an entity
        assert_matches!(
            eval.interpret_inline_policy(&Expr::has_tag(
                Expr::record([
                    ("spoon".into(), Expr::val(78)),
                ]).unwrap(),
                Expr::val("spoon"),
            )),
            Err(e) => {
                expect_err(
                    "",
                    &miette::Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type error: expected (entity of type `any_entity_type`), got record")
                        .build()
                );
            }
        );
        // getTag with a computed key that doesn't evaluate to a String
        assert_matches!(
            eval.interpret_inline_policy(&Expr::get_tag(
                Expr::val(EntityUID::with_eid("entity_with_tags")),
                Expr::get_attr(Expr::val(EntityUID::with_eid("entity_with_attrs")), "spoon".into()),
            )),
            Err(e) => {
                expect_err(
                    "",
                    &miette::Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type error: expected string, got long")
                        .build()
                );
            }
        );
        // hasTag with a computed key that doesn't evaluate to a String
        assert_matches!(
            eval.interpret_inline_policy(&Expr::has_tag(
                Expr::val(EntityUID::with_eid("entity_with_tags")),
                Expr::get_attr(Expr::val(EntityUID::with_eid("entity_with_attrs")), "spoon".into()),
            )),
            Err(e) => {
                expect_err(
                    "",
                    &miette::Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type error: expected string, got long")
                        .build()
                );
            }
        );
    }

    #[test]
    fn interpret_ternaries() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // if true then 3 else 8
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(Expr::val(true), Expr::val(3), Expr::val(8))),
            Ok(Value::from(3))
        );
        // if false then 3 else 8
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(Expr::val(false), Expr::val(3), Expr::val(8))),
            Ok(Value::from(8))
        );
        // if false then false else true
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(false),
                Expr::val(false),
                Expr::val(true)
            )),
            Ok(Value::from(true))
        );
        // if false then principal else resource
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(false),
                Expr::var(Var::Principal),
                Expr::var(Var::Resource)
            )),
            Ok(Value::from(EntityUID::with_eid("test_resource")))
        );
        // if "hello" then 3 else 8
        assert_matches!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val("hello"),
                Expr::val(3),
                Expr::val(8)
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Bool]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );
        // if principal then 3 else 8
        assert_matches!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::var(Var::Principal),
                Expr::val(3),
                Expr::val(8)
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Bool]);
                assert_eq!(actual, Type::Entity {
                    ty: EntityUID::test_entity_type(),
                });
                assert_eq!(advice, None);
            }
        );
        // if true then "hello" else 2
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(true),
                Expr::val("hello"),
                Expr::val(2)
            )),
            Ok(Value::from("hello"))
        );
        // if false then "hello" else 2
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(false),
                Expr::val("hello"),
                Expr::val(2)
            )),
            Ok(Value::from(2))
        );
        // if true then (if true then 3 else 8) else -10
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(true),
                Expr::ite(Expr::val(true), Expr::val(3), Expr::val(8)),
                Expr::val(-10)
            )),
            Ok(Value::from(3))
        );
        // if true then (if false then 3 else 8) else -10
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(true),
                Expr::ite(Expr::val(false), Expr::val(3), Expr::val(8)),
                Expr::val(-10)
            )),
            Ok(Value::from(8))
        );
        // if false then (if false then 3 else 8) else -10
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(false),
                Expr::ite(Expr::val(false), Expr::val(3), Expr::val(8)),
                Expr::val(-10)
            )),
            Ok(Value::from(-10))
        );
        // if false then (if "hello" then 3 else 8) else -10
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(false),
                Expr::ite(Expr::val("hello"), Expr::val(3), Expr::val(8)),
                Expr::val(-10)
            )),
            Ok(Value::from(-10))
        );
        // if true then 3 else (if true then 8 else -10)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(true),
                Expr::val(3),
                Expr::ite(Expr::val(true), Expr::val(8), Expr::val(-10))
            )),
            Ok(Value::from(3))
        );
        // if (if true then false else true) then 3 else 8
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::ite(Expr::val(true), Expr::val(false), Expr::val(true)),
                Expr::val(3),
                Expr::val(8)
            )),
            Ok(Value::from(8))
        );
        // if true then 3 else <err>
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(true),
                Expr::val(3),
                Expr::get_attr(Expr::record(vec![]).unwrap(), "foo".into()),
            )),
            Ok(Value::from(3))
        );
        // if false then 3 else <err>
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(false),
                Expr::val(3),
                Expr::get_attr(Expr::record(vec![]).unwrap(), "foo".into()),
            )),
            Err(EvaluationError::record_attr_does_not_exist(
                "foo".into(),
                std::iter::empty(),
                0,
                None,
            ))
        );
        // if true then <err> else 3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(true),
                Expr::get_attr(Expr::record(vec![]).unwrap(), "foo".into()),
                Expr::val(3),
            )),
            Err(EvaluationError::record_attr_does_not_exist(
                "foo".into(),
                std::iter::empty(),
                0,
                None,
            ))
        );
        // if false then <err> else 3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(false),
                Expr::get_attr(Expr::record(vec![]).unwrap(), "foo".into()),
                Expr::val(3),
            )),
            Ok(Value::from(3))
        );
    }

    #[test]
    fn interpret_sets() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // The below `assert_eq`s don't actually check the value's source location,
        // because `PartialEq` and `Eq` for `Value` don't compare source locations,
        // but checking the value's source location would not be an interesting
        // test, because these tests don't invoke the parser and there's no way
        // they could produce any source location other than `None`

        // set(8)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::set(vec![Expr::val(8)])),
            Ok(Value::set(
                vec![Value {
                    value: ValueKind::Lit(Literal::Long(8)),
                    loc: None,
                }],
                None,
            )),
        );
        // set(8, 2, 101)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::set(vec![
                Expr::val(8),
                Expr::val(2),
                Expr::val(101),
            ])),
            Ok(Value::set(
                vec![
                    Value {
                        value: ValueKind::Lit(Literal::Long(8)),
                        loc: None,
                    },
                    Value {
                        value: ValueKind::Lit(Literal::Long(2)),
                        loc: None,
                    },
                    Value {
                        value: ValueKind::Lit(Literal::Long(101)),
                        loc: None,
                    },
                ],
                None,
            )),
        );
        // empty set
        assert_eq!(
            eval.interpret_inline_policy(&Expr::set(vec![])),
            Ok(Value::empty_set(None)),
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::set(vec![])),
            Ok(Value::empty_set(None)),
        );
        // set(8)["hello"]
        assert_matches!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::set(vec![Expr::val(8)]),
                "hello".into()
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                    assert_eq!(expected, nonempty![
                        Type::Record,
                        Type::entity_type(
                            Name::parse_unqualified_name("any_entity_type")
                                .expect("should be a valid identifier")
                        ),
                    ]);
                    assert_eq!(actual, Type::Set);
                    assert_eq!(advice, None);
                }
        );
        // indexing into empty set
        assert_matches!(
            eval.interpret_inline_policy(&Expr::get_attr(Expr::set(vec![]), "hello".into())),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ]);
                assert_eq!(actual, Type::Set);
                assert_eq!(advice, None);
            }
        );
        // set("hello", 2, true, <entity foo>)
        let mixed_set = Expr::set(vec![
            Expr::val("hello"),
            Expr::val(2),
            Expr::val(true),
            Expr::val(EntityUID::with_eid("foo")),
        ]);
        assert_eq!(
            eval.interpret_inline_policy(&mixed_set),
            Ok(Value::set(
                vec![
                    Value {
                        value: ValueKind::Lit(Literal::String("hello".into())),
                        loc: None,
                    },
                    Value {
                        value: ValueKind::Lit(Literal::Long(2)),
                        loc: None,
                    },
                    Value {
                        value: ValueKind::Lit(Literal::Bool(true)),
                        loc: None,
                    },
                    Value {
                        value: ValueKind::Lit(Literal::EntityUID(Arc::new(EntityUID::with_eid(
                            "foo"
                        )))),
                        loc: None,
                    },
                ],
                None,
            )),
        );
        // set("hello", 2, true, <entity foo>)["hello"]
        assert_matches!(
            eval.interpret_inline_policy(&Expr::get_attr(mixed_set, "hello".into())),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ]);
                assert_eq!(actual, Type::Set);
                assert_eq!(advice, None);
            }
        );
        // set(set(8, 2), set(13, 702), set(3))
        let set_of_sets = Expr::set(vec![
            Expr::set(vec![Expr::val(8), Expr::val(2)]),
            Expr::set(vec![Expr::val(13), Expr::val(702)]),
            Expr::set(vec![Expr::val(3)]),
        ]);
        assert_eq!(
            eval.interpret_inline_policy(&set_of_sets),
            Ok(Value::set(
                vec![
                    Value::set(
                        vec![
                            Value {
                                value: ValueKind::Lit(Literal::Long(8)),
                                loc: None,
                            },
                            Value {
                                value: ValueKind::Lit(Literal::Long(2)),
                                loc: None,
                            },
                        ],
                        None,
                    ),
                    Value::set(
                        vec![
                            Value {
                                value: ValueKind::Lit(Literal::Long(13)),
                                loc: None,
                            },
                            Value {
                                value: ValueKind::Lit(Literal::Long(702)),
                                loc: None,
                            },
                        ],
                        None,
                    ),
                    Value::set(
                        vec![Value {
                            value: ValueKind::Lit(Literal::Long(3)),
                            loc: None,
                        }],
                        None,
                    ),
                ],
                None,
            )),
        );
        // set(set(8, 2), set(13, 702), set(3))["hello"]
        assert_matches!(
            eval.interpret_inline_policy(&Expr::get_attr(set_of_sets.clone(), "hello".into())),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ]);
                assert_eq!(actual, Type::Set);
                assert_eq!(advice, None);
            }
        );
        // set(set(8, 2), set(13, 702), set(3))["ham"]["eggs"]
        assert_matches!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::get_attr(set_of_sets, "ham".into()),
                "eggs".into()
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ]);
                assert_eq!(actual, Type::Set);
                assert_eq!(advice, None);
            }
        );
    }

    #[test]
    fn interpret_records() {
        let request = basic_request();
        let entities = rich_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // {"key": 3}["key"] or {"key": 3}.key
        let string_key = Expr::record(vec![("key".into(), Expr::val(3))]).unwrap();
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(string_key, "key".into())),
            Ok(Value::from(3))
        );
        // {"ham": 3, "eggs": 7}["ham"] or {"ham": 3, "eggs": 7}.ham
        let ham_and_eggs = Expr::record(vec![
            ("ham".into(), Expr::val(3)),
            ("eggs".into(), Expr::val(7)),
        ])
        .unwrap();
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(ham_and_eggs.clone(), "ham".into())),
            Ok(Value::from(3))
        );
        // {"ham": 3, "eggs": 7}["eggs"]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(ham_and_eggs.clone(), "eggs".into())),
            Ok(Value::from(7))
        );
        // {"ham": 3, "eggs": 7}["what"]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(ham_and_eggs, "what".into())),
            Err(EvaluationError::record_attr_does_not_exist(
                "what".into(),
                [&"eggs".into(), &"ham".into()],
                2,
                None,
            ))
        );

        // {"ham": 3, "eggs": "why"}["ham"]
        let ham_and_eggs_2 = Expr::record(vec![
            ("ham".into(), Expr::val(3)),
            ("eggs".into(), Expr::val("why")),
        ])
        .unwrap();
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(ham_and_eggs_2.clone(), "ham".into())),
            Ok(Value::from(3))
        );
        // {"ham": 3, "eggs": "why"}["eggs"]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(ham_and_eggs_2, "eggs".into())),
            Ok(Value::from("why"))
        );
        // {"ham": 3, "eggs": "why", "else": <entity foo>}["else"]
        let ham_and_eggs_3 = Expr::record(vec![
            ("ham".into(), Expr::val(3)),
            ("eggs".into(), Expr::val("why")),
            ("else".into(), Expr::val(EntityUID::with_eid("foo"))),
        ])
        .unwrap();
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(ham_and_eggs_3, "else".into())),
            Ok(Value::from(EntityUID::with_eid("foo")))
        );
        // {"hams": {"some": 1, "more": 2}, "eggs": "why"}["hams"]["more"]
        let hams_and_eggs = Expr::record(vec![
            (
                "hams".into(),
                Expr::record(vec![
                    ("some".into(), Expr::val(1)),
                    ("more".into(), Expr::val(2)),
                ])
                .unwrap(),
            ),
            ("eggs".into(), Expr::val("why")),
        ])
        .unwrap();
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::get_attr(hams_and_eggs, "hams".into()),
                "more".into()
            )),
            Ok(Value::from(2))
        );
        // {"this is a valid map key+.-_%() ": 7}["this is a valid map key+.-_%() "]
        let weird_key = Expr::record(vec![(
            "this is a valid map key+.-_%() ".into(),
            Expr::val(7),
        )])
        .unwrap();
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                weird_key,
                "this is a valid map key+.-_%() ".into()
            )),
            Ok(Value::from(7))
        );
        // { foo: 2, bar: [3, 33, 333] }.bar
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::record(vec![
                    ("foo".into(), Expr::val(2)),
                    (
                        "bar".into(),
                        Expr::set(vec![Expr::val(3), Expr::val(33), Expr::val(333)])
                    )
                ])
                .unwrap(),
                "bar".into()
            )),
            Ok(Value::set(
                vec![Value::from(3), Value::from(33), Value::from(333)],
                None
            ))
        );
        // { foo: 2, bar: {"a+b": 5, "jkl;": 10} }.bar["a+b"]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::get_attr(
                    Expr::record(vec![
                        ("foo".into(), Expr::val(2)),
                        (
                            "bar".into(),
                            Expr::record(vec![
                                ("a+b".into(), Expr::val(5)),
                                ("jkl;".into(), Expr::val(10)),
                            ])
                            .unwrap()
                        ),
                    ])
                    .unwrap(),
                    "bar".into()
                ),
                "a+b".into()
            )),
            Ok(Value::from(5))
        );
        // { foo: 2, bar: { foo: 4, cake: 77 } }.bar.foo
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::get_attr(
                    Expr::record(vec![
                        ("foo".into(), Expr::val(2)),
                        (
                            "bar".into(),
                            Expr::record(vec![
                                ("foo".into(), Expr::val(4)),
                                ("cake".into(), Expr::val(77)),
                            ])
                            .unwrap()
                        ),
                    ])
                    .unwrap(),
                    "bar".into(),
                ),
                "foo".into(),
            )),
            Ok(Value::from(4))
        );
        // duplicate record key
        // { foo: 2, bar: 4, foo: "hi" }.bar
        assert_eq!(
            Expr::record(vec![
                ("foo".into(), Expr::val(2)),
                ("bar".into(), Expr::val(4)),
                ("foo".into(), Expr::val("hi")),
            ]),
            Err(expression_construction_errors::DuplicateKeyError {
                key: "foo".into(),
                context: "in record literal",
            }
            .into())
        );
        // entity_with_attrs.address.street
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::get_attr(
                    Expr::val(EntityUID::with_eid("entity_with_attrs")),
                    "address".into()
                ),
                "street".into()
            )),
            Ok(Value::from("234 magnolia"))
        );
        // context.cur_time
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::var(Var::Context),
                "cur_time".into()
            )),
            Ok(Value::from("03:22:11"))
        );
        // context.device_properties.os_name
        assert_eq!(
            eval.interpret_inline_policy(&Expr::get_attr(
                Expr::get_attr(Expr::var(Var::Context), "device_properties".into()),
                "os_name".into()
            )),
            Ok(Value::from("Windows"))
        );
        // using has() to test for existence of a record field (which does exist)
        // has({"foo": 77, "bar" : "pancakes"}.foo)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::record(vec![
                    ("foo".into(), Expr::val(77)),
                    ("bar".into(), Expr::val("pancakes")),
                ])
                .unwrap(),
                "foo".into()
            )),
            Ok(Value::from(true))
        );
        // using has() to test for existence of a record field (which doesn't exist)
        // {"foo": 77, "bar" : "pancakes"} has pancakes
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::record(vec![
                    ("foo".into(), Expr::val(77)),
                    ("bar".into(), Expr::val("pancakes")),
                ])
                .unwrap(),
                "pancakes".into()
            )),
            Ok(Value::from(false))
        );
        // {"2": "ham"} has "2"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::record(vec![("2".into(), Expr::val("ham"))]).unwrap(),
                "2".into()
            )),
            Ok(Value::from(true))
        );
        // {"ham": 17, "eggs": if foo has spaghetti then 3 else 7} has ham
        assert_eq!(
            eval.interpret_inline_policy(&Expr::has_attr(
                Expr::record(vec![
                    ("ham".into(), Expr::val(17)),
                    (
                        "eggs".into(),
                        Expr::ite(
                            Expr::has_attr(
                                Expr::val(EntityUID::with_eid("foo")),
                                "spaghetti".into()
                            ),
                            Expr::val(3),
                            Expr::val(7)
                        )
                    ),
                ])
                .unwrap(),
                "ham".into()
            )),
            Ok(Value::from(true))
        );
        // indexing into something that's not a record, 1010122["hello"]
        assert_matches!(
            eval.interpret_inline_policy(&Expr::get_attr(Expr::val(1010122), "hello".into())),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ]);
                assert_eq!(actual, Type::Long);
                assert_eq!(advice, None);
            }
        );
        // indexing into something that's not a record, "hello"["eggs"]
        assert_matches!(
            eval.interpret_inline_policy(&Expr::get_attr(Expr::val("hello"), "eggs".into())),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );
        // has_attr on something that's not a record, 1010122 has hello
        assert_matches!(
            eval.interpret_inline_policy(&Expr::has_attr(Expr::val(1010122), "hello".into())),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ]);
                assert_eq!(actual, Type::Long);
                assert_eq!(advice, None);
            }
        );
        // has_attr on something that's not a record, "hello" has eggs
        assert_matches!(
            eval.interpret_inline_policy(&Expr::has_attr(Expr::val("hello"), "eggs".into())),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![
                    Type::Record,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    ),
                ]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );
    }

    use std::collections::HashSet;

    #[test]
    fn large_entity_err() {
        let expr = Expr::get_attr(
            Expr::val(EntityUID::from_str(r#"Foo::"bar""#).unwrap()),
            "foo".into(),
        );
        let attrs = (1..=7)
            .map(|id| (format!("{id}").into(), RestrictedExpr::val(true)))
            .collect::<HashMap<SmolStr, _>>();
        let entity = Entity::new(
            r#"Foo::"bar""#.parse().unwrap(),
            attrs,
            HashSet::new(),
            [],
            Extensions::none(),
        )
        .unwrap();
        let request = basic_request();
        let entities = Entities::from_entities(
            std::iter::once(entity),
            None::<&NoEntitiesSchema>,
            TCComputation::ComputeNow,
            Extensions::none(),
        )
        .unwrap();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        let result = eval.interpret_inline_policy(&expr).unwrap_err();
        // These are arbitrarily determined by BTreeMap ordering, but are deterministic
        let expected_keys = ["1", "2", "3", "4", "5"]
            .into_iter()
            .map(|x| x.into())
            .collect::<Vec<SmolStr>>();
        let expected = EvaluationError::entity_attr_does_not_exist(
            Arc::new(r#"Foo::"bar""#.parse().unwrap()),
            "foo".into(),
            expected_keys.iter(),
            false,
            7,
            None,
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn large_record_err() {
        let expr = Expr::get_attr(
            Expr::record((1..=7).map(|id| (format!("{id}").into(), Expr::val(true)))).unwrap(),
            "foo".into(),
        );
        let request = basic_request();
        let entities = rich_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        let result = eval.interpret_inline_policy(&expr).unwrap_err();
        let first_five = (1..=5)
            .map(|id| format!("{id}").into())
            .collect::<Vec<SmolStr>>();
        let expected =
            EvaluationError::record_attr_does_not_exist("foo".into(), first_five.iter(), 7, None);
        assert_eq!(result, expected);
    }

    #[test]
    fn interpret_nots() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // not(true)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::not(Expr::val(true))),
            Ok(Value::from(false))
        );
        // not(false)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::not(Expr::val(false))),
            Ok(Value::from(true))
        );
        // not(8)
        assert_matches!(
            eval.interpret_inline_policy(&Expr::not(Expr::val(8))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Bool]);
                assert_eq!(actual, Type::Long);
                assert_eq!(advice, None);
            }
        );
        // not(action)
        assert_matches!(
            eval.interpret_inline_policy(&Expr::not(Expr::var(Var::Action))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Bool]);
                assert_eq!(actual, Type::Entity {
                    ty: EntityUID::test_entity_type(),
                });
                assert_eq!(advice, None);
            }
        );
        // not(not(true))
        assert_eq!(
            eval.interpret_inline_policy(&Expr::not(Expr::not(Expr::val(true)))),
            Ok(Value::from(true))
        );
        // not(if true then false else true)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::not(Expr::ite(
                Expr::val(true),
                Expr::val(false),
                Expr::val(true)
            ))),
            Ok(Value::from(true))
        );
        // if not(true) then "hello" else "goodbye"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::not(Expr::val(true)),
                Expr::val("hello"),
                Expr::val("goodbye")
            )),
            Ok(Value::from("goodbye"))
        );
    }

    #[test]
    fn interpret_negs() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // neg(101)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::neg(Expr::val(101))),
            Ok(Value::from(-101))
        );
        // neg(-101)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::neg(Expr::val(-101))),
            Ok(Value::from(101))
        );
        // neg(0)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::neg(Expr::val(0))),
            Ok(Value::from(0))
        );
        // neg(neg(7))
        assert_eq!(
            eval.interpret_inline_policy(&Expr::neg(Expr::neg(Expr::val(7)))),
            Ok(Value::from(7))
        );
        // if true then neg(8) else neg(1)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::val(true),
                Expr::neg(Expr::val(8)),
                Expr::neg(Expr::val(1))
            )),
            Ok(Value::from(-8))
        );
        // overflow
        assert_eq!(
            eval.interpret_inline_policy(&Expr::neg(Expr::val(Integer::MIN))),
            Err(IntegerOverflowError::UnaryOp(UnaryOpOverflowError {
                op: UnaryOp::Neg,
                arg: Value::from(Integer::MIN),
                source_loc: None,
            })
            .into()),
        );
        // neg(false)
        assert_matches!(
            eval.interpret_inline_policy(&Expr::neg(Expr::val(false))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::Bool);
                assert_eq!(advice, None);
            }
        );
        // neg([1, 2, 3])
        assert_matches!(
            eval.interpret_inline_policy(&Expr::neg(Expr::set([
                Expr::val(1),
                Expr::val(2),
                Expr::val(3)
            ]))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::Set);
                assert_eq!(advice, None);
            }
        );
    }

    #[test]
    fn interpret_eqs() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // eq(33, 33)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(Expr::val(33), Expr::val(33))),
            Ok(Value::from(true))
        );
        // eq(33, -12)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(Expr::val(33), Expr::val(-12))),
            Ok(Value::from(false))
        );
        // if eq("foo", "foo") then 12 else 97
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::is_eq(Expr::val("foo"), Expr::val("foo")),
                Expr::val(12),
                Expr::val(97),
            )),
            Ok(Value::from(12))
        );
        // if eq([1, -33, 707], [1, -33]) then 12 else 97
        assert_eq!(
            eval.interpret_inline_policy(&Expr::ite(
                Expr::is_eq(
                    Expr::set(vec![Expr::val(1), Expr::val(-33), Expr::val(707)]),
                    Expr::set(vec![Expr::val(1), Expr::val(-33)])
                ),
                Expr::val(12),
                Expr::val(97),
            )),
            Ok(Value::from(97))
        );
        // eq(2>0, 0>(-2))
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::greater(Expr::val(2), Expr::val(0)),
                Expr::greater(Expr::val(0), Expr::val(-2))
            )),
            Ok(Value::from(true))
        );
        // eq(12+33, 50-5)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::add(Expr::val(12), Expr::val(33)),
                Expr::sub(Expr::val(50), Expr::val(5)),
            )),
            Ok(Value::from(true))
        );
        // eq([1, 2, 40], [1, 2, 40])
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::set(vec![Expr::val(1), Expr::val(2), Expr::val(40)]),
                Expr::set(vec![Expr::val(1), Expr::val(2), Expr::val(40)])
            )),
            Ok(Value::from(true))
        );
        // eq([1, 2, 40], [1, 40, 2])
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::set(vec![Expr::val(1), Expr::val(2), Expr::val(40)]),
                Expr::set(vec![Expr::val(1), Expr::val(40), Expr::val(2)])
            )),
            Ok(Value::from(true))
        );
        // eq([1, -2, 40], [1, 40])
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::set(vec![Expr::val(1), Expr::val(-2), Expr::val(40)]),
                Expr::set(vec![Expr::val(1), Expr::val(40)])
            )),
            Ok(Value::from(false))
        );
        // eq([1, 1, 1, 2, 40], [40, 1, 2])
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::set(vec![
                    Expr::val(1),
                    Expr::val(1),
                    Expr::val(1),
                    Expr::val(2),
                    Expr::val(40)
                ]),
                Expr::set(vec![Expr::val(40), Expr::val(1), Expr::val(2)])
            )),
            Ok(Value::from(true))
        );
        // eq([1, 1, 2, 1, 40, 2, 1, 2, 40, 1], [1, 40, 1, 2])
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::set(vec![
                    Expr::val(1),
                    Expr::val(1),
                    Expr::val(2),
                    Expr::val(1),
                    Expr::val(40),
                    Expr::val(2),
                    Expr::val(1),
                    Expr::val(2),
                    Expr::val(40),
                    Expr::val(1)
                ]),
                Expr::set(vec![
                    Expr::val(1),
                    Expr::val(40),
                    Expr::val(1),
                    Expr::val(2)
                ])
            )),
            Ok(Value::from(true))
        );
        // eq(context.device_properties, { appropriate record literal })
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::get_attr(Expr::var(Var::Context), "device_properties".into()),
                Expr::record(vec![
                    ("os_name".into(), Expr::val("Windows")),
                    ("manufacturer".into(), Expr::val("ACME Corp")),
                ])
                .unwrap()
            )),
            Ok(Value::from(true))
        );
        // eq(context.device_properties, { record literal missing one field })
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::get_attr(Expr::var(Var::Context), "device_properties".into()),
                Expr::record(vec![("os_name".into(), Expr::val("Windows"))]).unwrap()
            )),
            Ok(Value::from(false))
        );
        // eq(context.device_properties, { record literal with an extra field })
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::get_attr(Expr::var(Var::Context), "device_properties".into()),
                Expr::record(vec![
                    ("os_name".into(), Expr::val("Windows")),
                    ("manufacturer".into(), Expr::val("ACME Corp")),
                    ("extrafield".into(), Expr::val(true)),
                ])
                .unwrap()
            )),
            Ok(Value::from(false))
        );
        // eq(context.device_properties, { record literal with the same keys/values })
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::get_attr(Expr::var(Var::Context), "device_properties".into()),
                Expr::record(vec![
                    ("os_name".into(), Expr::val("Windows")),
                    ("manufacturer".into(), Expr::val("ACME Corp")),
                ])
                .unwrap()
            )),
            Ok(Value::from(true))
        );
        // eq(A, A) where A is an Entity
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::val(EntityUID::with_eid("foo")),
                Expr::val(EntityUID::with_eid("foo")),
            )),
            Ok(Value::from(true))
        );
        // eq(A, A) where A is an Entity that doesn't exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::val(EntityUID::with_eid("doesnotexist")),
                Expr::val(EntityUID::with_eid("doesnotexist")),
            )),
            Ok(Value::from(true))
        );
        // eq(A, B) where A and B are entities of the same type
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::val(EntityUID::with_eid("foo")),
                Expr::val(EntityUID::with_eid("bar")),
            )),
            Ok(Value::from(false))
        );
        // eq(A, B) where A and B are entities of different types
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::val(
                    EntityUID::with_eid_and_type("type1", "foo")
                        .expect("should be a valid identifier")
                ),
                Expr::val(
                    EntityUID::with_eid_and_type("type2", "bar")
                        .expect("should be a valid identifier")
                ),
            )),
            Ok(Value::from(false))
        );
        // eq(A, B) where A and B are entities of different types but happen to
        // have the same name
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::val(
                    EntityUID::with_eid_and_type("type1", "foo")
                        .expect("should be a valid identifier")
                ),
                Expr::val(
                    EntityUID::with_eid_and_type("type2", "foo")
                        .expect("should be a valid identifier")
                ),
            )),
            Ok(Value::from(false))
        );
        // eq(A, B) where A exists but B does not
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::val(EntityUID::with_eid("foo")),
                Expr::val(EntityUID::with_eid("doesnotexist")),
            )),
            Ok(Value::from(false))
        );
        // eq("foo", <entity foo>)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::val("foo"),
                Expr::val(EntityUID::with_eid("foo"))
            )),
            Ok(Value::from(false))
        );
    }

    #[test]
    fn interpret_compares() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::all_available());
        // 3 < 303
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(3), Expr::val(303))),
            Ok(Value::from(true))
        );
        // 3 < -303
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(3), Expr::val(-303))),
            Ok(Value::from(false))
        );
        // -303 < -1
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(-303), Expr::val(-1))),
            Ok(Value::from(true))
        );
        // 3 < 3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(3), Expr::val(3))),
            Ok(Value::from(false))
        );
        // -33 <= 0
        assert_eq!(
            eval.interpret_inline_policy(&Expr::lesseq(Expr::val(-33), Expr::val(0))),
            Ok(Value::from(true))
        );
        // 3 <= 3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::lesseq(Expr::val(3), Expr::val(3))),
            Ok(Value::from(true))
        );
        // 7 > 3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greater(Expr::val(7), Expr::val(3))),
            Ok(Value::from(true))
        );
        // 7 > -3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greater(Expr::val(7), Expr::val(-3))),
            Ok(Value::from(true))
        );
        // 7 > 7
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greater(Expr::val(7), Expr::val(7))),
            Ok(Value::from(false))
        );
        // 0 >= -7
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val(0), Expr::val(-7))),
            Ok(Value::from(true))
        );
        // -1 >= 7
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val(-1), Expr::val(7))),
            Ok(Value::from(false))
        );
        // 7 >= 7
        assert_eq!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val(7), Expr::val(7))),
            Ok(Value::from(true))
        );
        // false < true
        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(false), Expr::val(true))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::Bool);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // false < false
        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(false), Expr::val(false))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::Bool);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // true <= false
        assert_matches!(
            eval.interpret_inline_policy(&Expr::lesseq(Expr::val(true), Expr::val(false))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::Bool);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // false <= false
        assert_matches!(
            eval.interpret_inline_policy(&Expr::lesseq(Expr::val(false), Expr::val(false))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected,nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::Bool);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // false > true
        assert_matches!(
            eval.interpret_inline_policy(&Expr::greater(Expr::val(false), Expr::val(true))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::Bool);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // true > true
        assert_matches!(
            eval.interpret_inline_policy(&Expr::greater(Expr::val(true), Expr::val(true))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::Bool);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // true >= false
        assert_matches!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val(true), Expr::val(false))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::Bool);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // true >= true
        assert_matches!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val(true), Expr::val(true))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::Bool);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // bc < zzz
        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(Expr::val("bc"), Expr::val("zzz"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // banana < zzz
        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(Expr::val("banana"), Expr::val("zzz"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // "" < zzz
        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(""), Expr::val("zzz"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // a < 1
        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(Expr::val("a"), Expr::val("1"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // a < A
        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(Expr::val("a"), Expr::val("A"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // A < A
        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(Expr::val("A"), Expr::val("A"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // zebra < zebras
        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(Expr::val("zebra"), Expr::val("zebras"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // zebra <= zebras
        assert_matches!(
            eval.interpret_inline_policy(&Expr::lesseq(Expr::val("zebra"), Expr::val("zebras"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // zebras <= zebras
        assert_matches!(
            eval.interpret_inline_policy(&Expr::lesseq(Expr::val("zebras"), Expr::val("zebras"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // zebras <= Zebras
        assert_matches!(
            eval.interpret_inline_policy(&Expr::lesseq(Expr::val("zebras"), Expr::val("Zebras"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // 123 > 78
        assert_matches!(
            eval.interpret_inline_policy(&Expr::greater(Expr::val("123"), Expr::val("78"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // <space>zebras >= zebras
        assert_matches!(
            eval.interpret_inline_policy(&Expr::greatereq(
                Expr::val(" zebras"),
                Expr::val("zebras")
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // "" >= ""
        assert_matches!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val(""), Expr::val(""))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // "" >= _hi
        assert_matches!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val(""), Expr::val("_hi"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // 🦀 >= _hi
        assert_matches!(
            eval.interpret_inline_policy(&Expr::greatereq(Expr::val("🦀"), Expr::val("_hi"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );
        // 2 < "4"
        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(2), Expr::val("4"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );
        // "4" < 2
        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(Expr::val("4"), Expr::val(2))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );
        // false < 1
        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(false), Expr::val(1))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::Bool);
                assert_eq!(advice, None);
            }
        );
        // 1 < false
        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(Expr::val(1), Expr::val(false))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::Bool);
                assert_eq!(advice, None);
            }
        );
        // [1, 2] < [47, 0]
        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(
                Expr::set(vec![Expr::val(1), Expr::val(2)]),
                Expr::set(vec![Expr::val(47), Expr::val(0)])
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: "datetime".parse().unwrap()}, Type::Extension { name: "duration".parse().unwrap()}, Type::Long]);
                assert_eq!(actual, Type::Set);
                assert_eq!(advice, Some("Only `Long` and extension types `datetime`, `duration` support comparison".into()));
            }
        );

        let datetime_constructor: Name = "datetime".parse().unwrap();
        let duration_constructor: Name = "duration".parse().unwrap();
        assert_matches!(eval.interpret_inline_policy(
            &Expr::less(
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-01-01").into()]),
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-01-23").into()]))),
            Ok(v) if v == Value::from(true));
        assert_matches!(eval.interpret_inline_policy(
            &Expr::lesseq(
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-01-01").into()]),
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-01-23").into()]))),
            Ok(v) if v == Value::from(true));
        assert_matches!(eval.interpret_inline_policy(
            &Expr::less(
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-01-01T01:02:03Z").into()]),
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2023-01-23").into()]))),
            Ok(v) if v == Value::from(false));
        assert_matches!(eval.interpret_inline_policy(
            &Expr::lesseq(
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-01-01T01:02:03Z").into()]),
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2023-01-23").into()]))),
            Ok(v) if v == Value::from(false));
        assert_matches!(eval.interpret_inline_policy(
            &Expr::less(
                Expr::call_extension_fn(
                    duration_constructor.clone(),
                    vec![Value::from("5s").into()]),
                Expr::call_extension_fn(
                    duration_constructor.clone(),
                    vec![Value::from("2m").into()]))),
            Ok(v) if v == Value::from(true));
        assert_matches!(eval.interpret_inline_policy(
            &Expr::lesseq(
                Expr::call_extension_fn(
                    duration_constructor.clone(),
                    vec![Value::from("1h").into()]),
                Expr::call_extension_fn(
                    duration_constructor.clone(),
                    vec![Value::from("2h").into()]))),
            Ok(v) if v == Value::from(true));
        assert_matches!(eval.interpret_inline_policy(
            &Expr::less(
                Expr::call_extension_fn(
                    duration_constructor.clone(),
                    vec![Value::from("3h2m").into()]),
                Expr::call_extension_fn(
                    duration_constructor.clone(),
                    vec![Value::from("2h").into()]))),
            Ok(v) if v == Value::from(false));
        assert_matches!(eval.interpret_inline_policy(
            &Expr::lesseq(
                Expr::call_extension_fn(
                    duration_constructor.clone(),
                    vec![Value::from("3h2m").into()]),
                Expr::call_extension_fn(
                    duration_constructor.clone(),
                    vec![Value::from("2h").into()]))),
            Ok(v) if v == Value::from(false));

        // datetimes that are different times on the same day
        assert_matches!(eval.interpret_inline_policy(
            &Expr::noteq(
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-11-07").into()]),
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-11-07T14:00:00Z").into()]))),
            Ok(v) if v == Value::from(true));
        assert_matches!(eval.interpret_inline_policy(
            &Expr::noteq(
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-11-07T14:00:00.123Z").into()]),
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-11-07T14:00:00Z").into()]))),
            Ok(v) if v == Value::from(true));
        assert_matches!(eval.interpret_inline_policy(
            &Expr::noteq(
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-11-07T14:00:00Z").into()]),
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-11-07T17:00:00Z").into()]))),
            Ok(v) if v == Value::from(true));

        // datetimes that use the UTC offset
        // both datetimes are UTC 2024-11-07T12:00:00Z
        assert_matches!(eval.interpret_inline_policy(
            &Expr::noteq(
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-11-07T14:00:00+0200").into()]),
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-11-07T11:00:00-0100").into()]))),
            Ok(v) if v == Value::from(false));
        // both datetimes are UTC 2024-11-08
        assert_matches!(eval.interpret_inline_policy(
            &Expr::noteq(
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-11-08T02:00:00+0200").into()]),
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-11-07T23:00:00-0100").into()]))),
            Ok(v) if v == Value::from(false));

        // feb 28 < feb 29 < mar 1 for a leap year
        assert_matches!(eval.interpret_inline_policy(
            &Expr::less(
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-02-28").into()]),
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-02-29").into()]))),
            Ok(v) if v == Value::from(true));
        assert_matches!(eval.interpret_inline_policy(
            &Expr::less(
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-02-29").into()]),
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2024-03-01").into()]))),
            Ok(v) if v == Value::from(true));

        // type error favors long and then extension types with operator overloading
        assert_matches!(eval.interpret_inline_policy(
        &Expr::lesseq(
            Value::from(1).into(),
            Expr::call_extension_fn(
                duration_constructor.clone(),
                vec![Value::from("2h").into()]))),
        Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::Extension { name: duration_constructor.clone() });
                assert_eq!(advice, None);
        });

        assert_matches!(eval.interpret_inline_policy(
            &Expr::lesseq(
                Expr::call_extension_fn(
                    duration_constructor.clone(),
                    vec![Value::from("2h").into()]),
                Value::from(1).into())),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::Extension { name: duration_constructor.clone() });
                assert_eq!(advice, None);
        });

        assert_matches!(eval.interpret_inline_policy(
        &Expr::lesseq(
            Expr::call_extension_fn(
                duration_constructor.clone(),
                vec![Value::from("2h").into()]),
            Expr::call_extension_fn(
                "decimal".parse().unwrap(),
                vec![Value::from("2.0").into()]))),
        Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: duration_constructor.clone() }]);
                assert_eq!(actual, Type::Extension { name: "decimal".parse().unwrap() });
                assert_eq!(advice, None);
        });

        assert_matches!(eval.interpret_inline_policy(
            &Expr::lesseq(
                Expr::call_extension_fn(
                    "decimal".parse().unwrap(),
                    vec![Value::from("2.0").into()]),
                Expr::call_extension_fn(
                    duration_constructor.clone(),
                    vec![Value::from("2h").into()]))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: duration_constructor.clone() }]);
                assert_eq!(actual, Type::Extension { name: "decimal".parse().unwrap() });
                assert_eq!(advice, None);
        });

        // if both sides support overloading, favor lhs
        assert_matches!(eval.interpret_inline_policy(
            &Expr::lesseq(
                Expr::call_extension_fn(
                    datetime_constructor.clone(),
                    vec![Value::from("2023-01-23").into()]),
                Expr::call_extension_fn(
                    duration_constructor.clone(),
                    vec![Value::from("2h").into()]))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: datetime_constructor.clone() }]);
                assert_eq!(actual, Type::Extension { name: duration_constructor.clone() });
                assert_eq!(advice, None);
        });

        // if both sides are of the same extension type without any operator overloading, remind users those that have
        assert_matches!(eval.interpret_inline_policy(
            &Expr::lesseq(
                Expr::call_extension_fn(
                    "decimal".parse().unwrap(),
                    vec![Value::from("2.0").into()]),
                Expr::call_extension_fn(
                    "decimal".parse().unwrap(),
                    vec![Value::from("3.0").into()]))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Extension { name: datetime_constructor }, Type::Extension { name: duration_constructor }]);
                assert_eq!(actual, Type::Extension { name: "decimal".parse().unwrap() });
                assert_eq!(advice, Some("Only extension types `datetime` and `duration` support operator overloading".into()));
        });
    }

    #[test]
    fn interpret_comparison_err_order() {
        // Expressions are evaluated left to right, so the unexpected-string
        // type error should be reported for all of the following. This tests a
        // fix for incorrect evaluation order in `>` and `>=`.
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());

        assert_matches!(
            eval.interpret_inline_policy(&Expr::greatereq(
                Expr::add(Expr::val("a"), Expr::val("b")),
                Expr::add(Expr::val(false), Expr::val(true))
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );

        assert_matches!(
            eval.interpret_inline_policy(&Expr::greater(
                Expr::add(Expr::val("a"), Expr::val("b")),
                Expr::add(Expr::val(false), Expr::val(true))
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );

        assert_matches!(
            eval.interpret_inline_policy(&Expr::lesseq(
                Expr::add(Expr::val("a"), Expr::val("b")),
                Expr::add(Expr::val(false), Expr::val(true))
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );

        assert_matches!(
            eval.interpret_inline_policy(&Expr::less(
                Expr::add(Expr::val("a"), Expr::val("b")),
                Expr::add(Expr::val(false), Expr::val(true))
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );
    }

    #[test]
    fn interpret_arithmetic() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // 11 + 22
        assert_eq!(
            eval.interpret_inline_policy(&Expr::add(Expr::val(11), Expr::val(22))),
            Ok(Value::from(33))
        );
        // 11 + 0
        assert_eq!(
            eval.interpret_inline_policy(&Expr::add(Expr::val(11), Expr::val(0))),
            Ok(Value::from(11))
        );
        // -1 + 1
        assert_eq!(
            eval.interpret_inline_policy(&Expr::add(Expr::val(-1), Expr::val(1))),
            Ok(Value::from(0))
        );
        // overflow
        assert_eq!(
            eval.interpret_inline_policy(&Expr::add(Expr::val(Integer::MAX), Expr::val(1))),
            Err(IntegerOverflowError::BinaryOp(BinaryOpOverflowError {
                op: BinaryOp::Add,
                arg1: Value::from(Integer::MAX),
                arg2: Value::from(1),
                source_loc: None,
            })
            .into())
        );
        // 7 + "3"
        assert_matches!(
            eval.interpret_inline_policy(&Expr::add(Expr::val(7), Expr::val("3"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );
        // 44 - 31
        assert_eq!(
            eval.interpret_inline_policy(&Expr::sub(Expr::val(44), Expr::val(31))),
            Ok(Value::from(13))
        );
        // 5 - (-3)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::sub(Expr::val(5), Expr::val(-3))),
            Ok(Value::from(8))
        );
        // overflow
        assert_eq!(
            eval.interpret_inline_policy(&Expr::sub(Expr::val(Integer::MIN + 2), Expr::val(3))),
            Err(IntegerOverflowError::BinaryOp(BinaryOpOverflowError {
                op: BinaryOp::Sub,
                arg1: Value::from(Integer::MIN + 2),
                arg2: Value::from(3),
                source_loc: None,
            })
            .into())
        );
        // "ham" - "ha"
        assert_matches!(
            eval.interpret_inline_policy(&Expr::sub(Expr::val("ham"), Expr::val("ha"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );
        // 5 * (-3)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::mul(Expr::val(5), Expr::val(-3))),
            Ok(Value::from(-15))
        );
        // 5 * 0
        assert_eq!(
            eval.interpret_inline_policy(&Expr::mul(Expr::val(5), Expr::val(0))),
            Ok(Value::from(0))
        );
        // "5" * 0
        assert_matches!(
            eval.interpret_inline_policy(&Expr::mul(Expr::val("5"), Expr::val(0))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Long]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );
        // overflow
        assert_eq!(
            eval.interpret_inline_policy(&Expr::mul(Expr::val(Integer::MAX - 1), Expr::val(3))),
            Err(IntegerOverflowError::BinaryOp(BinaryOpOverflowError {
                op: BinaryOp::Mul,
                arg1: Value::from(Integer::MAX - 1),
                arg2: Value::from(3),
                source_loc: None,
            })
            .into())
        );
    }

    #[test]
    fn interpret_set_and_map_membership() {
        let request = basic_request();
        let entities = rich_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());

        // [2, 3, 4] contains 2
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![Expr::val(2), Expr::val(3), Expr::val(4)]),
                Expr::val(2)
            )),
            Ok(Value::from(true))
        );
        // [34, 2, -7] contains 2
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![Expr::val(34), Expr::val(2), Expr::val(-7)]),
                Expr::val(2)
            )),
            Ok(Value::from(true))
        );
        // [34, 2, -7] contains 3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![Expr::val(34), Expr::val(2), Expr::val(-7)]),
                Expr::val(3)
            )),
            Ok(Value::from(false))
        );
        // [] contains 7
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(Expr::set(vec![]), Expr::val(7))),
            Ok(Value::from(false))
        );
        // ["some", "useful", "tags"] contains "foo"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![
                    Expr::val("some"),
                    Expr::val("useful"),
                    Expr::val("tags")
                ]),
                Expr::val("foo")
            )),
            Ok(Value::from(false))
        );
        // ["some", "useful", "tags"] contains "useful"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![
                    Expr::val("some"),
                    Expr::val("useful"),
                    Expr::val("tags")
                ]),
                Expr::val("useful")
            )),
            Ok(Value::from(true))
        );
        // [<entity child>, <entity sibling>] contains <entity child>
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("child")),
                    Expr::val(EntityUID::with_eid("sibling"))
                ]),
                Expr::val(EntityUID::with_eid("child"))
            )),
            Ok(Value::from(true))
        );
        // [<entity parent>, <entity sibling>] contains <entity child>
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("parent")),
                    Expr::val(EntityUID::with_eid("sibling"))
                ]),
                Expr::val(EntityUID::with_eid("child"))
            )),
            Ok(Value::from(false))
        );
        // ["foo", "bar"] contains 3
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![Expr::val("foo"), Expr::val("bar")]),
                Expr::val(3)
            )),
            Ok(Value::from(false))
        );
        // ["foo", "bar"] contains [3]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![Expr::val("foo"), Expr::val("bar")]),
                Expr::set(vec![Expr::val(3)])
            )),
            Ok(Value::from(false))
        );
        // [[7], "eggs", [3]] contains [3]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![
                    Expr::set(vec![Expr::val(7)]),
                    Expr::val("eggs"),
                    Expr::set(vec![Expr::val(3)])
                ]),
                Expr::set(vec![Expr::val(3)])
            )),
            Ok(Value::from(true))
        );

        // ["2", 20, true, <entity foo>] contains 2
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![
                    Expr::val("2"),
                    Expr::val(20),
                    Expr::val(true),
                    Expr::val(EntityUID::with_eid("foo")),
                ]),
                Expr::val(2)
            )),
            Ok(Value::from(false))
        );
        // ["ham", entity_with_attrs.address.town, -1] contains "barmstadt"
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::set(vec![
                    Expr::val("ham"),
                    Expr::get_attr(
                        Expr::get_attr(
                            Expr::val(EntityUID::with_eid("entity_with_attrs")),
                            "address".into()
                        ),
                        "town".into()
                    ),
                    Expr::val(-1),
                ]),
                Expr::val("barmstadt")
            )),
            Ok(Value::from(true))
        );
        // 3 contains 7
        assert_matches!(
            eval.interpret_inline_policy(&Expr::contains(Expr::val(3), Expr::val(7))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Set]);
                assert_eq!(actual, Type::Long);
                assert_eq!(advice, None);
            }
        );
        // { ham: "eggs" } contains "ham"
        assert_matches!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::record(vec![("ham".into(), Expr::val("eggs"))]).unwrap(),
                Expr::val("ham")
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Set]);
                assert_eq!(actual, Type::Record);
                assert_eq!(advice, None);
            }
        );
        // wrong argument order
        assert_matches!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::val(3),
                Expr::set(vec![Expr::val(1), Expr::val(3), Expr::val(7)])
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Set]);
                assert_eq!(actual, Type::Long);
                assert_eq!(advice, None);
            }
        );
    }

    #[test]
    fn interpret_hierarchy_membership() {
        let request = basic_request();
        let entities = rich_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // A in B, where A and B are unrelated (but same type)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::val(EntityUID::with_eid("unrelated"))
            )),
            Ok(Value::from(false))
        );
        // A in B, where A and B are the same type and it's true
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::val(EntityUID::with_eid("parent"))
            )),
            Ok(Value::from(true))
        );
        // A in B, where A and B are different types and it's true
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(
                    EntityUID::with_eid_and_type("other_type", "other_child")
                        .expect("should be a valid identifier")
                ),
                Expr::val(EntityUID::with_eid("parent"))
            )),
            Ok(Value::from(true))
        );
        // A in B, where A and B are unrelated _and_ different types
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(
                    EntityUID::with_eid_and_type("other_type", "other_child")
                        .expect("should be a valid identifier")
                ),
                Expr::val(EntityUID::with_eid("unrelated"))
            )),
            Ok(Value::from(false))
        );
        // A in B, where A and B are siblings
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::val(EntityUID::with_eid("sibling"))
            )),
            Ok(Value::from(false))
        );
        // A in A, where A exists
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("parent")),
                Expr::val(EntityUID::with_eid("parent"))
            )),
            Ok(Value::from(true))
        );
        // A in A, where A does not exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("doesnotexist")),
                Expr::val(EntityUID::with_eid("doesnotexist")),
            )),
            Ok(Value::from(true))
        );
        // A in B, where actually B in A
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("parent")),
                Expr::val(EntityUID::with_eid("child"))
            )),
            Ok(Value::from(false))
        );
        // A in B, where actually A is a grandchild of B
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::val(EntityUID::with_eid("grandparent"))
            )),
            Ok(Value::from(true))
        );
        // A in B, where A doesn't exist but B does
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("doesnotexist")),
                Expr::val(EntityUID::with_eid("parent"))
            )),
            Ok(Value::from(false))
        );
        // A in B, where B doesn't exist but A does
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("parent")),
                Expr::val(EntityUID::with_eid("doesnotexist"))
            )),
            Ok(Value::from(false))
        );
        // A in [B, C] where A in B but not A in C
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("grandparent")),
                    Expr::val(EntityUID::with_eid("sibling")),
                ])
            )),
            Ok(Value::from(true))
        );
        // A in [B, C] where A in C but not A in B
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("sibling")),
                    Expr::val(EntityUID::with_eid("grandparent")),
                ])
            )),
            Ok(Value::from(true))
        );
        // A in [B, C] where A is in neither B nor C
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("sibling")),
                    Expr::val(EntityUID::with_eid("unrelated")),
                ])
            )),
            Ok(Value::from(false))
        );
        // A in [A, B] where B is unrelated
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("unrelated")),
                    Expr::val(EntityUID::with_eid("child")),
                ])
            )),
            Ok(Value::from(true))
        );
        // A in [B, A] where B is unrelated
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("child")),
                    Expr::val(EntityUID::with_eid("unrelated")),
                ])
            )),
            Ok(Value::from(true))
        );
        // A in [A, true]
        assert_matches!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("child")),
                    Expr::val(true),
                ])
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::entity_type(
                    Name::parse_unqualified_name("any_entity_type")
                        .expect("should be a valid identifier")
                )]);
                assert_eq!(actual, Type::Bool);
                assert_eq!(advice, None);
            }
        );
        // A in [A, B] where A and B do not exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("doesnotexistA")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("doesnotexistA")),
                    Expr::val(EntityUID::with_eid("doesnotexistB")),
                ])
            )),
            Ok(Value::from(true))
        );
        // A in [B, C] where none of A, B, or C exist
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("doesnotexistA")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("doesnotexistB")),
                    Expr::val(EntityUID::with_eid("doesnotexistC")),
                ])
            )),
            Ok(Value::from(false))
        );
        // A in [B, C] where B and C do not exist but A does
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("doesnotexistB")),
                    Expr::val(EntityUID::with_eid("doesnotexistC")),
                ])
            )),
            Ok(Value::from(false))
        );
        // A in [B, C] where B and C exist but A does not
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("doesnotexistA")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("child")),
                    Expr::val(EntityUID::with_eid("grandparent")),
                ])
            )),
            Ok(Value::from(false))
        );
        // "foo" in "foobar"
        assert_matches!(
            eval.interpret_inline_policy(&Expr::is_in(Expr::val("foo"), Expr::val("foobar"))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::entity_type(
                    Name::parse_unqualified_name("any_entity_type")
                        .expect("should be a valid identifier")
                )]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );
        // "spoon" in A (where has(A.spoon))
        assert_matches!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val("spoon"),
                Expr::val(EntityUID::with_eid("entity_with_attrs"))
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::entity_type(
                    Name::parse_unqualified_name("any_entity_type")
                        .expect("should be a valid identifier")
                )]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );
        // 3 in [34, -2, 7]
        assert_matches!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(3),
                Expr::set(vec![Expr::val(34), Expr::val(-2), Expr::val(7)])
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::entity_type(
                    Name::parse_unqualified_name("any_entity_type")
                        .expect("should be a valid identifier")
                )]);
                assert_eq!(actual, Type::Long);
                assert_eq!(advice, Some("`in` is for checking the entity hierarchy; use `.contains()` to test set membership".into()));
            }
        );
        // "foo" in { "foo": 2, "bar": true }
        assert_matches!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val("foo"),
                Expr::record(vec![
                    ("foo".into(), Expr::val(2)),
                    ("bar".into(), Expr::val(true)),
                ]).unwrap()
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::entity_type(
                    Name::parse_unqualified_name("any_entity_type")
                        .expect("should be a valid identifier")
                )]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, Some("`in` is for checking the entity hierarchy; use `has` to test if a record has a key".into()));
            }
        );
        // A in { "foo": 2, "bar": true }
        assert_matches!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("child")),
                Expr::record(vec![
                    ("foo".into(), Expr::val(2)),
                    ("bar".into(), Expr::val(true)),
                ])
                .unwrap()
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![
                    Type::Set,
                    Type::entity_type(
                        Name::parse_unqualified_name("any_entity_type")
                            .expect("should be a valid identifier")
                    )
                ]);
                assert_eq!(actual, Type::Record);
                assert_eq!(advice, None);
            }
        );
    }

    #[test]
    fn interpret_hierarchy_membership_slice() {
        // User::"Alice" in Group::"Friends".
        // Slice.attributes = {Alice},
        // Slice.hierarchy = {Alice, Group::Friends}
        // Should be allow under new semantics for "in"

        let request = Request::new(
            (EntityUID::with_eid("Alice"), None),
            (EntityUID::with_eid("test_action"), None),
            (EntityUID::with_eid("test_resource"), None),
            Context::empty(),
            Some(&RequestSchemaAllPass),
            Extensions::none(),
        )
        .unwrap();
        //Alice has parent "Friends" but we don't add "Friends" to the slice
        let mut alice = Entity::with_uid(EntityUID::with_eid("Alice"));
        let parent = Entity::with_uid(EntityUID::with_eid("Friends"));
        alice.add_ancestor(parent.uid().clone());
        let entities = Entities::from_entities(
            vec![alice],
            None::<&NoEntitiesSchema>,
            TCComputation::AssumeAlreadyComputed,
            Extensions::all_available(),
        )
        .expect("failed to create basic entities");
        let eval = Evaluator::new(request, &entities, Extensions::none());
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("Alice")),
                Expr::val(EntityUID::with_eid("Friends"))
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("Bob")),
                Expr::val(EntityUID::with_eid("Friends"))
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("Alice")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("Friends")),
                    Expr::val(EntityUID::with_eid("Bob"))
                ])
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_in(
                Expr::val(EntityUID::with_eid("Bob")),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("Friends")),
                    Expr::val(EntityUID::with_eid("Alice"))
                ])
            )),
            Ok(Value::from(false))
        );
    }

    #[test]
    fn interpret_string_like() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // "eggs" vs "ham"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs" like "ham*""#).expect("parsing error")
            ),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs" like "*ham""#).expect("parsing error")
            ),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs" like "*ham*""#).expect("parsing error")
            ),
            Ok(Value::from(false))
        );
        // "ham and eggs" vs "ham"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham and eggs" like "ham*""#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham and eggs" like "*ham""#).expect("parsing error")
            ),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham and eggs" like "*ham*""#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham and eggs" like "*h*a*m*""#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        // "eggs and ham" vs "ham"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs and ham" like "ham*""#).expect("parsing error")
            ),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs and ham" like "*ham""#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        // "eggs, ham, and spinach" vs "ham"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs, ham, and spinach" like "ham*""#).expect("parsing error")
            ),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs, ham, and spinach" like "*ham""#).expect("parsing error")
            ),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""eggs, ham, and spinach" like "*ham*""#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        // "Gotham" vs "ham"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""Gotham" like "ham*""#).expect("parsing error")
            ),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""Gotham" like "*ham""#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        // "ham" vs "ham"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham" like "ham""#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham" like "ham*""#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham" like "*ham""#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham" like "*h*a*m*""#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        // "ham and ham" vs "ham"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham and ham" like "ham*""#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham and ham" like "*ham""#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        // "ham" vs "ham and eggs"
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""ham" like "*ham and eggs*""#).expect("parsing error")
            ),
            Ok(Value::from(false))
        );
        // type error
        assert_matches!(
            eval.interpret_inline_policy(&Expr::like(Expr::val(354), Pattern::from(vec![]))),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::String]);
                assert_eq!(actual, Type::Long);
                assert_eq!(advice, None);
            }
        );
        // 'contains' is not allowed on strings
        assert_matches!(
            eval.interpret_inline_policy(&Expr::contains(
                Expr::val("ham and ham"),
                Expr::val("ham")
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Set]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );
        // '\0' should not match '*'
        assert_eq!(
            eval.interpret_inline_policy(&Expr::like(
                Expr::val("*"),
                Pattern::from(vec![PatternElem::Char('\u{0000}')])
            )),
            Ok(Value::from(false))
        );

        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"   "\\afterslash" like "\\*"   "#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
    }

    #[test]
    fn interpret_string_like_escaped_chars() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // testing like wth escaped characters -- similar tests are also in parser/convert.rs
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""string\\with\\backslashes" like "string\\with\\backslashes""#)
                    .expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(
                    r#""string\\with\\backslashes" like "string\u{0000}with\u{0000}backslashe""#
                )
                .expect("parsing error")
            ),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""string\\with\\backslashes" like "string*with*backslashes""#)
                    .expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""string*with*stars" like "string\*with\*stars""#)
                    .expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        assert_eq!(eval.interpret_inline_policy(&parse_expr(r#""string\\*with\\*backslashes\\*and\\*stars" like "string\\*with\\*backslashes\\*and\\*stars""#).expect("parsing error")), Ok(Value::from(true)));
    }

    #[test]
    fn interpret_is() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(&format!(
                    r#"principal is {}"#,
                    EntityUID::test_entity_type()
                ))
                .expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(&format!(
                    r#"principal is N::S::{}"#,
                    EntityUID::test_entity_type()
                ))
                .expect("parsing error")
            ),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"User::"alice" is User"#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"User::"alice" is Group"#).expect("parsing error")
            ),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"N::S::User::"alice" is N::S::User"#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#"N::S::User::"alice" is User"#).expect("parsing error")
            ),
            Ok(Value::from(false))
        );
        assert_matches!(
            eval.interpret_inline_policy(&parse_expr(r#"1 is Group"#).expect("parsing error")),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::entity_type(names::ANY_ENTITY_TYPE.clone())]);
                assert_eq!(actual, Type::Long);
                assert_eq!(advice, None);
            }
        );
    }

    #[test]
    fn interpret_is_empty() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        // [].isEmpty()
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_empty(Expr::set([]),)),
            Ok(Value::from(true))
        );
        // [1].isEmpty()
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_empty(Expr::set(vec![Expr::val(1)]),)),
            Ok(Value::from(false))
        );
        // [false].isEmpty()
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_empty(Expr::set(vec![Expr::val(false)]),)),
            Ok(Value::from(false))
        );
        // [1,2,3,4,5,User::"alice"].isEmpty()
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_empty(Expr::set(vec![
                Expr::val(1),
                Expr::val(2),
                Expr::val(3),
                Expr::val(4),
                Expr::val(5),
                Expr::val(EntityUID::with_eid("jane"))
            ]))),
            Ok(Value::from(false))
        );
        // 0.isEmpty()
        assert_matches!(
            eval.interpret_inline_policy(&Expr::is_empty(
                Expr::val(0)
            )),
            Err(e) => {
                expect_err(
                    "",
                    &miette::Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type error: expected set, got long").build(),
                );
            }
        );
        // { foo: [] }.isEmpty()
        assert_matches!(
            eval.interpret_inline_policy(&Expr::is_empty(
                Expr::record([
                    ("foo".into(), Expr::set([]))
                ]).unwrap()
            )),
            Err(e) => {
                expect_err(
                    "",
                    &miette::Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type error: expected set, got record").build(),
                );
            }
        );
    }

    #[test]
    fn interpret_contains_all_and_contains_any() {
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(request, &entities, Extensions::none());
        //  [1, -22, 34] containsall of [1, -22]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(1), Expr::val(-22), Expr::val(34)]),
                Expr::set(vec![Expr::val(1), Expr::val(-22)])
            )),
            Ok(Value::from(true))
        );
        // [1, -22, 34] containsall [-22, 1]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(1), Expr::val(-22), Expr::val(34)]),
                Expr::set(vec![Expr::val(-22), Expr::val(1)])
            )),
            Ok(Value::from(true))
        );
        // [1, -22, 34] containsall [-22]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(1), Expr::val(-22), Expr::val(34)]),
                Expr::set(vec![Expr::val(-22)])
            )),
            Ok(Value::from(true))
        );
        // [43, 34] containsall [34, 43]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(43), Expr::val(34)]),
                Expr::set(vec![Expr::val(34), Expr::val(43)])
            )),
            Ok(Value::from(true))
        );
        // [1, -2, 34] containsall [1, -22]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(1), Expr::val(-2), Expr::val(34)]),
                Expr::set(vec![Expr::val(1), Expr::val(-22)])
            )),
            Ok(Value::from(false))
        );
        // [1, 34] containsall [1, 101, 34]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(1), Expr::val(34)]),
                Expr::set(vec![Expr::val(1), Expr::val(101), Expr::val(34)])
            )),
            Ok(Value::from(false))
        );
        // [1, 34, 102] containsall [1, 101, 34]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(1), Expr::val(34), Expr::val(102)]),
                Expr::set(vec![Expr::val(1), Expr::val(101), Expr::val(34)])
            )),
            Ok(Value::from(false))
        );
        // [2, -7, 387] containsall [1, 101, 34]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(2), Expr::val(-7), Expr::val(387)]),
                Expr::set(vec![Expr::val(1), Expr::val(101), Expr::val(34)])
            )),
            Ok(Value::from(false))
        );
        // [2, 43] containsall []?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![Expr::val(2), Expr::val(43)]),
                Expr::set(vec![])
            )),
            Ok(Value::from(true))
        );
        // [] containsall [2, 43]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![]),
                Expr::set(vec![Expr::val(2), Expr::val(43)])
            )),
            Ok(Value::from(false))
        );
        // [<entity bar>, <entity foo>] containsall [<entity foo>]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("bar")),
                    Expr::val(EntityUID::with_eid("foo"))
                ]),
                Expr::set(vec![Expr::val(EntityUID::with_eid("foo"))])
            )),
            Ok(Value::from(true))
        );
        // [false, 3, [47, 0], {"2": "ham"}] containsall [3, {"2": "ham"}]?
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::set(vec![
                    Expr::val(false),
                    Expr::val(3),
                    Expr::set(vec![Expr::val(47), Expr::val(0)]),
                    Expr::record(vec![("2".into(), Expr::val("ham"))]).unwrap()
                ]),
                Expr::set(vec![
                    Expr::val(3),
                    Expr::record(vec![("2".into(), Expr::val("ham"))]).unwrap()
                ])
            )),
            Ok(Value::from(true))
        );
        //  "ham and eggs" containsall "ham"?
        assert_matches!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::val("ham"),
                Expr::val("ham and eggs")
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Set]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );
        // {"2": "ham", "3": "eggs"} containsall {"2": "ham"} ?
        assert_matches!(
            eval.interpret_inline_policy(&Expr::contains_all(
                Expr::record(vec![("2".into(), Expr::val("ham"))]).unwrap(),
                Expr::record(vec![
                    ("2".into(), Expr::val("ham")),
                    ("3".into(), Expr::val("eggs"))
                ])
                .unwrap()
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Set]);
                assert_eq!(actual, Type::Record);
                assert_eq!(advice, None);
            }
        );
        // test for [1, -22] contains_any of [1, -22, 34]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![Expr::val(1), Expr::val(-22)]),
                Expr::set(vec![Expr::val(1), Expr::val(-22), Expr::val(34)])
            )),
            Ok(Value::from(true))
        );
        // test for [1, -22, 34] contains_any of [1, -22]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![Expr::val(1), Expr::val(-22), Expr::val(34)]),
                Expr::set(vec![Expr::val(1), Expr::val(-22)])
            )),
            Ok(Value::from(true))
        );
        // test for [-22] contains_any of [1, -22, 34]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![Expr::val(-22)]),
                Expr::set(vec![Expr::val(1), Expr::val(-22), Expr::val(34)])
            )),
            Ok(Value::from(true))
        );
        // test for [1, 101] contains_any of [1, -22, 34]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![Expr::val(1), Expr::val(101)]),
                Expr::set(vec![Expr::val(1), Expr::val(-22), Expr::val(34)])
            )),
            Ok(Value::from(true))
        );
        // test for [1, 101] contains_any of [-22, 34]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![Expr::val(1), Expr::val(101)]),
                Expr::set(vec![Expr::val(-22), Expr::val(34)])
            )),
            Ok(Value::from(false))
        );
        // test for [] contains_any of [-22, 34]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![]),
                Expr::set(vec![Expr::val(-22), Expr::val(34)])
            )),
            Ok(Value::from(false))
        );
        // test for [-22, 34] contains_any of []
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![Expr::val(-22), Expr::val(34)]),
                Expr::set(vec![])
            )),
            Ok(Value::from(false))
        );
        // test for [<entity foo>, <entity bar>] contains_any of [<entity ham>, <entity eggs>]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("foo")),
                    Expr::val(EntityUID::with_eid("bar"))
                ]),
                Expr::set(vec![
                    Expr::val(EntityUID::with_eid("ham")),
                    Expr::val(EntityUID::with_eid("eggs"))
                ])
            )),
            Ok(Value::from(false))
        );
        // test for [3, {"2": "ham", "1": "eggs"}] contains_any of [7, false, [-22, true], {"1": "eggs", "2": "ham"}]
        assert_eq!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::set(vec![
                    Expr::val(3),
                    Expr::record(vec![
                        ("2".into(), Expr::val("ham")),
                        ("1".into(), Expr::val("eggs"))
                    ])
                    .unwrap()
                ]),
                Expr::set(vec![
                    Expr::val(7),
                    Expr::val(false),
                    Expr::set(vec![Expr::val(-22), Expr::val(true)]),
                    Expr::record(vec![
                        ("1".into(), Expr::val("eggs")),
                        ("2".into(), Expr::val("ham"))
                    ])
                    .unwrap()
                ])
            )),
            Ok(Value::from(true))
        );
        // test for "ham" contains_any of "ham and eggs"
        assert_matches!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::val("ham"),
                Expr::val("ham and eggs")
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Set]);
                assert_eq!(actual, Type::String);
                assert_eq!(advice, None);
            }
        );
        // test for {"2": "ham"} contains_any of {"2": "ham", "3": "eggs"}
        assert_matches!(
            eval.interpret_inline_policy(&Expr::contains_any(
                Expr::record(vec![("2".into(), Expr::val("ham"))]).unwrap(),
                Expr::record(vec![
                    ("2".into(), Expr::val("ham")),
                    ("3".into(), Expr::val("eggs"))
                ])
                .unwrap()
            )),
            Err(EvaluationError::TypeError(TypeError { expected, actual, advice, .. })) => {
                assert_eq!(expected, nonempty![Type::Set]);
                assert_eq!(actual, Type::Record);
                assert_eq!(advice, None);
            }
        );
    }

    #[test]
    fn eval_and_or() -> Result<()> {
        use crate::parser;
        let request = basic_request();
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::none(), TCComputation::ComputeNow);
        let entities = eparser.from_json_str("[]").expect("empty slice");
        let evaluator = Evaluator::new(request, &entities, Extensions::none());

        // short-circuit allows these to pass without error
        let raw_expr = "(false && 3)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Ok(_));

        let raw_expr = "(true || 3)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Ok(_));

        // short-circuit plus total equality allows these to pass without error
        let raw_expr = "(false && 3) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Ok(_));

        let raw_expr = "(true || 3) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Ok(_));

        let raw_expr = "(false && 3 && true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Ok(_));

        let raw_expr = "(true || 3 || true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Ok(_));

        // These must error
        let raw_expr = "(true && 3)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        let t = evaluator.interpret_inline_policy(&expr);
        println!("EXPR={:?}", t);
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(3 && true)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(3 && false)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(3 || true)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(3 || false)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(false || 3)";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(true && 3) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(3 && true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(3 && false) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(3 || true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(3 || false) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(false || 3) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(true && 3 && true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(3 && true && true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(3 && false && true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(3 || true || true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(3 || false || true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        let raw_expr = "(false || 3 || true) == 3";
        let expr = parser::parse_expr(raw_expr).expect("parse fail");
        assert_matches!(evaluator.interpret_inline_policy(&expr), Err(_));

        Ok(())
    }

    #[test]
    fn template_env_tests() {
        let request = basic_request();
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::none(), TCComputation::ComputeNow);
        let entities = eparser.from_json_str("[]").expect("empty slice");
        let evaluator = Evaluator::new(request, &entities, Extensions::none());
        let e = Expr::slot(SlotId::principal());

        let slots = HashMap::new();
        let r = evaluator.interpret(&e, &slots);
        assert_matches!(r, Err(EvaluationError::UnlinkedSlot(UnlinkedSlotError { slot, .. })) => {
            assert_eq!(slot, SlotId::principal());
        });

        let mut slots = HashMap::new();
        slots.insert(SlotId::principal(), EntityUID::with_eid("eid"));
        let r = evaluator.interpret(&e, &slots);
        assert_matches!(r, Ok(e) => {
            assert_eq!(
                e,
                Value::from(
                    EntityUID::with_eid("eid")
                )
            );
        });
    }

    #[test]
    fn template_interp() {
        let t = parse_policy_or_template(
            Some(PolicyID::from_string("template")),
            r#"permit(principal == ?principal, action, resource);"#,
        )
        .expect("Parse Error");
        let mut pset = PolicySet::new();
        pset.add_template(t)
            .expect("Template already present in PolicySet");
        let mut values = HashMap::new();
        values.insert(SlotId::principal(), EntityUID::with_eid("p"));
        pset.link(
            PolicyID::from_string("template"),
            PolicyID::from_string("instance"),
            values,
        )
        .expect("Linking failed!");
        let q = Request::new(
            (EntityUID::with_eid("p"), None),
            (EntityUID::with_eid("a"), None),
            (EntityUID::with_eid("r"), None),
            Context::empty(),
            Some(&RequestSchemaAllPass),
            Extensions::none(),
        )
        .unwrap();
        let eparser: EntityJsonParser<'_, '_> =
            EntityJsonParser::new(None, Extensions::none(), TCComputation::ComputeNow);
        let entities = eparser.from_json_str("[]").expect("empty slice");
        let eval = Evaluator::new(q, &entities, Extensions::none());

        let ir = pset.policies().next().expect("No linked policies");
        assert_matches!(eval.evaluate(ir), Ok(b) => {
            assert!(b, "Should be enforced");
        });
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_restricted_expression_error(e: Expr) {
        assert_matches!(
            BorrowedRestrictedExpr::new(&e),
            Err(RestrictedExpressionError::InvalidRestrictedExpression { .. })
        );
    }

    #[test]
    fn restricted_expressions() {
        let evaluator = RestrictedEvaluator::new(Extensions::all_available());

        // simple expressions
        assert_eq!(
            evaluator.partial_interpret(BorrowedRestrictedExpr::new(&Expr::val(true)).unwrap()),
            Ok(Value::from(true).into())
        );
        assert_eq!(
            evaluator.partial_interpret(BorrowedRestrictedExpr::new(&Expr::val(-2)).unwrap()),
            Ok(Value::from(-2).into())
        );
        assert_eq!(
            evaluator
                .partial_interpret(BorrowedRestrictedExpr::new(&Expr::val("hello world")).unwrap()),
            Ok(Value::from("hello world").into())
        );
        assert_eq!(
            evaluator.partial_interpret(
                BorrowedRestrictedExpr::new(&Expr::val(EntityUID::with_eid("alice"))).unwrap()
            ),
            Ok(Value::from(EntityUID::with_eid("alice")).into())
        );
        assert_restricted_expression_error(Expr::var(Var::Principal));
        assert_restricted_expression_error(Expr::var(Var::Action));
        assert_restricted_expression_error(Expr::var(Var::Resource));
        assert_restricted_expression_error(Expr::var(Var::Context));
        assert_restricted_expression_error(Expr::ite(Expr::val(true), Expr::val(7), Expr::val(12)));
        assert_restricted_expression_error(Expr::and(Expr::val("bogus"), Expr::val(true)));
        assert_restricted_expression_error(Expr::or(Expr::val("bogus"), Expr::val(true)));
        assert_restricted_expression_error(Expr::not(Expr::val(true)));
        assert_restricted_expression_error(Expr::is_in(
            Expr::val(EntityUID::with_eid("alice")),
            Expr::val(EntityUID::with_eid("some_group")),
        ));
        assert_restricted_expression_error(Expr::is_eq(
            Expr::val(EntityUID::with_eid("alice")),
            Expr::val(EntityUID::with_eid("some_group")),
        ));
        #[cfg(feature = "ipaddr")]
        assert_matches!(
            evaluator.partial_interpret(
                BorrowedRestrictedExpr::new(&Expr::call_extension_fn(
                    "ip".parse().expect("should be a valid Name"),
                    vec![Expr::val("222.222.222.222")]
                ))
                .unwrap()
            ),
            Ok(PartialValue::Value(Value {
                value: ValueKind::ExtensionValue(_),
                ..
            }))
        );
        assert_restricted_expression_error(Expr::get_attr(
            Expr::val(EntityUID::with_eid("alice")),
            "pancakes".into(),
        ));
        assert_restricted_expression_error(Expr::has_attr(
            Expr::val(EntityUID::with_eid("alice")),
            "pancakes".into(),
        ));
        assert_restricted_expression_error(Expr::like(
            Expr::val("abcdefg12"),
            Pattern::from(vec![
                PatternElem::Char('a'),
                PatternElem::Char('b'),
                PatternElem::Char('c'),
                PatternElem::Wildcard,
            ]),
        ));
        assert_matches!(
            evaluator.partial_interpret(
                BorrowedRestrictedExpr::new(&Expr::set([Expr::val("hi"), Expr::val("there")]))
                    .unwrap()
            ),
            Ok(PartialValue::Value(Value {
                value: ValueKind::Set(_),
                ..
            }))
        );
        assert_matches!(
            evaluator.partial_interpret(
                BorrowedRestrictedExpr::new(
                    &Expr::record([
                        ("hi".into(), Expr::val(1001)),
                        ("foo".into(), Expr::val("bar"))
                    ])
                    .unwrap()
                )
                .unwrap()
            ),
            Ok(PartialValue::Value(Value {
                value: ValueKind::Record(_),
                ..
            }))
        );

        // complex expressions -- for instance, violation not at top level
        assert_restricted_expression_error(Expr::set([
            Expr::val("hi"),
            Expr::and(Expr::val("bogus"), Expr::val(false)),
        ]));
        assert_restricted_expression_error(Expr::call_extension_fn(
            "ip".parse().expect("should be a valid Name"),
            vec![Expr::var(Var::Principal)],
        ));

        assert_restricted_expression_error(Expr::is_entity_type(
            Expr::val(EntityUID::with_eid("alice")),
            "User".parse().unwrap(),
        ));
    }

    pub(crate) fn empty_request() -> Request {
        let p: EntityUID = r#"p::"Principal""#.parse().unwrap();
        let a: EntityUID = r#"a::"Action""#.parse().unwrap();
        let r: EntityUID = r#"r::"Resource""#.parse().unwrap();
        let c = Context::empty();
        Request::new(
            (p, None),
            (a, None),
            (r, None),
            c,
            Some(&RequestSchemaAllPass),
            Extensions::none(),
        )
        .unwrap()
    }

    #[test]
    fn interpret_extended_has() {
        let es = Entities::new();
        let eval = Evaluator::new(empty_request(), &es, Extensions::none());
        assert_matches!(eval.interpret_inline_policy(&parse_expr(r#"
    {a: {b: {c: 1}}} has a.b.c
        "#).unwrap()), Ok(v) => {
            assert_eq!(v, Value::from(true));
        });
        assert_matches!(eval.interpret_inline_policy(&parse_expr(r#"
    {a: {b: {c: 1}}} has a.b
        "#).unwrap()), Ok(v) => {
            assert_eq!(v, Value::from(true));
        });
        assert_matches!(eval.interpret_inline_policy(&parse_expr(r#"
    {a: {b: {c: 1}}} has a
        "#).unwrap()), Ok(v) => {
            assert_eq!(v, Value::from(true));
        });
        assert_matches!(eval.interpret_inline_policy(&parse_expr(r#"
    {a: {b: {c: 1}}} has b.c
        "#).unwrap()), Ok(v) => {
            assert_eq!(v, Value::from(false));
        });
        assert_matches!(eval.interpret_inline_policy(&parse_expr(r#"
    {a: {b: {c: 1}}} has c
        "#).unwrap()), Ok(v) => {
            assert_eq!(v, Value::from(false));
        });
        assert_matches!(eval.interpret_inline_policy(&parse_expr(r#"
    {a: {b: {c: 1}}} has d
        "#).unwrap()), Ok(v) => {
            assert_eq!(v, Value::from(false));
        });
        assert_matches!(eval.interpret_inline_policy(&parse_expr(r#"
    {a: {b: {c: 1}}} has "🚫"
        "#).unwrap()), Ok(v) => {
            assert_eq!(v, Value::from(false));
        });

        assert_matches!(eval.interpret_inline_policy(&parse_expr(r#"
    {a: {b: {c: 1}}} has a.b.c && {a: {b: {c: 1}}}.a.b.c == 1
        "#).unwrap()), Ok(v) => {
            assert_eq!(v, Value::from(true));
        });
        assert_matches!(eval.interpret_inline_policy(&parse_expr(r#"
    {a: {b: {c: 1}}} has a.b && {a: {b: {c: 1}}}.a.b == {c: 1}
        "#).unwrap()), Ok(v) => {
            assert_eq!(v, Value::from(true));
        });
        assert_matches!(eval.interpret_inline_policy(&parse_expr(r#"
    {a: {b: {c: 1}}} has a && {a: {b: {c: 1}}}.a == {b: {c: 1}}
        "#).unwrap()), Ok(v) => {
            assert_eq!(v, Value::from(true));
        });
        assert_matches!(eval.interpret_inline_policy(&parse_expr(r#"
    {a: {b: {d: 1}}} has a.b.c && {a: {b: {d: 1}}}.a.b.c == 1
        "#).unwrap()), Ok(v) => {
            assert_eq!(v, Value::from(false));
        });

        assert_matches!(eval.interpret_inline_policy(&parse_expr(r#"
        {a: {b: {c: 1}}} has a.b && {a: {b: {c: 1}}}.a.b.d == 1
            "#).unwrap()), Err(EvaluationError::RecordAttrDoesNotExist(err)) => {
            assert_eq!(err.attr, "d");
        });
    }
}
