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

pub mod err;

use super::{json::err::TypeMismatchError, EntityTypeDescription, Schema, SchemaType};
use super::{Eid, EntityUID, ExprKind, Literal};
use crate::ast::{
    BorrowedRestrictedExpr, Entity, PartialValue, PartialValueToRestrictedExprError, RestrictedExpr,
};
use crate::extensions::{ExtensionFunctionLookupError, Extensions};
use err::{
    EntitySchemaConformanceError, InvalidEnumEntity, InvalidEnumEntityError, UndeclaredAction,
    UnexpectedEntityTypeError,
};
use miette::Diagnostic;
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

/// Struct used to check whether entities conform to a schema
#[derive(Debug, Clone)]
pub struct EntitySchemaConformanceChecker<'a, S> {
    /// Schema to check conformance with
    schema: &'a S,
    /// Extensions which are active for the conformance checks
    extensions: &'a Extensions<'a>,
}

impl<'a, S> EntitySchemaConformanceChecker<'a, S> {
    /// Create a new checker
    pub fn new(schema: &'a S, extensions: &'a Extensions<'a>) -> Self {
        Self { schema, extensions }
    }
}

impl<S: Schema> EntitySchemaConformanceChecker<'_, S> {
    /// Validate an action
    pub fn validate_action(&self, action: &Entity) -> Result<(), EntitySchemaConformanceError> {
        let uid = action.uid();
        let schema_action = self
            .schema
            .action(uid)
            .ok_or_else(|| EntitySchemaConformanceError::undeclared_action(uid.clone()))?;
        // check that the action exactly matches the schema's definition
        if !action.deep_eq(&schema_action) {
            return Err(EntitySchemaConformanceError::action_declaration_mismatch(
                uid.clone(),
            ));
        }
        Ok(())
    }

    /// Validate ancestors of an entity
    pub fn validate_entity_ancestors<'a>(
        &self,
        uid: &EntityUID,
        ancestors: impl Iterator<Item = &'a EntityUID>,
        schema_etype: &impl EntityTypeDescription,
    ) -> Result<(), EntitySchemaConformanceError> {
        // For each ancestor that actually appears in `entity`, ensure the
        // ancestor type is allowed by the schema
        for ancestor_euid in ancestors {
            validate_euid(self.schema, ancestor_euid)?;
            let ancestor_type = ancestor_euid.entity_type();
            if schema_etype.allowed_parent_types().contains(ancestor_type) {
                // note that `allowed_parent_types()` was transitively
                // closed, so it's actually `allowed_ancestor_types()`
                //
                // thus, the check passes in this case
            } else {
                return Err(EntitySchemaConformanceError::invalid_ancestor_type(
                    uid.clone(),
                    ancestor_type.clone(),
                ));
            }
        }
        Ok(())
    }

    /// Validate attributes of an entity
    pub fn validate_entity_attributes<'a>(
        &self,
        uid: &EntityUID,
        attrs: impl Iterator<Item = (&'a SmolStr, &'a PartialValue)>,
        schema_etype: &impl EntityTypeDescription,
    ) -> Result<(), EntitySchemaConformanceError> {
        let attrs: HashMap<&SmolStr, &PartialValue> = attrs.collect();
        // Ensure that all required attributes for `etype` are actually
        // included in `entity`
        for required_attr in schema_etype.required_attrs() {
            if !attrs.contains_key(&required_attr) {
                return Err(EntitySchemaConformanceError::missing_entity_attr(
                    uid.clone(),
                    required_attr,
                ));
            }
        }
        // For each attribute that actually appears in `entity`, ensure it
        // complies with the schema
        for (attr, val) in attrs {
            match schema_etype.attr_type(attr) {
                None => {
                    // `None` indicates the attribute shouldn't exist -- see
                    // docs on the `attr_type()` trait method
                    if !schema_etype.open_attributes() {
                        return Err(EntitySchemaConformanceError::unexpected_entity_attr(
                            uid.clone(),
                            attr.clone(),
                        ));
                    }
                }
                Some(expected_ty) => {
                    // typecheck: ensure that the entity attribute value matches
                    // the expected type
                    match typecheck_value_against_schematype(val, &expected_ty, self.extensions) {
                        Ok(()) => {} // typecheck passes
                        Err(TypecheckError::TypeMismatch(err)) => {
                            return Err(EntitySchemaConformanceError::type_mismatch(
                                uid.clone(),
                                attr.clone(),
                                err::AttrOrTag::Attr,
                                err,
                            ));
                        }
                        Err(TypecheckError::ExtensionFunctionLookup(err)) => {
                            return Err(EntitySchemaConformanceError::extension_function_lookup(
                                uid.clone(),
                                attr.clone(),
                                err::AttrOrTag::Attr,
                                err,
                            ));
                        }
                    };
                }
            }
            validate_euids_in_partial_value(self.schema, val)?;
        }
        Ok(())
    }

    /// Validate tags of an entity
    pub fn validate_tags<'a>(
        &self,
        uid: &EntityUID,
        tags: impl Iterator<Item = (&'a SmolStr, &'a PartialValue)>,
        schema_etype: &impl EntityTypeDescription,
    ) -> Result<(), EntitySchemaConformanceError> {
        let tags: HashMap<&SmolStr, &PartialValue> = tags.collect();
        match schema_etype.tag_type() {
            None => {
                if let Some((k, _)) = tags.iter().next() {
                    return Err(EntitySchemaConformanceError::unexpected_entity_tag(
                        uid.clone(),
                        k.to_string(),
                    ));
                }
            }
            Some(expected_ty) => {
                for (tag, val) in &tags {
                    match typecheck_value_against_schematype(val, &expected_ty, self.extensions) {
                        Ok(()) => {} // typecheck passes
                        Err(TypecheckError::TypeMismatch(err)) => {
                            return Err(EntitySchemaConformanceError::type_mismatch(
                                uid.clone(),
                                tag.to_string(),
                                err::AttrOrTag::Tag,
                                err,
                            ));
                        }
                        Err(TypecheckError::ExtensionFunctionLookup(err)) => {
                            return Err(EntitySchemaConformanceError::extension_function_lookup(
                                uid.clone(),
                                tag.to_string(),
                                err::AttrOrTag::Tag,
                                err,
                            ));
                        }
                    }
                }
            }
        }
        for val in tags.values() {
            validate_euids_in_partial_value(self.schema, val)?;
        }
        Ok(())
    }

    /// Validate an entity against the schema, returning an
    /// [`EntitySchemaConformanceError`] if it does not comply.
    pub fn validate_entity(&self, entity: &Entity) -> Result<(), EntitySchemaConformanceError> {
        let uid = entity.uid();
        let etype = uid.entity_type();
        if etype.is_action() {
            self.validate_action(entity)?;
        } else {
            let schema_etype = self.schema.entity_type(etype).ok_or_else(|| {
                let suggested_types = self
                    .schema
                    .entity_types_with_basename(&etype.name().basename())
                    .collect();
                UnexpectedEntityTypeError {
                    uid: uid.clone(),
                    suggested_types,
                }
            })?;

            validate_euid(self.schema, uid)?;
            self.validate_entity_attributes(uid, entity.attrs(), &schema_etype)?;
            self.validate_entity_ancestors(uid, entity.ancestors(), &schema_etype)?;
            self.validate_tags(uid, entity.tags(), &schema_etype)?;
        }
        Ok(())
    }
}

/// Return an [`InvalidEnumEntityError`] if `uid`'s eid is not among valid `choices`
pub fn is_valid_enumerated_entity(
    choices: &[Eid],
    uid: &EntityUID,
) -> Result<(), InvalidEnumEntityError> {
    choices
        .iter()
        .find(|id| uid.eid() == *id)
        .ok_or_else(|| InvalidEnumEntityError {
            uid: uid.clone(),
            choices: choices.to_vec(),
        })
        .map(|_| ())
}

/// Errors returned from `validate_euid()` and friends
///
/// This is NOT a publicly exported error type.
#[derive(Debug, Error, Diagnostic)]
pub enum ValidateEuidError {
    /// EUID's type is an enum type, but its value is not one of the declared enum values
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidEnumEntity(#[from] InvalidEnumEntityError),
    /// EUID's type is an action type, but it is not one of the declared actions
    #[error(transparent)]
    #[diagnostic(transparent)]
    UndeclaredAction(#[from] UndeclaredAction),
}

impl From<ValidateEuidError> for EntitySchemaConformanceError {
    fn from(e: ValidateEuidError) -> Self {
        match e {
            ValidateEuidError::InvalidEnumEntity(e) => InvalidEnumEntity::from(e).into(),
            ValidateEuidError::UndeclaredAction(e) => e.into(),
        }
    }
}

/// Validate if `euid` is valid
///
/// As of this writing, the only ways for an `euid` to be invalid are if it is
/// of enumerated entity type or action type, in which case it needs to have one
/// of the specific entity IDs declared in the schema.
pub fn validate_euid(schema: &impl Schema, euid: &EntityUID) -> Result<(), ValidateEuidError> {
    let entity_type = euid.entity_type();
    if let Some(desc) = schema.entity_type(entity_type) {
        if let Some(choices) = desc.enum_entity_eids() {
            is_valid_enumerated_entity(&Vec::from(choices), euid)?;
        }
    }
    if entity_type.is_action() && schema.action(euid).is_none() {
        return Err(ValidateEuidError::UndeclaredAction(UndeclaredAction {
            uid: euid.clone(),
        }));
    }
    Ok(())
}

fn validate_euids_in_subexpressions<'a>(
    exprs: impl IntoIterator<Item = &'a crate::ast::Expr>,
    schema: &impl Schema,
) -> std::result::Result<(), ValidateEuidError> {
    exprs.into_iter().try_for_each(|e| match e.expr_kind() {
        ExprKind::Lit(Literal::EntityUID(euid)) => validate_euid(schema, euid.as_ref()),
        _ => Ok(()),
    })
}

/// Validate if enumerated entities and action UIDs in `val` are valid
pub fn validate_euids_in_partial_value(
    schema: &impl Schema,
    val: &PartialValue,
) -> Result<(), ValidateEuidError> {
    match val {
        PartialValue::Value(val) => validate_euids_in_subexpressions(
            RestrictedExpr::from(val.clone()).subexpressions(),
            schema,
        ),
        PartialValue::Residual(e) => validate_euids_in_subexpressions(e.subexpressions(), schema),
    }
}

/// Check whether the given `PartialValue` typechecks with the given `SchemaType`.
/// If the typecheck passes, return `Ok(())`.
/// If the typecheck fails, return an appropriate `Err`.
pub fn typecheck_value_against_schematype(
    value: &PartialValue,
    expected_ty: &SchemaType,
    extensions: &Extensions<'_>,
) -> Result<(), TypecheckError> {
    match RestrictedExpr::try_from(value.clone()) {
        Ok(expr) => typecheck_restricted_expr_against_schematype(
            expr.as_borrowed(),
            expected_ty,
            extensions,
        ),
        Err(PartialValueToRestrictedExprError::NontrivialResidual { .. }) => {
            // this case should be unreachable for the case of `PartialValue`s
            // which are entity attributes, because a `PartialValue` computed
            // from a `RestrictedExpr` should only have trivial residuals.
            // And as of this writing, there are no callers of this function that
            // pass anything other than entity attributes.
            // Nonetheless, rather than relying on these delicate invariants,
            // it's safe to consider this as passing.
            Ok(())
        }
    }
}

/// Check whether the given `RestrictedExpr` is a valid instance of
/// `SchemaType`.  We do not have type information for unknowns, so this
/// function liberally treats unknowns as implementing any schema type.  If the
/// typecheck passes, return `Ok(())`.  If the typecheck fails, return an
/// appropriate `Err`.
pub fn typecheck_restricted_expr_against_schematype(
    expr: BorrowedRestrictedExpr<'_>,
    expected_ty: &SchemaType,
    extensions: &Extensions<'_>,
) -> Result<(), TypecheckError> {
    use SchemaType::*;
    let type_mismatch_err = || {
        Err(TypeMismatchError::type_mismatch(
            expected_ty.clone(),
            expr.try_type_of(extensions),
            expr.to_owned(),
        )
        .into())
    };

    match expr.expr_kind() {
        // Check for `unknowns`.  Unless explicitly annotated, we don't have the
        // information to know whether the unknown value matches the expected type.
        // For now we consider this as passing -- we can't really report a type
        // error <https://github.com/cedar-policy/cedar/issues/418>.
        ExprKind::Unknown(u) => match u.type_annotation.clone().and_then(SchemaType::from_ty) {
            Some(ty) => {
                if &ty == expected_ty {
                    return Ok(());
                } else {
                    return type_mismatch_err();
                }
            }
            None => return Ok(()),
        },
        // Check for extension function calls. Restricted expressions permit all
        // extension function calls, including those that aren't constructors.
        // Checking the return type here before matching on the expected type lets
        // us handle extension functions that return, e.g., bool and not an extension type.
        ExprKind::ExtensionFunctionApp { fn_name, .. } => {
            return match extensions.func(fn_name)?.return_type() {
                None => {
                    // This is actually another `unknown` case. The return type
                    // is `None` only when the function is an "unknown"
                    Ok(())
                }
                Some(rty) => {
                    if rty == expected_ty {
                        Ok(())
                    } else {
                        type_mismatch_err()
                    }
                }
            };
        }
        _ => (),
    };

    // We know `expr` is a restricted expression, so it must either be an
    // extension function call or a literal bool, long string, set or record.
    // This means we don't need to check if it's a `has` or `==` expression to
    // decide if it typechecks against `Bool`. Anything other an than a boolean
    // literal is an error. To handle extension function calls, which could
    // return `Bool`, we have already checked if the expression is an extension
    // function in the prior `match` expression.
    match expected_ty {
        Bool => {
            if expr.as_bool().is_some() {
                Ok(())
            } else {
                type_mismatch_err()
            }
        }
        Long => {
            if expr.as_long().is_some() {
                Ok(())
            } else {
                type_mismatch_err()
            }
        }
        String => {
            if expr.as_string().is_some() {
                Ok(())
            } else {
                type_mismatch_err()
            }
        }
        EmptySet => {
            if expr.as_set_elements().is_some_and(|e| e.count() == 0) {
                Ok(())
            } else {
                type_mismatch_err()
            }
        }
        Set { .. } if expr.as_set_elements().is_some_and(|e| e.count() == 0) => Ok(()),
        Set { element_ty: elty } => match expr.as_set_elements() {
            Some(mut els) => els.try_for_each(|e| {
                typecheck_restricted_expr_against_schematype(e, elty, extensions)
            }),
            None => type_mismatch_err(),
        },
        Record { attrs, open_attrs } => match expr.as_record_pairs() {
            Some(pairs) => {
                let pairs_map: BTreeMap<&SmolStr, BorrowedRestrictedExpr<'_>> = pairs.collect();
                // Check that all attributes required by the schema are present
                // in the record.
                attrs.iter().try_for_each(|(k, v)| {
                    if !v.required {
                        Ok(())
                    } else {
                        match pairs_map.get(k) {
                            Some(inner_e) => typecheck_restricted_expr_against_schematype(
                                *inner_e,
                                &v.attr_type,
                                extensions,
                            ),
                            None => Err(TypeMismatchError::missing_required_attr(
                                expected_ty.clone(),
                                k.clone(),
                                expr.to_owned(),
                            )
                            .into()),
                        }
                    }
                })?;
                // Check that all attributes in the record are present (as
                // required or optional) in the schema.
                pairs_map
                    .iter()
                    .try_for_each(|(k, inner_e)| match attrs.get(*k) {
                        Some(sch_ty) => typecheck_restricted_expr_against_schematype(
                            *inner_e,
                            &sch_ty.attr_type,
                            extensions,
                        ),
                        None => {
                            if *open_attrs {
                                Ok(())
                            } else {
                                Err(TypeMismatchError::unexpected_attr(
                                    expected_ty.clone(),
                                    (*k).clone(),
                                    expr.to_owned(),
                                )
                                .into())
                            }
                        }
                    })?;
                Ok(())
            }
            None => type_mismatch_err(),
        },
        // Extension functions are handled by the first `match` in this function.
        Extension { .. } => type_mismatch_err(),
        Entity { ty } => match expr.as_euid() {
            Some(actual_euid) if actual_euid.entity_type() == ty => Ok(()),
            _ => type_mismatch_err(),
        },
    }
}

/// Errors returned by [`typecheck_value_against_schematype()`] and
/// [`typecheck_restricted_expr_against_schematype()`]
#[derive(Debug, Diagnostic, Error)]
pub enum TypecheckError {
    /// The given value had a type different than what was expected
    #[error(transparent)]
    #[diagnostic(transparent)]
    TypeMismatch(#[from] TypeMismatchError),
    /// Error looking up an extension function. This error can occur when
    /// typechecking a `RestrictedExpr` because that may require getting
    /// information about any extension functions referenced in the
    /// `RestrictedExpr`; and it can occur when typechecking a `PartialValue`
    /// because that may require getting information about any extension
    /// functions referenced in residuals.
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExtensionFunctionLookup(#[from] ExtensionFunctionLookupError),
}

#[cfg(test)]
mod test_typecheck {
    use std::collections::BTreeMap;

    use cool_asserts::assert_matches;
    use miette::Report;
    use smol_str::ToSmolStr;

    use crate::{
        entities::{
            conformance::TypecheckError, AttributeType, BorrowedRestrictedExpr, Expr, SchemaType,
            Unknown,
        },
        extensions::Extensions,
        test_utils::{expect_err, ExpectedErrorMessageBuilder},
    };

    use super::typecheck_restricted_expr_against_schematype;

    #[test]
    fn unknown() {
        typecheck_restricted_expr_against_schematype(
            BorrowedRestrictedExpr::new(&Expr::unknown(Unknown::new_untyped("foo"))).unwrap(),
            &SchemaType::Bool,
            Extensions::all_available(),
        )
        .unwrap();
        typecheck_restricted_expr_against_schematype(
            BorrowedRestrictedExpr::new(&Expr::unknown(Unknown::new_untyped("foo"))).unwrap(),
            &SchemaType::String,
            Extensions::all_available(),
        )
        .unwrap();
        typecheck_restricted_expr_against_schematype(
            BorrowedRestrictedExpr::new(&Expr::unknown(Unknown::new_untyped("foo"))).unwrap(),
            &SchemaType::Set {
                element_ty: Box::new(SchemaType::Extension {
                    name: "decimal".parse().unwrap(),
                }),
            },
            Extensions::all_available(),
        )
        .unwrap();
    }

    #[test]
    fn bool() {
        typecheck_restricted_expr_against_schematype(
            BorrowedRestrictedExpr::new(&"false".parse().unwrap()).unwrap(),
            &SchemaType::Bool,
            Extensions::all_available(),
        )
        .unwrap();
    }

    #[test]
    fn bool_fails() {
        assert_matches!(
            typecheck_restricted_expr_against_schematype(
                BorrowedRestrictedExpr::new(&"1".parse().unwrap()).unwrap(),
                &SchemaType::Bool,
                Extensions::all_available(),
            ),
            Err(e@TypecheckError::TypeMismatch(_)) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type mismatch: value was expected to have type bool, but it actually has type long: `1`").build()
                );
            }
        )
    }

    #[test]
    fn long() {
        typecheck_restricted_expr_against_schematype(
            BorrowedRestrictedExpr::new(&"1".parse().unwrap()).unwrap(),
            &SchemaType::Long,
            Extensions::all_available(),
        )
        .unwrap();
    }

    #[test]
    fn long_fails() {
        assert_matches!(
            typecheck_restricted_expr_against_schematype(
                BorrowedRestrictedExpr::new(&"false".parse().unwrap()).unwrap(),
                &SchemaType::Long,
                Extensions::all_available(),
            ),
            Err(e@TypecheckError::TypeMismatch(_)) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type mismatch: value was expected to have type long, but it actually has type bool: `false`").build()
                );
            }
        )
    }

    #[test]
    fn string() {
        typecheck_restricted_expr_against_schematype(
            BorrowedRestrictedExpr::new(&r#""foo""#.parse().unwrap()).unwrap(),
            &SchemaType::String,
            Extensions::all_available(),
        )
        .unwrap();
    }

    #[test]
    fn string_fails() {
        assert_matches!(
            typecheck_restricted_expr_against_schematype(
                BorrowedRestrictedExpr::new(&"false".parse().unwrap()).unwrap(),
                &SchemaType::String,
                Extensions::all_available(),
            ),
            Err(e@TypecheckError::TypeMismatch(_)) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type mismatch: value was expected to have type string, but it actually has type bool: `false`").build()
                );
            }
        )
    }

    #[test]
    fn test_typecheck_set() {
        typecheck_restricted_expr_against_schematype(
            BorrowedRestrictedExpr::new(&"[1, 2, 3]".parse().unwrap()).unwrap(),
            &SchemaType::Set {
                element_ty: Box::new(SchemaType::Long),
            },
            Extensions::all_available(),
        )
        .unwrap();
        typecheck_restricted_expr_against_schematype(
            BorrowedRestrictedExpr::new(&"[]".parse().unwrap()).unwrap(),
            &SchemaType::Set {
                element_ty: Box::new(SchemaType::Bool),
            },
            Extensions::all_available(),
        )
        .unwrap();
    }

    #[test]
    fn test_typecheck_set_fails() {
        assert_matches!(
            typecheck_restricted_expr_against_schematype(
                BorrowedRestrictedExpr::new(&"{}".parse().unwrap()).unwrap(),
                &SchemaType::Set { element_ty: Box::new(SchemaType::String) },
                Extensions::all_available(),
            ),
            Err(e@TypecheckError::TypeMismatch(_)) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type mismatch: value was expected to have type [string], but it actually has type record: `{}`").build()
                );
            }
        );
        assert_matches!(
            typecheck_restricted_expr_against_schematype(
                BorrowedRestrictedExpr::new(&"[1, 2, 3]".parse().unwrap()).unwrap(),
                &SchemaType::Set { element_ty: Box::new(SchemaType::String) },
                Extensions::all_available(),
            ),
            Err(e@TypecheckError::TypeMismatch(_)) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type mismatch: value was expected to have type string, but it actually has type long: `1`").build()
                );
            }
        );
        assert_matches!(
            typecheck_restricted_expr_against_schematype(
                BorrowedRestrictedExpr::new(&"[1, true]".parse().unwrap()).unwrap(),
                &SchemaType::Set { element_ty: Box::new(SchemaType::Long) },
                Extensions::all_available(),
            ),
            Err(e@TypecheckError::TypeMismatch(_)) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type mismatch: value was expected to have type long, but it actually has type bool: `true`").build()
                );
            }
        )
    }

    #[test]
    fn test_typecheck_record() {
        typecheck_restricted_expr_against_schematype(
            BorrowedRestrictedExpr::new(&"{}".parse().unwrap()).unwrap(),
            &SchemaType::Record {
                attrs: BTreeMap::new(),
                open_attrs: false,
            },
            Extensions::all_available(),
        )
        .unwrap();
        typecheck_restricted_expr_against_schematype(
            BorrowedRestrictedExpr::new(&"{a: 1}".parse().unwrap()).unwrap(),
            &SchemaType::Record {
                attrs: BTreeMap::from([(
                    "a".to_smolstr(),
                    AttributeType {
                        attr_type: SchemaType::Long,
                        required: true,
                    },
                )]),
                open_attrs: false,
            },
            Extensions::all_available(),
        )
        .unwrap();
        typecheck_restricted_expr_against_schematype(
            BorrowedRestrictedExpr::new(&"{}".parse().unwrap()).unwrap(),
            &SchemaType::Record {
                attrs: BTreeMap::from([(
                    "a".to_smolstr(),
                    AttributeType {
                        attr_type: SchemaType::Long,
                        required: false,
                    },
                )]),
                open_attrs: false,
            },
            Extensions::all_available(),
        )
        .unwrap();
    }

    #[test]
    fn test_typecheck_record_fails() {
        assert_matches!(
            typecheck_restricted_expr_against_schematype(
                BorrowedRestrictedExpr::new(&"[]".parse().unwrap()).unwrap(),
                &SchemaType::Record { attrs: BTreeMap::from([]), open_attrs: false },
                Extensions::all_available(),
            ),
            Err(e@TypecheckError::TypeMismatch(_)) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type mismatch: value was expected to have type {  }, but it actually has type set: `[]`").build()
                );
            }
        );
        assert_matches!(
            typecheck_restricted_expr_against_schematype(
                BorrowedRestrictedExpr::new(&"{a: false}".parse().unwrap()).unwrap(),
                &SchemaType::Record { attrs: BTreeMap::from([("a".to_smolstr(), AttributeType { attr_type: SchemaType::Long, required: true })]), open_attrs: false },
                Extensions::all_available(),
            ),
            Err(e@TypecheckError::TypeMismatch(_)) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type mismatch: value was expected to have type long, but it actually has type bool: `false`").build()
                );
            }
        );
        assert_matches!(
            typecheck_restricted_expr_against_schematype(
                BorrowedRestrictedExpr::new(&"{a: {}}".parse().unwrap()).unwrap(),
                &SchemaType::Record { attrs: BTreeMap::from([("a".to_smolstr(), AttributeType { attr_type: SchemaType::Long, required: false })]), open_attrs: false },
                Extensions::all_available(),
            ),
            Err(e@TypecheckError::TypeMismatch(_)) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error("type mismatch: value was expected to have type long, but it actually has type record: `{}`").build()
                );
            }
        );
        assert_matches!(
            typecheck_restricted_expr_against_schematype(
                BorrowedRestrictedExpr::new(&"{}".parse().unwrap()).unwrap(),
                &SchemaType::Record { attrs: BTreeMap::from([("a".to_smolstr(), AttributeType { attr_type: SchemaType::Long, required: true })]), open_attrs: false },
                Extensions::all_available(),
            ),
            Err(e@TypecheckError::TypeMismatch(_)) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error(r#"type mismatch: value was expected to have type { "a" => (required) long }, but it is missing the required attribute `a`: `{}`"#).build()
                );
            }
        );
        assert_matches!(
            typecheck_restricted_expr_against_schematype(
                BorrowedRestrictedExpr::new(&"{a: 1, b: 1}".parse().unwrap()).unwrap(),
                &SchemaType::Record { attrs: BTreeMap::from([("a".to_smolstr(), AttributeType { attr_type: SchemaType::Long, required: true })]), open_attrs: false },
                Extensions::all_available(),
            ),
            Err(e@TypecheckError::TypeMismatch(_)) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error(r#"type mismatch: value was expected to have type { "a" => (required) long }, but it contains an unexpected attribute `b`: `{"a": 1, "b": 1}`"#).build()
                );
            }
        );
        assert_matches!(
            typecheck_restricted_expr_against_schematype(
                BorrowedRestrictedExpr::new(&"{b: 1}".parse().unwrap()).unwrap(),
                &SchemaType::Record { attrs: BTreeMap::from([("a".to_smolstr(), AttributeType { attr_type: SchemaType::Long, required: false })]), open_attrs: false },
                Extensions::all_available(),
            ),
            Err(e@TypecheckError::TypeMismatch(_)) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error(r#"type mismatch: value was expected to have type { "a" => (optional) long }, but it contains an unexpected attribute `b`: `{"b": 1}`"#).build()
                );
            }
        );
    }

    #[test]
    fn extension() {
        typecheck_restricted_expr_against_schematype(
            BorrowedRestrictedExpr::new(&r#"decimal("1.1")"#.parse().unwrap()).unwrap(),
            &SchemaType::Extension {
                name: "decimal".parse().unwrap(),
            },
            Extensions::all_available(),
        )
        .unwrap();
    }

    #[test]
    fn non_constructor_extension_function() {
        typecheck_restricted_expr_against_schematype(
            BorrowedRestrictedExpr::new(&r#"ip("127.0.0.1").isLoopback()"#.parse().unwrap())
                .unwrap(),
            &SchemaType::Bool,
            Extensions::all_available(),
        )
        .unwrap();
    }

    #[test]
    fn extension_fails() {
        assert_matches!(
            typecheck_restricted_expr_against_schematype(
                BorrowedRestrictedExpr::new(&r#"decimal("1.1")"#.parse().unwrap()).unwrap(),
                &SchemaType::Extension { name: "ipaddr".parse().unwrap() },
                Extensions::all_available(),
            ),
            Err(e@TypecheckError::TypeMismatch(_)) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error(r#"type mismatch: value was expected to have type ipaddr, but it actually has type decimal: `decimal("1.1")`"#).build()
                );
            }
        )
    }

    #[test]
    fn entity() {
        typecheck_restricted_expr_against_schematype(
            BorrowedRestrictedExpr::new(&r#"User::"alice""#.parse().unwrap()).unwrap(),
            &SchemaType::Entity {
                ty: "User".parse().unwrap(),
            },
            Extensions::all_available(),
        )
        .unwrap();
    }

    #[test]
    fn entity_fails() {
        assert_matches!(
            typecheck_restricted_expr_against_schematype(
                BorrowedRestrictedExpr::new(&r#"User::"alice""#.parse().unwrap()).unwrap(),
                &SchemaType::Entity { ty: "Photo".parse().unwrap() },
                Extensions::all_available(),
            ),
            Err(e@TypecheckError::TypeMismatch(_)) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error(r#"type mismatch: value was expected to have type `Photo`, but it actually has type (entity of type `User`): `User::"alice"`"#).build()
                );
            }
        )
    }
}
