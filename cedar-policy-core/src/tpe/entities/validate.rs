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

use std::collections::HashSet;

use smol_str::SmolStr;

use crate::ast::{EntityUID, RestrictedExpr, Value, ValueKind};
use crate::entities::conformance::{
    err, err::EntitySchemaConformanceError, err::UnexpectedEntityTypeError, validate_euid,
    validate_euids_in_partial_value, EntitySchemaConformanceChecker, TypecheckError,
};
use crate::entities::{EntityTypeDescription, Schema, SchemaType};
use crate::extensions::Extensions;
use crate::tpe::{
    entities::PartialEntity,
    err::{EntityValidationError, MismatchedActionAncestorsError, UnknownActionComponentError},
    value::{PartialAttribute, PartialRecord, PartialValue},
};
use crate::validator::{CoreSchema, ValidatorSchema};

#[cfg(test)]
mod test;

impl PartialEntity {
    /// Validate `self` according to `schema`.
    ///
    /// This mirrors the semantics of
    /// [`EntitySchemaConformanceChecker::validate_entity`] for complete
    /// entities, but applied to partial entities where attrs/tags/ancestors
    /// may be `None` (entirely unknown) or contain individual `Exists`
    /// attributes that are skipped during validation. All present data is
    /// validated.
    pub fn validate(
        &self,
        schema: &ValidatorSchema,
    ) -> std::result::Result<(), EntityValidationError> {
        let core_schema = CoreSchema::new(schema);
        let uid = &self.uid;
        let etype = uid.entity_type();

        if uid.is_action() {
            return self.validate_action(&core_schema);
        }

        validate_euid(&core_schema, uid).map_err(EntitySchemaConformanceError::from)?;
        let schema_etype = core_schema
            .entity_type(etype)
            .ok_or_else(|| {
                let suggested_types = core_schema
                    .entity_types_with_basename(&etype.name().basename())
                    .collect();
                UnexpectedEntityTypeError {
                    uid: uid.clone(),
                    suggested_types,
                }
            })
            .map_err(EntitySchemaConformanceError::from)?;
        let checker =
            EntitySchemaConformanceChecker::new(&core_schema, Extensions::all_available());
        if let Some(ancestors) = &self.ancestors {
            checker.validate_entity_ancestors(uid, ancestors.iter(), &schema_etype)?;
        }
        if let Some(attrs) = &self.attrs {
            validate_partial_record_as_attrs(attrs, uid, &schema_etype, &core_schema)?;
        }
        if let Some(tags) = &self.tags {
            validate_partial_record_as_tags(tags, uid, &schema_etype, &core_schema)?;
        }
        Ok(())
    }

    /// Validate an action entity. Actions require all components to be known.
    fn validate_action<S: Schema>(
        &self,
        core_schema: &S,
    ) -> std::result::Result<(), EntityValidationError> {
        let uid = &self.uid;

        if self.attrs.is_none() || self.tags.is_none() {
            return Err(UnknownActionComponentError {
                action: uid.clone(),
            }
            .into());
        }
        if let Some(attrs) = &self.attrs {
            if let Some((attr, _)) = attrs.first_key_value() {
                return Err(EntitySchemaConformanceError::unexpected_entity_attr(
                    uid.clone(),
                    attr.clone(),
                )
                .into());
            }
        }
        if let Some(tags) = &self.tags {
            if let Some((tag, _)) = tags.first_key_value() {
                return Err(EntitySchemaConformanceError::unexpected_entity_tag(
                    uid.clone(),
                    tag.clone(),
                )
                .into());
            }
        }
        if let Some(action) = core_schema.action(uid) {
            if let Some(ancestors) = &self.ancestors {
                let schema_ancestors: HashSet<EntityUID> = action.ancestors().cloned().collect();
                if &schema_ancestors != ancestors {
                    return Err(MismatchedActionAncestorsError {
                        action: uid.clone(),
                    }
                    .into());
                }
            } else {
                return Err(UnknownActionComponentError {
                    action: uid.clone(),
                }
                .into());
            }
        } else {
            return Err(EntitySchemaConformanceError::UndeclaredAction(
                crate::entities::conformance::err::UndeclaredAction { uid: uid.clone() },
            )
            .into());
        }
        Ok(())
    }
}

/// Typecheck a [`PartialValue`] against a [`SchemaType`].
///
/// This mirrors [`typecheck_restricted_expr_against_schematype`] but operates
/// on `PartialValue` directly, recursing into records and skipping `Exists`
/// attributes while validating all `Value` data.
///
/// For non-record types (`Lit`, `Set`, `ExtensionValue`), the value is fully
/// concrete so we convert to `ast::PartialValue` and delegate to the existing
/// typechecker. For `Record`, we recurse manually to handle `Exists` fields.
pub(crate) fn typecheck_partial_value(
    val: &PartialValue,
    expected_ty: &SchemaType,
    extensions: &Extensions<'_>,
) -> Result<(), TypecheckError> {
    match val {
        PartialValue::Record(rec) => {
            match expected_ty {
                SchemaType::Record { attrs, open_attrs } => {
                    // TPE's partial-record reductions assume records are
                    // closed: an attribute a record value does not list and the
                    // type does not declare is treated as `Absent` (folding
                    // `has` to false and access to an error). For an open record
                    // an undeclared attribute could still be present at runtime,
                    // so that fold would be unsound. Open record types cannot
                    // arise without the `partial-validate` feature, which is
                    // independent of `tpe`; reject one here rather than silently
                    // mis-evaluate against it. Reported as a type mismatch: the
                    // partial value's type does not conform to the closed type
                    // TPE requires.
                    if *open_attrs {
                        return Err(
                            crate::entities::json::err::TypeMismatchError::type_mismatch(
                                expected_ty.clone(),
                                None,
                                mismatched_val(val, expected_ty),
                            )
                            .into(),
                        );
                    }
                    // Validate schema-declared attributes
                    for (k, v) in attrs {
                        match rec.get(k) {
                            // Not in map: unknown whether it exists, skip
                            None => {}
                            // Absent: definitively not present. Error if required.
                            Some(PartialAttribute::Absent) => {
                                if v.required {
                                    return Err(
                                        crate::entities::json::err::TypeMismatchError::missing_required_attr(
                                            expected_ty.clone(),
                                            k.clone(),
                                            mismatched_val(val, expected_ty),
                                        )
                                        .into(),
                                    );
                                }
                            }
                            // Exists: exists but value unknown, skip typecheck
                            Some(PartialAttribute::Exists) => {}
                            // Value: validate the value
                            Some(PartialAttribute::Value(inner)) => {
                                typecheck_partial_value(inner, &v.attr_type, extensions)?;
                            }
                        }
                    }
                    // Check for unexpected attrs. Value and Exists mean
                    // the attr exists — error if not in schema. Absent means
                    // it doesn't exist — fine.
                    if !open_attrs {
                        for (k, partial_attr) in rec.iter() {
                            if matches!(partial_attr, PartialAttribute::Absent) {
                                continue;
                            }
                            if attrs.get(k).is_none() {
                                return Err(
                                    crate::entities::json::err::TypeMismatchError::unexpected_attr(
                                        expected_ty.clone(),
                                        k.clone(),
                                        mismatched_val(val, expected_ty),
                                    )
                                    .into(),
                                );
                            }
                        }
                    }
                    Ok(())
                }
                // Expected a non-record type but got a record.
                _ => Err(
                    crate::entities::json::err::TypeMismatchError::type_mismatch(
                        expected_ty.clone(),
                        None,
                        mismatched_val(val, expected_ty),
                    )
                    .into(),
                ),
            }
        }
        // Non-record types hold no partial state, so each converts with no
        // fallible step. Delegate to the existing typechecker.
        PartialValue::Lit(lit) => {
            typecheck_concrete(Value::new(lit.clone(), None), expected_ty, extensions)
        }
        PartialValue::Set(set) => typecheck_concrete(
            Value {
                value: ValueKind::Set(set.clone()),
                loc: None,
            },
            expected_ty,
            extensions,
        ),
        PartialValue::ExtensionValue(ext) => typecheck_concrete(
            Value {
                value: ValueKind::ExtensionValue(ext.clone()),
                loc: None,
            },
            expected_ty,
            extensions,
        ),
    }
}

/// TODO: fix error on partial values
fn mismatched_val(val: &PartialValue, expected_ty: &SchemaType) -> RestrictedExpr {
    let concrete = val
        .try_into_value(expected_ty)
        .unwrap_or_else(|| Value::record(std::iter::empty::<(SmolStr, Value)>(), None));
    RestrictedExpr::from(concrete)
}

/// Typecheck a fully concrete value against `expected_ty`.
fn typecheck_concrete(
    value: Value,
    expected_ty: &SchemaType,
    extensions: &Extensions<'_>,
) -> Result<(), TypecheckError> {
    crate::entities::conformance::typecheck_value_against_schematype(
        &crate::ast::PartialValue::from(value),
        expected_ty,
        extensions,
    )
}

/// Validate a [`PartialRecord`] as entity attributes against the schema.
///
/// Mirrors [`EntitySchemaConformanceChecker::validate_entity_attributes`]:
/// - Checks all required attributes are present (or `Exists`)
/// - For each `Value` attribute, typechecks against the schema and validates EUIDs
/// - `Exists` attributes are skipped
fn validate_partial_record_as_attrs<S: Schema>(
    record: &PartialRecord,
    uid: &EntityUID,
    schema_etype: &impl EntityTypeDescription,
    schema: &S,
) -> Result<(), EntitySchemaConformanceError> {
    let extensions = Extensions::all_available();

    // Check required attributes:
    // - Not in map: unknown whether it exists, skip
    // - Absent: definitively missing, error
    // - Exists/Value: exists, satisfied
    for required_attr in schema_etype.required_attrs() {
        if matches!(record.get(&required_attr), Some(PartialAttribute::Absent)) {
            return Err(EntitySchemaConformanceError::missing_entity_attr(
                uid.clone(),
                required_attr,
            ));
        }
    }

    // Validate each attribute
    for (attr, partial_attr) in record.iter() {
        // Absent means the attr doesn't exist — nothing to validate
        if matches!(partial_attr, PartialAttribute::Absent) {
            continue;
        }

        // The attribute exists (Exists or Value) — check it's allowed
        match schema_etype.attr_type(attr) {
            None => {
                if !schema_etype.open_attributes() {
                    return Err(EntitySchemaConformanceError::unexpected_entity_attr(
                        uid.clone(),
                        attr.clone(),
                    ));
                }
            }
            Some(expected_ty) => {
                // Typecheck only if the value is present
                if let PartialAttribute::Value(val) = partial_attr {
                    match typecheck_partial_value(val, &expected_ty, extensions) {
                        Ok(()) => {}
                        Err(TypecheckError::TypeMismatch(e)) => {
                            return Err(EntitySchemaConformanceError::type_mismatch(
                                uid.clone(),
                                attr.clone(),
                                err::AttrOrTag::Attr,
                                e,
                            ));
                        }
                        Err(TypecheckError::ExtensionFunctionLookup(e)) => {
                            return Err(EntitySchemaConformanceError::extension_function_lookup(
                                uid.clone(),
                                attr.clone(),
                                err::AttrOrTag::Attr,
                                e,
                            ));
                        }
                    }
                }
            }
        }

        // Validate EUIDs in the known parts of the value. An attribute with no
        // declared type is rejected above, so `attr_type` is `Some` here.
        if let PartialAttribute::Value(val) = partial_attr {
            if let Some(attr_schema_ty) = schema_etype.attr_type(attr) {
                if let Some(concrete) = val.try_into_value(&attr_schema_ty) {
                    let ast_pv: crate::ast::PartialValue = concrete.into();
                    validate_euids_in_partial_value(schema, &ast_pv)?;
                }
            }
        }
    }
    Ok(())
}

/// Validate a [`PartialRecord`] as entity tags against the schema.
///
/// Mirrors [`EntitySchemaConformanceChecker::validate_tags`]:
/// - If schema says no tags allowed, errors on any present tag
/// - For each `Value` tag, typechecks against the schema tag type and validates EUIDs
/// - `Exists` tags are skipped
fn validate_partial_record_as_tags<S: Schema>(
    record: &PartialRecord,
    uid: &EntityUID,
    schema_etype: &impl EntityTypeDescription,
    schema: &S,
) -> Result<(), EntitySchemaConformanceError> {
    let extensions = Extensions::all_available();

    match schema_etype.tag_type() {
        None => {
            // No tags allowed — Value or Exists means the tag exists, error.
            // Absent means it doesn't exist, fine.
            for (tag, attr) in record.iter() {
                if !matches!(attr, PartialAttribute::Absent) {
                    return Err(EntitySchemaConformanceError::unexpected_entity_tag(
                        uid.clone(),
                        tag.clone(),
                    ));
                }
            }
        }
        Some(expected_ty) => {
            for (tag, partial_attr) in record.iter() {
                let val = match partial_attr {
                    PartialAttribute::Exists | PartialAttribute::Absent => continue,
                    PartialAttribute::Value(v) => v,
                };

                match typecheck_partial_value(val, &expected_ty, extensions) {
                    Ok(()) => {}
                    Err(TypecheckError::TypeMismatch(e)) => {
                        return Err(EntitySchemaConformanceError::type_mismatch(
                            uid.clone(),
                            tag.clone(),
                            err::AttrOrTag::Tag,
                            e,
                        ));
                    }
                    Err(TypecheckError::ExtensionFunctionLookup(e)) => {
                        return Err(EntitySchemaConformanceError::extension_function_lookup(
                            uid.clone(),
                            tag.clone(),
                            err::AttrOrTag::Tag,
                            e,
                        ));
                    }
                }

                if let Some(concrete) = val.try_into_value(&expected_ty) {
                    let ast_pv: crate::ast::PartialValue = concrete.into();
                    validate_euids_in_partial_value(schema, &ast_pv)?;
                }
            }
        }
    }
    Ok(())
}
