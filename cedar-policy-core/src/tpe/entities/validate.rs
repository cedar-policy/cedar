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

use crate::ast::{EntityUID, RestrictedExpr, Value, ValueKind};
use crate::entities::conformance::err::{AttrOrTag, UndeclaredAction};
use crate::entities::conformance::typecheck_value_against_schematype;
use crate::entities::conformance::{
    err::EntitySchemaConformanceError, err::UnexpectedEntityTypeError, validate_euid,
    EntitySchemaConformanceChecker, TypecheckError,
};
use crate::entities::json::err::TypeMismatchError;
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
    /// This is like validating a concrete entity, except where [`typecheck_partial_value`] differs
    /// from normal typechecking
    pub fn validate(&self, schema: &ValidatorSchema) -> Result<(), EntityValidationError> {
        let schema = CoreSchema::new(schema);
        if self.uid.is_action() {
            return self.validate_action(&schema);
        }

        validate_euid(&schema, &self.uid).map_err(EntitySchemaConformanceError::from)?;
        let schema_etype = schema
            .entity_type(self.uid.entity_type())
            .ok_or_else(|| {
                let suggested_types = schema
                    .entity_types_with_basename(&self.uid.entity_type().name().basename())
                    .collect();
                UnexpectedEntityTypeError {
                    uid: self.uid.clone(),
                    suggested_types,
                }
            })
            .map_err(EntitySchemaConformanceError::from)?;
        let checker = EntitySchemaConformanceChecker::new(&schema, Extensions::all_available());
        if let Some(ancestors) = &self.ancestors {
            checker.validate_entity_ancestors(&self.uid, ancestors.iter(), &schema_etype)?;
        }
        if let Some(attrs) = &self.attrs {
            validate_partial_record_as_attrs(attrs, &self.uid, &schema_etype, &schema)?;
        }
        if let Some(tags) = &self.tags {
            validate_partial_record_as_tags(tags, &self.uid, &schema_etype, &schema)?;
        }
        Ok(())
    }

    /// Validate an action entity. Actions require all components to be known.
    fn validate_action<S: Schema>(&self, core_schema: &S) -> Result<(), EntityValidationError> {
        let uid = &self.uid;

        if self.attrs.is_none() || self.tags.is_none() {
            return Err(UnknownActionComponentError {
                action: uid.clone(),
            }
            .into());
        }
        if let Some((attr, _)) = self.attrs.as_ref().and_then(|attrs| attrs.attrs().next()) {
            return Err(EntitySchemaConformanceError::unexpected_entity_attr(
                uid.clone(),
                attr.clone(),
            )
            .into());
        }
        if let Some((tag, _)) = self.tags.as_ref().and_then(|tags| tags.attrs().next()) {
            return Err(EntitySchemaConformanceError::unexpected_entity_tag(
                uid.clone(),
                tag.clone(),
            )
            .into());
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
            return Err(
                EntitySchemaConformanceError::UndeclaredAction(UndeclaredAction {
                    uid: uid.clone(),
                })
                .into(),
            );
        }
        Ok(())
    }
}

/// Typecheck a `PartialValue` against a `SchemaType`
///
/// This is like normal value typechecking except for partial record values. If an attribute
/// value is known to exist (even if we don't know it's value), then the schema must allow it
/// to exist with some type. If the attribute is explicitly absent then the schema must not
/// require it. If the attribute is fully unknown, then it needs no validation.
pub(crate) fn typecheck_partial_value(
    val: &PartialValue,
    expected_ty: &SchemaType,
    extensions: &Extensions<'_>,
) -> Result<(), TypecheckError> {
    match val {
        PartialValue::Record(rec) => {
            // TODO: Return a new error type. `TypecheckError` carries a restricted
            // expression, but we want give it a `PartialValue`
            let bogus_actual_val = RestrictedExpr::val(false);
            match expected_ty {
                SchemaType::Record { attrs, .. } => {
                    // Validate schema-declared attributes
                    for (k, v) in attrs {
                        match rec.attr(k) {
                            PartialAttribute::Value(inner) => {
                                typecheck_partial_value(inner, &v.attr_type, extensions)?;
                            }
                            PartialAttribute::Absent => {
                                // Attribute is not present, so error if it's required
                                if v.required {
                                    return Err(TypeMismatchError::missing_required_attr(
                                        expected_ty.clone(),
                                        k.clone(),
                                        bogus_actual_val,
                                    )
                                    .into());
                                }
                            }
                            // Attribute is unknown, so nothing to do. In the `Exists` case, we know
                            // the attribute is allowed to exist because it is in the schema type.
                            PartialAttribute::Unknown | PartialAttribute::Exists => {}
                        }
                    }
                    // Any non-absent attribute that is not declared in the schema is unexpected.
                    if let Some((k, _)) = rec.attrs().find(|(k, v)| {
                        !matches!(v, PartialAttribute::Absent) && attrs.get(*k).is_none()
                    }) {
                        return Err(TypeMismatchError::unexpected_attr(
                            expected_ty.clone(),
                            k.clone(),
                            bogus_actual_val,
                        )
                        .into());
                    }
                    Ok(())
                }
                _ => Err(TypeMismatchError::type_mismatch(
                    expected_ty.clone(),
                    None,
                    bogus_actual_val,
                )
                .into()),
            }
        }
        // Non-record types hold no partial state, so we can delegate to the existing typechecker.
        PartialValue::Lit(lit) => typecheck_value_against_schematype(
            &Value::new(lit.clone(), None).into(),
            expected_ty,
            extensions,
        ),
        PartialValue::Set(set) => typecheck_value_against_schematype(
            &Value {
                value: ValueKind::Set(set.clone()),
                loc: None,
            }
            .into(),
            expected_ty,
            extensions,
        ),
        PartialValue::ExtensionValue(ext) => typecheck_value_against_schematype(
            &Value {
                value: ValueKind::ExtensionValue(ext.clone()),
                loc: None,
            }
            .into(),
            expected_ty,
            extensions,
        ),
    }
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
        if matches!(record.attr(&required_attr), PartialAttribute::Absent) {
            return Err(EntitySchemaConformanceError::missing_entity_attr(
                uid.clone(),
                required_attr,
            ));
        }
    }

    // Validate each attribute
    for (attr, partial_val) in record.attrs() {
        // Absent means the attr doesn't exist — nothing to validate
        if matches!(partial_val, PartialAttribute::Absent) {
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
                if let PartialAttribute::Value(val) = partial_val {
                    match typecheck_partial_value(val, &expected_ty, extensions) {
                        Ok(()) => {}
                        Err(TypecheckError::TypeMismatch(e)) => {
                            return Err(EntitySchemaConformanceError::type_mismatch(
                                uid.clone(),
                                attr.clone(),
                                AttrOrTag::Attr,
                                e,
                            ));
                        }
                        Err(TypecheckError::ExtensionFunctionLookup(e)) => {
                            return Err(EntitySchemaConformanceError::extension_function_lookup(
                                uid.clone(),
                                attr.clone(),
                                AttrOrTag::Attr,
                                e,
                            ));
                        }
                    }
                }
            }
        }

        if let PartialAttribute::Value(val) = partial_val {
            val.validate_euids(schema)?;
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
            for (tag, attr) in record.attrs() {
                if !matches!(attr, PartialAttribute::Absent) {
                    return Err(EntitySchemaConformanceError::unexpected_entity_tag(
                        uid.clone(),
                        tag.clone(),
                    ));
                }
            }
        }
        Some(expected_ty) => {
            for (tag, partial_val) in record.attrs() {
                let Some(partial_val) = partial_val.as_value() else {
                    continue;
                };

                match typecheck_partial_value(partial_val, &expected_ty, extensions) {
                    Ok(()) => {}
                    Err(TypecheckError::TypeMismatch(e)) => {
                        return Err(EntitySchemaConformanceError::type_mismatch(
                            uid.clone(),
                            tag.clone(),
                            AttrOrTag::Tag,
                            e,
                        ));
                    }
                    Err(TypecheckError::ExtensionFunctionLookup(e)) => {
                        return Err(EntitySchemaConformanceError::extension_function_lookup(
                            uid.clone(),
                            tag.clone(),
                            AttrOrTag::Tag,
                            e,
                        ));
                    }
                }

                partial_val.validate_euids(schema)?;
            }
        }
    }
    Ok(())
}
