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

    /// Validate an action entity.
    ///
    /// Unlike other entities, an action's attributes, tags, and ancestors come from the schema
    /// rather than from request data, so they should all be concrete and exactly equal to the data
    /// in the schema.
    fn validate_action<S: Schema>(&self, core_schema: &S) -> Result<(), EntityValidationError> {
        let (Some(attrs), Some(ancestors), Some(tags)) = (&self.attrs, &self.ancestors, &self.tags)
        else {
            return Err(UnknownActionComponentError {
                action: (&self.uid).clone(),
            }
            .into());
        };
        let Some(action) = core_schema.action(&self.uid) else {
            return Err(
                EntitySchemaConformanceError::UndeclaredAction(UndeclaredAction {
                    uid: self.uid.clone(),
                })
                .into(),
            );
        };
        if let Some((attr, _)) = attrs.attrs().next() {
            return Err(EntitySchemaConformanceError::unexpected_entity_attr(
                self.uid.clone(),
                attr.clone(),
            )
            .into());
        }
        if let Some((tag, _)) = tags.attrs().next() {
            return Err(EntitySchemaConformanceError::unexpected_entity_tag(
                self.uid.clone(),
                tag.clone(),
            )
            .into());
        }
        let schema_ancestors: HashSet<EntityUID> = action.ancestors().cloned().collect();
        if &schema_ancestors != ancestors {
            return Err(MismatchedActionAncestorsError {
                action: self.uid.clone(),
            }
            .into());
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
                    // An attribute claimed to exist that the schema does not declare is unexpected.
                    if let Some((k, _)) = rec.attrs().find(|(k, v)| {
                        matches!(v, PartialAttribute::Value(_) | PartialAttribute::Exists)
                            && attrs.get(*k).is_none()
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

fn validate_partial_attr<S: Schema>(
    partial_val: &PartialAttribute,
    expected_ty: &SchemaType,
    uid: &EntityUID,
    key: &SmolStr,
    kind: AttrOrTag,
    schema: &S,
) -> Result<(), EntitySchemaConformanceError> {
    let Some(val) = partial_val.as_value() else {
        // non-value variant. Calling function checked that it's existence is valid given the
        // enclosing record type, so there's nothing else to do here.
        return Ok(());
    };
    match typecheck_partial_value(val, expected_ty, Extensions::all_available()) {
        Ok(()) => {}
        Err(TypecheckError::TypeMismatch(e)) => {
            return Err(EntitySchemaConformanceError::type_mismatch(
                uid.clone(),
                key.clone(),
                kind,
                e,
            ));
        }
        Err(TypecheckError::ExtensionFunctionLookup(e)) => {
            return Err(EntitySchemaConformanceError::extension_function_lookup(
                uid.clone(),
                key.clone(),
                kind,
                e,
            ));
        }
    }
    val.validate_euids(schema)?;
    Ok(())
}

/// Validate a `PartialRecord` as entity attributes against the schema.
fn validate_partial_record_as_attrs<S: Schema>(
    record: &PartialRecord,
    uid: &EntityUID,
    schema_etype: &impl EntityTypeDescription,
    schema: &S,
) -> Result<(), EntitySchemaConformanceError> {
    if let Some(absent) = schema_etype
        .required_attrs()
        .find(|attr| matches!(record.attr(&attr), PartialAttribute::Absent))
    {
        return Err(EntitySchemaConformanceError::missing_entity_attr(
            uid.clone(),
            absent,
        ));
    }

    for (attr, partial_val) in record.attrs() {
        if matches!(
            partial_val,
            PartialAttribute::Absent | PartialAttribute::Unknown
        ) {
            // `Absent` was already checked against the required attributes, and `Unknown` claims
            // nothing, so neither can conflict with what the schema declares.
            continue;
        }

        let Some(expected_ty) = schema_etype.attr_type(attr) else {
            return Err(EntitySchemaConformanceError::unexpected_entity_attr(
                uid.clone(),
                attr.clone(),
            ));
        };

        validate_partial_attr(
            partial_val,
            &expected_ty,
            uid,
            attr,
            AttrOrTag::Attr,
            schema,
        )?
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
    match schema_etype.tag_type() {
        None => {
            // No tags allowed, so a tag claimed to exist is an error
            if let Some((tag, _)) = record
                .attrs()
                .find(|(_, a)| matches!(a, PartialAttribute::Value(_) | PartialAttribute::Exists))
            {
                return Err(EntitySchemaConformanceError::unexpected_entity_tag(
                    uid.clone(),
                    tag.clone(),
                ));
            }
        }
        // Tags share one declared type and have no fixed key set, so any key is allowed and every
        // value is checked against the same type.
        Some(expected_ty) => {
            for (tag, partial_val) in record.attrs() {
                validate_partial_attr(partial_val, &expected_ty, uid, tag, AttrOrTag::Tag, schema)?;
            }
        }
    }
    Ok(())
}
