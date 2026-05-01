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

use crate::ast::EntityUID;
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

impl PartialEntity {
    /// Validate `self` according to `schema`.
    ///
    /// This mirrors the semantics of
    /// [`EntitySchemaConformanceChecker::validate_entity`] for complete
    /// entities, but applied to partial entities where attrs/tags/ancestors
    /// may be `None` (entirely unknown) or contain individual `Unknown`
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
/// on `PartialValue` directly, recursing into records and skipping `Unknown`
/// attributes while validating all `Present` data.
///
/// For non-record types (`Lit`, `Set`, `ExtensionValue`), the value is fully
/// concrete so we convert to `ast::PartialValue` and delegate to the existing
/// typechecker. For `Record`, we recurse manually to handle `Unknown` fields.
pub(crate) fn typecheck_partial_value(
    val: &PartialValue,
    expected_ty: &SchemaType,
    extensions: &Extensions<'_>,
) -> Result<(), TypecheckError> {
    match val {
        PartialValue::Record(rec) => {
            match expected_ty {
                SchemaType::Record { attrs, open_attrs } => {
                    // Validate schema-declared attributes
                    for (k, v) in attrs {
                        match rec.get(k) {
                            // Not in map: unknown whether it exists, skip
                            None => {}
                            // Absent: definitively not present. Error if required.
                            Some(PartialAttribute::Absent) => {
                                if v.required {
                                    let expr = val
                                        .try_into_value(Some(expected_ty))
                                        .map(|v| crate::ast::RestrictedExpr::from(v).to_owned())
                                        .unwrap_or_else(|| "< partial record >".parse().unwrap());
                                    return Err(
                                        crate::entities::json::err::TypeMismatchError::missing_required_attr(
                                            expected_ty.clone(),
                                            k.clone(),
                                            expr,
                                        )
                                        .into(),
                                    );
                                }
                            }
                            // Unknown: exists but value unknown, skip typecheck
                            Some(PartialAttribute::Unknown) => {}
                            // Present: validate the value
                            Some(PartialAttribute::Present(inner)) => {
                                typecheck_partial_value(inner, &v.attr_type, extensions)?;
                            }
                        }
                    }
                    // Check for unexpected attrs. Present and Unknown mean
                    // the attr exists — error if not in schema. Absent means
                    // it doesn't exist — fine.
                    if !open_attrs {
                        for (k, partial_attr) in rec.iter() {
                            if matches!(partial_attr, PartialAttribute::Absent) {
                                continue;
                            }
                            if attrs.get(k).is_none() {
                                let expr = val
                                    .try_into_value(Some(expected_ty))
                                    .map(|v| crate::ast::RestrictedExpr::from(v).to_owned())
                                    .unwrap_or_else(|| "< partial record >".parse().unwrap());
                                return Err(
                                    crate::entities::json::err::TypeMismatchError::unexpected_attr(
                                        expected_ty.clone(),
                                        k.clone(),
                                        expr,
                                    )
                                    .into(),
                                );
                            }
                        }
                    }
                    Ok(())
                }
                _ => {
                    // Expected a non-record type but got a record — type error.
                    // We can't construct a perfect error expr, but this is
                    // always wrong regardless.
                    let expr = val
                        .try_into_value(Some(expected_ty))
                        .map(|v| crate::ast::RestrictedExpr::from(v).to_owned())
                        .unwrap_or_else(|| "< partial record >".parse().unwrap());
                    Err(
                        crate::entities::json::err::TypeMismatchError::type_mismatch(
                            expected_ty.clone(),
                            None,
                            expr,
                        )
                        .into(),
                    )
                }
            }
        }
        // Non-record types can't contain unknowns, so try_into_value always
        // succeeds. Delegate to the existing typechecker.
        _ => {
            let concrete: crate::ast::Value = val
                .try_into_value(Some(expected_ty))
                .expect("non-record PartialValue should always convert to Value");
            let ast_pv: crate::ast::PartialValue = concrete.into();
            crate::entities::conformance::typecheck_value_against_schematype(
                &ast_pv,
                expected_ty,
                extensions,
            )
        }
    }
}

/// Validate a [`PartialRecord`] as entity attributes against the schema.
///
/// Mirrors [`EntitySchemaConformanceChecker::validate_entity_attributes`]:
/// - Checks all required attributes are present (or `Unknown`)
/// - For each `Present` attribute, typechecks against the schema and validates EUIDs
/// - `Unknown` attributes are skipped
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
    // - Unknown/Present: exists, satisfied
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

        // The attribute exists (Unknown or Present) — check it's allowed
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
                if let PartialAttribute::Present(val) = partial_attr {
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

        // Validate EUIDs in concrete parts of the value
        if let PartialAttribute::Present(val) = partial_attr {
            let attr_schema_ty = schema_etype.attr_type(attr);
            if let Some(concrete) = val.try_into_value(attr_schema_ty.as_ref()) {
                let ast_pv: crate::ast::PartialValue = concrete.into();
                validate_euids_in_partial_value(schema, &ast_pv)?;
            }
        }
    }
    Ok(())
}

/// Validate a [`PartialRecord`] as entity tags against the schema.
///
/// Mirrors [`EntitySchemaConformanceChecker::validate_tags`]:
/// - If schema says no tags allowed, errors on any present tag
/// - For each `Present` tag, typechecks against the schema tag type and validates EUIDs
/// - `Unknown` tags are skipped
fn validate_partial_record_as_tags<S: Schema>(
    record: &PartialRecord,
    uid: &EntityUID,
    schema_etype: &impl EntityTypeDescription,
    schema: &S,
) -> Result<(), EntitySchemaConformanceError> {
    let extensions = Extensions::all_available();

    match schema_etype.tag_type() {
        None => {
            // No tags allowed — Present or Unknown means the tag exists, error.
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
                    PartialAttribute::Unknown | PartialAttribute::Absent => continue,
                    PartialAttribute::Present(v) => v,
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

                if let Some(concrete) = val.try_into_value(Some(&expected_ty)) {
                    let ast_pv: crate::ast::PartialValue = concrete.into();
                    validate_euids_in_partial_value(schema, &ast_pv)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "test_validate.rs"]
mod test_validate;
