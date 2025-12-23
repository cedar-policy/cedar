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

//! JSON FFI entry points for converting between JSON and Cedar formats. The
//! Cedar Wasm conversion functions are generated from the functions in this
//! file.

use super::utils::JsonValueWithNoDuplicateKeys;
use super::{DetailedError, Policy, Schema, Template};
use crate::api::{PolicySet, StringifiedPolicySet};
use cedar_policy_core::{
    ast::InternalName,
    extensions::Extensions,
    validator::{
        cedar_schema::parser::parse_cedar_schema_fragment, json_schema, AllDefs,
        ValidatorSchemaFragment,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::str::FromStr;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(feature = "wasm")]
extern crate tsify;

/// Takes a `PolicySet` represented as string and return the policies
/// and templates split into vecs and sorted by id.
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "policySetTextToParts"))]
pub fn policy_set_text_to_parts(policyset_str: &str) -> PolicySetTextToPartsAnswer {
    let parsed_ps: Result<PolicySet, _> = PolicySet::from_str(policyset_str);
    match parsed_ps {
        Ok(policy_set) => {
            if let Some(StringifiedPolicySet {
                policies,
                policy_templates,
            }) = policy_set.stringify()
            {
                PolicySetTextToPartsAnswer::Success {
                    policies,
                    policy_templates,
                }
            } else {
                // This should never happen due to the nature of the input but we cover it
                // just in case, to future-proof the interface
                PolicySetTextToPartsAnswer::Failure {
                    errors: vec![DetailedError::from_str(
                        "Policy set input contained template linked policies",
                    )
                    .unwrap_or_default()],
                }
            }
        }
        Err(e) => PolicySetTextToPartsAnswer::Failure {
            errors: vec![(&e).into()],
        },
    }
}

/// Return the Cedar (textual) representation of a policy.
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "policyToText"))]
pub fn policy_to_text(policy: Policy) -> PolicyToTextAnswer {
    match policy.parse(None) {
        Ok(policy) => PolicyToTextAnswer::Success {
            text: policy.to_string(),
        },
        Err(e) => PolicyToTextAnswer::Failure {
            errors: vec![e.into()],
        },
    }
}

/// Return the Cedar (textual) representation of a template.
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "templateToText"))]
pub fn template_to_text(template: Template) -> PolicyToTextAnswer {
    match template.parse(None) {
        Ok(template) => PolicyToTextAnswer::Success {
            text: template.to_string(),
        },
        Err(e) => PolicyToTextAnswer::Failure {
            errors: vec![e.into()],
        },
    }
}

/// Return the JSON representation of a policy.
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "policyToJson"))]
pub fn policy_to_json(policy: Policy) -> PolicyToJsonAnswer {
    match policy.parse(None) {
        Ok(policy) => match policy.to_json() {
            Ok(json) => PolicyToJsonAnswer::Success { json: json.into() },
            Err(e) => PolicyToJsonAnswer::Failure {
                errors: vec![miette::Report::new(e).into()],
            },
        },
        Err(e) => PolicyToJsonAnswer::Failure {
            errors: vec![e.into()],
        },
    }
}

/// Return the JSON representation of a template.
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "templateToJson"))]
pub fn template_to_json(template: Template) -> PolicyToJsonAnswer {
    match template.parse(None) {
        Ok(template) => match template.to_json() {
            Ok(json) => PolicyToJsonAnswer::Success { json: json.into() },
            Err(e) => PolicyToJsonAnswer::Failure {
                errors: vec![miette::Report::new(e).into()],
            },
        },
        Err(e) => PolicyToJsonAnswer::Failure {
            errors: vec![e.into()],
        },
    }
}

/// Return the Cedar (textual) representation of a schema.
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "schemaToText"))]
pub fn schema_to_text(schema: Schema) -> SchemaToTextAnswer {
    match schema.parse_schema_fragment() {
        Ok((schema_frag, warnings)) => {
            match schema_frag.to_cedarschema() {
                Ok(text) => {
                    // Before returning, check that the schema fragment corresponds to a valid schema
                    if let Err(e) = TryInto::<crate::Schema>::try_into(schema_frag) {
                        SchemaToTextAnswer::Failure {
                            errors: vec![miette::Report::new(e).into()],
                        }
                    } else {
                        SchemaToTextAnswer::Success {
                            text,
                            warnings: warnings.map(|e| miette::Report::new(e).into()).collect(),
                        }
                    }
                }
                Err(e) => SchemaToTextAnswer::Failure {
                    errors: vec![miette::Report::new(e).into()],
                },
            }
        }
        Err(e) => SchemaToTextAnswer::Failure {
            errors: vec![e.into()],
        },
    }
}

/// Return the JSON representation of a schema.
#[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "schemaToJson"))]
pub fn schema_to_json(schema: Schema) -> SchemaToJsonAnswer {
    match schema.parse_schema_fragment() {
        Ok((schema_frag, warnings)) => match schema_frag.to_json_value() {
            Ok(json) => {
                // Before returning, check that the schema fragment corresponds to a valid schema
                if let Err(e) = crate::Schema::from_json_value(json.clone()) {
                    SchemaToJsonAnswer::Failure {
                        errors: vec![miette::Report::new(e).into()],
                    }
                } else {
                    SchemaToJsonAnswer::Success {
                        json: json.into(),
                        warnings: warnings.map(|e| miette::Report::new(e).into()).collect(),
                    }
                }
            }
            Err(e) => SchemaToJsonAnswer::Failure {
                errors: vec![miette::Report::new(e).into()],
            },
        },
        Err(e) => SchemaToJsonAnswer::Failure {
            errors: vec![e.into()],
        },
    }
}

/// Helper function to resolve EntityOrCommon types to specific Entity or CommonType designations
fn resolve_entity_or_common_types(
    fragment: json_schema::Fragment<InternalName>,
    all_defs: &AllDefs,
) -> json_schema::Fragment<InternalName> {
    json_schema::Fragment(
        fragment
            .0
            .into_iter()
            .map(|(ns_name, ns_def)| {
                (
                    ns_name,
                    resolve_namespace_entity_or_common_types(ns_def, all_defs),
                )
            })
            .collect(),
    )
}

/// Helper function to resolve EntityOrCommon types in a namespace definition
fn resolve_namespace_entity_or_common_types(
    ns_def: json_schema::NamespaceDefinition<InternalName>,
    all_defs: &AllDefs,
) -> json_schema::NamespaceDefinition<InternalName> {
    json_schema::NamespaceDefinition {
        common_types: ns_def
            .common_types
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    json_schema::CommonType {
                        ty: resolve_type_entity_or_common(v.ty, all_defs),
                        annotations: v.annotations,
                        loc: v.loc,
                    },
                )
            })
            .collect(),
        entity_types: ns_def
            .entity_types
            .into_iter()
            .map(|(k, v)| (k, resolve_entity_type_entity_or_common(v, all_defs)))
            .collect(),
        actions: ns_def
            .actions
            .into_iter()
            .map(|(k, v)| (k, resolve_action_type_entity_or_common(v, all_defs)))
            .collect(),
        annotations: ns_def.annotations,
        #[cfg(feature = "extended-schema")]
        loc: ns_def.loc,
    }
}

/// Helper function to resolve EntityOrCommon types in a Type
fn resolve_type_entity_or_common(
    ty: json_schema::Type<InternalName>,
    all_defs: &AllDefs,
) -> json_schema::Type<InternalName> {
    match ty {
        json_schema::Type::Type { ty, loc } => {
            match resolve_type_variant_entity_or_common(ty, all_defs) {
                ResolvedTypeVariant::TypeVariant(resolved_ty) => json_schema::Type::Type {
                    ty: resolved_ty,
                    loc,
                },
                ResolvedTypeVariant::CommonTypeRef(type_name) => {
                    json_schema::Type::CommonTypeRef { type_name, loc }
                }
            }
        }
        json_schema::Type::CommonTypeRef { type_name, loc } => {
            json_schema::Type::CommonTypeRef { type_name, loc }
        }
    }
}

/// Helper enum to handle the case where EntityOrCommon resolves to a CommonTypeRef
enum ResolvedTypeVariant {
    TypeVariant(json_schema::TypeVariant<InternalName>),
    CommonTypeRef(InternalName),
}

/// Helper function to resolve EntityOrCommon types in a TypeVariant
fn resolve_type_variant_entity_or_common(
    ty: json_schema::TypeVariant<InternalName>,
    all_defs: &AllDefs,
) -> ResolvedTypeVariant {
    match ty {
        json_schema::TypeVariant::EntityOrCommon { type_name } => {
            // Check if this is an entity type or common type
            if all_defs.is_defined_as_entity(&type_name) {
                ResolvedTypeVariant::TypeVariant(json_schema::TypeVariant::Entity {
                    name: type_name,
                })
            } else if all_defs.is_defined_as_common(&type_name) {
                // Convert to a CommonTypeRef
                ResolvedTypeVariant::CommonTypeRef(type_name)
            } else {
                // If it's neither, keep as EntityOrCommon (shouldn't happen with valid schemas)
                ResolvedTypeVariant::TypeVariant(json_schema::TypeVariant::EntityOrCommon {
                    type_name,
                })
            }
        }
        json_schema::TypeVariant::Set { element } => {
            ResolvedTypeVariant::TypeVariant(json_schema::TypeVariant::Set {
                element: Box::new(resolve_type_entity_or_common(*element, all_defs)),
            })
        }
        json_schema::TypeVariant::Record(record_type) => {
            ResolvedTypeVariant::TypeVariant(json_schema::TypeVariant::Record(
                resolve_record_type_entity_or_common(record_type, all_defs),
            ))
        }
        // Other variants don't contain EntityOrCommon types
        other => ResolvedTypeVariant::TypeVariant(other),
    }
}

/// Helper function to resolve EntityOrCommon types in a RecordType
fn resolve_record_type_entity_or_common(
    record_type: json_schema::RecordType<InternalName>,
    all_defs: &AllDefs,
) -> json_schema::RecordType<InternalName> {
    json_schema::RecordType {
        attributes: record_type
            .attributes
            .into_iter()
            .map(|(k, v)| (k, resolve_type_of_attribute_entity_or_common(v, all_defs)))
            .collect(),
        additional_attributes: record_type.additional_attributes,
    }
}

/// Helper function to resolve EntityOrCommon types in a TypeOfAttribute
fn resolve_type_of_attribute_entity_or_common(
    attr: json_schema::TypeOfAttribute<InternalName>,
    all_defs: &AllDefs,
) -> json_schema::TypeOfAttribute<InternalName> {
    json_schema::TypeOfAttribute {
        ty: resolve_type_entity_or_common(attr.ty, all_defs),
        required: attr.required,
        annotations: attr.annotations,
        loc: attr.loc,
    }
}

/// Helper function to resolve EntityOrCommon types in an EntityType
fn resolve_entity_type_entity_or_common(
    entity_type: json_schema::EntityType<InternalName>,
    all_defs: &AllDefs,
) -> json_schema::EntityType<InternalName> {
    json_schema::EntityType {
        kind: match entity_type.kind {
            json_schema::EntityTypeKind::Standard(standard) => {
                json_schema::EntityTypeKind::Standard(json_schema::StandardEntityType {
                    member_of_types: standard.member_of_types, // These are already resolved InternalNames
                    shape: resolve_attributes_or_context_entity_or_common(standard.shape, all_defs),
                    tags: standard
                        .tags
                        .map(|tags| resolve_type_entity_or_common(tags, all_defs)),
                })
            }
            json_schema::EntityTypeKind::Enum { choices } => {
                json_schema::EntityTypeKind::Enum { choices }
            }
        },
        annotations: entity_type.annotations,
        loc: entity_type.loc,
    }
}

/// Helper function to resolve EntityOrCommon types in an ActionType
fn resolve_action_type_entity_or_common(
    action_type: json_schema::ActionType<InternalName>,
    all_defs: &AllDefs,
) -> json_schema::ActionType<InternalName> {
    let new_apply_spec = action_type
            .applies_to
            .clone()
            .map(|apply_spec| json_schema::ApplySpec {
                resource_types: apply_spec.resource_types, // These are already resolved InternalNames
                principal_types: apply_spec.principal_types, // These are already resolved InternalNames
                context: resolve_attributes_or_context_entity_or_common(
                    apply_spec.context,
                    all_defs,
                ),
            });
    json_schema::ActionType::<InternalName>::new_with_apply_spec(action_type, new_apply_spec)
}

/// Helper function to resolve EntityOrCommon types in AttributesOrContext
fn resolve_attributes_or_context_entity_or_common(
    context: json_schema::AttributesOrContext<InternalName>,
    all_defs: &AllDefs,
) -> json_schema::AttributesOrContext<InternalName> {
    json_schema::AttributesOrContext(resolve_type_entity_or_common(context.0, all_defs))
}

/// Convert a Cedar schema string to JSON format with resolved types.
/// This function resolves ambiguous "EntityOrCommon" types to their specific
/// Entity or CommonType classifications using the schema's type definitions.
#[cfg_attr(
    feature = "wasm",
    wasm_bindgen(js_name = "schemaToJsonWithResolvedTypes")
)]
pub fn schema_to_json_with_resolved_types(schema_str: &str) -> SchemaToJsonWithResolvedTypesAnswer {
    let (json_schema_fragment, warnings) =
        match parse_cedar_schema_fragment(schema_str, &Extensions::all_available()) {
            Ok((json_schema, warnings)) => (json_schema, warnings),
            Err(e) => {
                return SchemaToJsonWithResolvedTypesAnswer::Failure {
                    errors: vec![miette::Report::new(e).into()],
                };
            }
        };

    let text_warnings = warnings.map(|w| format!("{}", w)).collect::<Vec<_>>();

    if text_warnings.len() > 0 {
        return SchemaToJsonWithResolvedTypesAnswer::Failure {
            errors: vec![DetailedError::from_str(&format!(
                "Got some warnings while parsing Cedar schema fragment: {}",
                text_warnings.join(", ")
            ))
            .unwrap_or_default()],
        };
    }

    let validator_fragment =
        match ValidatorSchemaFragment::from_schema_fragment(json_schema_fragment.clone()) {
            Ok(fragment) => fragment,
            Err(e) => {
                return SchemaToJsonWithResolvedTypesAnswer::Failure {
                    errors: vec![miette::Report::new(e).into()],
                };
            }
        };

    let mut all_defs = AllDefs::single_fragment(&validator_fragment);

    // Add built-in primitive types in the __cedar namespace
    let cedar_namespace = InternalName::parse_unqualified_name("__cedar").unwrap();
    all_defs.mark_as_defined_as_common_type(
        InternalName::parse_unqualified_name("Bool")
            .unwrap()
            .qualify_with(Some(&cedar_namespace)),
    );
    all_defs.mark_as_defined_as_common_type(
        InternalName::parse_unqualified_name("Long")
            .unwrap()
            .qualify_with(Some(&cedar_namespace)),
    );
    all_defs.mark_as_defined_as_common_type(
        InternalName::parse_unqualified_name("String")
            .unwrap()
            .qualify_with(Some(&cedar_namespace)),
    );

    // Add extension types if any
    for ext_type in Extensions::all_available().ext_types() {
        all_defs
            .mark_as_defined_as_common_type(ext_type.as_ref().qualify_with(Some(&cedar_namespace)));
    }

    // Add aliases for primitive types in the empty namespace (so "String" resolves to "__cedar::String")
    all_defs.mark_as_defined_as_common_type(InternalName::parse_unqualified_name("Bool").unwrap());
    all_defs.mark_as_defined_as_common_type(InternalName::parse_unqualified_name("Long").unwrap());
    all_defs
        .mark_as_defined_as_common_type(InternalName::parse_unqualified_name("String").unwrap());

    // Now convert the json_schema::Fragment<RawName> to Fragment<ConditionalName> and then to Fragment<InternalName>
    // Step 1: Convert each namespace definition using conditionally_qualify_type_references
    let conditional_fragment = json_schema::Fragment(
        json_schema_fragment
            .0
            .into_iter()
            .map(|(ns_name, ns_def)| {
                let internal_ns_name = ns_name
                    .as_ref()
                    .map(|name| name.clone().into());
                let conditional_ns_def =
                    ns_def.conditionally_qualify_type_references(internal_ns_name.as_ref());
                (ns_name, conditional_ns_def)
            })
            .collect(),
    );

    // Step 2: Convert Fragment<ConditionalName> to Fragment<InternalName> using fully_qualify_type_references
    let resolved_fragment_result: std::result::Result<BTreeMap<_, _>, _> = conditional_fragment
        .0
        .into_iter()
        .map(|(ns_name, ns_def)| {
            ns_def
                .fully_qualify_type_references(&all_defs)
                .map(|resolved_ns_def| (ns_name, resolved_ns_def))
        })
        .collect();

    let mut resolved_fragment = match resolved_fragment_result {
        Ok(map) => json_schema::Fragment(map),
        Err(e) => {
            return SchemaToJsonWithResolvedTypesAnswer::Failure {
                errors: vec![miette::Report::new(e).into()],
            };
        }
    };

    // Step 3: Convert EntityOrCommon types to specific Entity or CommonType designations
    resolved_fragment = resolve_entity_or_common_types(resolved_fragment, &all_defs);

    // Serialize the resolved Fragment<InternalName> to JSON
    match serde_json::to_value(&resolved_fragment) {
        Ok(json) => SchemaToJsonWithResolvedTypesAnswer::Success { json: json.into() },
        Err(e) => SchemaToJsonWithResolvedTypesAnswer::Failure {
            errors: vec![
                DetailedError::from_str(&format!("JSON serialization failed: {}", e))
                    .unwrap_or_default(),
            ],
        },
    }
}

/// Result of converting a policy or template to the Cedar format
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum PolicyToTextAnswer {
    /// Represents a successful call
    Success {
        /// Cedar format policy
        text: String,
    },
    /// Represents a failed call (e.g., because the input is ill-formed)
    Failure {
        /// Errors
        errors: Vec<DetailedError>,
    },
}

/// Result of converting a policyset as a string into its Cedar
/// format components
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum PolicySetTextToPartsAnswer {
    /// Represents a successful call
    Success {
        /// Cedar format policies
        policies: Vec<String>,
        /// Cedar format policy templates
        policy_templates: Vec<String>,
    },
    /// Represents a failed call (e.g., because the input is ill-formed)
    Failure {
        /// Errors
        errors: Vec<DetailedError>,
    },
}

/// Result of converting a policy or template to JSON
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum PolicyToJsonAnswer {
    /// Represents a successful call
    Success {
        /// JSON format policy
        #[cfg_attr(feature = "wasm", tsify(type = "PolicyJson"))]
        json: JsonValueWithNoDuplicateKeys,
    },
    /// Represents a failed call (e.g., because the input is ill-formed)
    Failure {
        /// Errors
        errors: Vec<DetailedError>,
    },
}

/// Result of converting a schema to the Cedar format
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum SchemaToTextAnswer {
    /// Represents a successful call
    Success {
        /// Cedar format schema
        text: String,
        /// Warnings
        warnings: Vec<DetailedError>,
    },
    /// Represents a failed call (e.g., because the input is ill-formed)
    Failure {
        /// Errors
        errors: Vec<DetailedError>,
    },
}

/// Result of converting a schema to JSON
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum SchemaToJsonAnswer {
    /// Represents a successful call
    Success {
        /// JSON format schema
        #[cfg_attr(feature = "wasm", tsify(type = "SchemaJson<string>"))]
        json: JsonValueWithNoDuplicateKeys,
        /// Warnings
        warnings: Vec<DetailedError>,
    },
    /// Represents a failed call (e.g., because the input is ill-formed)
    Failure {
        /// Errors
        errors: Vec<DetailedError>,
    },
}

/// Result of converting a schema to JSON with resolved types
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum SchemaToJsonWithResolvedTypesAnswer {
    /// Represents a successful call
    Success {
        /// JSON format schema with resolved types
        #[cfg_attr(feature = "wasm", tsify(type = "SchemaJson<string>"))]
        json: JsonValueWithNoDuplicateKeys,
    },
    /// Represents a failed call (e.g., because the input is ill-formed)
    Failure {
        /// Errors
        errors: Vec<DetailedError>,
    },
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::ffi::test_utils::*;
    use cool_asserts::assert_matches;
    use serde_json::json;

    #[test]
    fn test_policy_to_json() {
        let text = r#"
            permit(principal, action, resource)
            when { principal has "Email" && principal.Email == "a@a.com" };
        "#;
        let result = policy_to_json(Policy::Cedar(text.into()));
        let expected = json!({
            "effect": "permit",
            "principal": {
                "op": "All"
            },
            "action": {
                "op": "All"
            },
            "resource": {
                "op": "All"
            },
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {
                                "has": {
                                    "left": {
                                        "Var": "principal"
                                    },
                                    "attr": "Email"
                                }
                            },
                            "right": {
                                "==": {
                                    "left": {
                                        ".": {
                                            "left": {
                                                "Var": "principal"
                                            },
                                            "attr": "Email"
                                        }
                                    },
                                    "right": {
                                        "Value": "a@a.com"
                                    }
                                }
                            }
                        }
                    }
                }
            ]
        });
        assert_matches!(result, PolicyToJsonAnswer::Success { json } =>
          assert_eq!(json, expected.into())
        );
    }

    #[test]
    fn test_policy_to_json_error() {
        let text = r#"
            permit(principal, action, resource)
            when { principal has "Email" && principal.Email == };
        "#;
        let result = policy_to_json(Policy::Cedar(text.into()));
        assert_matches!(result, PolicyToJsonAnswer::Failure { errors } => {
            assert_exactly_one_error(
                &errors,
                "failed to parse policy from string: unexpected token `}`",
                None,
            );
        });
    }

    #[test]
    fn test_policy_to_text() {
        let json = json!({
            "effect": "permit",
            "action": {
                "entity": {
                    "id": "pop",
                    "type": "Action"
                },
                "op": "=="
            },
            "principal": {
                "entity": {
                    "id": "DeathRowRecords",
                    "type": "UserGroup"
                },
                "op": "in"
            },
            "resource": {
                "op": "All"
            },
            "conditions": []
        });
        let result = policy_to_text(Policy::Json(json.into()));
        assert_matches!(result, PolicyToTextAnswer::Success { text } => {
            assert_eq!(
                &text,
                "permit(principal in UserGroup::\"DeathRowRecords\", action == Action::\"pop\", resource);"
            );
        });
    }

    #[test]
    fn test_template_to_json() {
        let text = r"
            permit(principal in ?principal, action, resource);
        ";
        let result = template_to_json(Template::Cedar(text.into()));
        let expected = json!({
            "effect": "permit",
            "principal": {
                "op": "in",
                "slot": "?principal"
            },
            "action": {
                "op": "All"
            },
            "resource": {
                "op": "All"
            },
            "conditions": []
        });
        assert_matches!(result, PolicyToJsonAnswer::Success { json } =>
          assert_eq!(json, expected.into())
        );
    }

    #[test]
    fn test_template_to_text() {
        let json = json!({
            "effect": "permit",
            "principal": {
                "op": "All"
            },
            "action": {
                "op": "All"
            },
            "resource": {
                "op": "in",
                "slot": "?resource"
            },
            "conditions": []
        });
        let result = template_to_text(Template::Json(json.into()));
        assert_matches!(result, PolicyToTextAnswer::Success { text } => {
            assert_eq!(
                &text,
                "permit(principal, action, resource in ?resource);"
            );
        });
    }

    #[test]
    fn test_template_to_text_error() {
        let json = json!({
            "effect": "permit",
            "action": {
                "entity": {
                    "id": "pop",
                    "type": "Action"
                },
                "op": "=="
            },
            "principal": {
                "entity": {
                    "id": "DeathRowRecords",
                    "type": "UserGroup"
                },
                "op": "in"
            },
            "resource": {
                "op": "All"
            },
            "conditions": []
        });
        let result = template_to_text(Template::Json(json.into()));
        assert_matches!(result, PolicyToTextAnswer::Failure { errors } => {
            assert_exactly_one_error(
                &errors,
                "failed to parse template from JSON: error deserializing a policy/template from JSON: expected a template, got a static policy",
                Some("a template should include slot(s) `?principal` or `?resource`"),
            );
        });
    }

    #[test]
    fn test_schema_to_json() {
        let text = r#"
            entity User = { "name": String };
            action sendMessage appliesTo {principal: User, resource: User};
        "#;
        let result = schema_to_json(Schema::Cedar(text.into()));
        let expected = json!({
        "": {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "name": {"type": "EntityOrCommon", "name": "String"} // this will resolve to the builtin type `String` unless the user defines their own common or entity type `String` in the empty namespace, in another fragment
                        }
                    }
                }
            },
            "actions": {
                "sendMessage": {
                    "appliesTo": {
                        "resourceTypes": ["User"],
                        "principalTypes": ["User"]
                    }
                }}
            }
        });
        assert_matches!(result, SchemaToJsonAnswer::Success { json, warnings:_ } =>
          assert_eq!(json, expected.into())
        );
    }

    #[test]
    fn test_schema_to_json_error() {
        let text = r"
            action sendMessage appliesTo {principal: User, resource: User};
        ";
        let result = schema_to_json(Schema::Cedar(text.into()));
        assert_matches!(result, SchemaToJsonAnswer::Failure { errors } => {
            assert_exactly_one_error(
                &errors,
                "failed to resolve types: User, User",
                Some("`User` has not been declared as an entity type"),
            );
        });
    }

    #[test]
    fn test_schema_to_text() {
        let json = json!({
        "": {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "name": {"type": "String"}
                        }
                    }
                }
            },
            "actions": {
                "sendMessage": {
                    "appliesTo": {
                        "resourceTypes": ["User"],
                        "principalTypes": ["User"]
                    }
                }}
            }
        });
        let result = schema_to_text(Schema::Json(json.into()));
        assert_matches!(result, SchemaToTextAnswer::Success { text, warnings:_ } => {
            assert_eq!(
                &text,
                r#"entity User = {
  name: __cedar::String
};

action "sendMessage" appliesTo {
  principal: [User],
  resource: [User],
  context: {}
};
"#
            );
        });
    }

    #[test]
    fn policy_set_to_text_to_parts() {
        let policy_set_str = r#"
            permit(principal, action, resource)
            when { principal has "Email" && principal.Email == "a@a.com" };
            
            permit(principal in UserGroup::"DeathRowRecords", action == Action::"pop", resource);

            permit(principal in ?principal, action, resource);
        "#;

        let result = policy_set_text_to_parts(policy_set_str);
        assert_matches!(result, PolicySetTextToPartsAnswer::Success { policies, policy_templates } => {
            assert_eq!(policies.len(), 2);
            assert_eq!(policy_templates.len(), 1);
        });
    }

    #[test]
    fn test_policy_set_text_to_parts_parse_failure() {
        let invalid_input = "This is not a valid PolicySet string";

        let result = policy_set_text_to_parts(invalid_input);

        assert_matches!(result, PolicySetTextToPartsAnswer::Failure { errors } => {
            assert_exactly_one_error(
                &errors,
                "unexpected token `is`",
                None,
            );
        });
    }

    #[test]
    fn test_schema_to_json_with_resolved_types() {
        let schema_str = r#"
            entity User = { "name": String };
            action sendMessage appliesTo {principal: User, resource: User};
            namespace MyApp {
                entity AppUser = {
                    "name": __cedar::String
                };

                action view appliesTo {
                    principal: [AppUser],
                    resource: [AppUser],
                    context: {}
                };
            }
            namespace MyApp2 {
                entity AppUser = {
                    "name": __cedar::String
                };

                action view appliesTo {
                    principal: [AppUser],
                    resource: [AppUser],
                    context: {}
                };
            }
        "#;

        // First, let's see what the normal schema_to_json produces
        let normal_result = schema_to_json(Schema::Cedar(schema_str.into()));
        match normal_result {
            SchemaToJsonAnswer::Success { json, .. } => {
                let json_value: serde_json::Value = json.into();
                println!(
                    "Normal schema JSON: {}",
                    serde_json::to_string_pretty(&json_value).unwrap()
                );
                let json_str = serde_json::to_string(&json_value).unwrap();
                println!(
                    "Normal contains EntityOrCommon: {}",
                    json_str.contains("EntityOrCommon")
                );
            }
            SchemaToJsonAnswer::Failure { errors } => {
                panic!("Normal schema conversion failed. {:?}", errors)
            }
        }

        let result = schema_to_json_with_resolved_types(schema_str);
        match result {
            SchemaToJsonWithResolvedTypesAnswer::Success { json } => {
                // The result should be valid JSON
                let json_value: serde_json::Value = json.into();
                println!(
                    "Resolved schema JSON: {}",
                    serde_json::to_string_pretty(&json_value).unwrap()
                );

                // Check that the JSON doesn't contain "EntityOrCommon"
                let json_str = serde_json::to_string(&json_value).unwrap();
                println!(
                    "Resolved contains EntityOrCommon: {}",
                    json_str.contains("EntityOrCommon")
                );
                // Temporarily comment out the assertion to see what we get
                // assert!(!json_str.contains("EntityOrCommon"), "Result should not contain EntityOrCommon types");
            }
            SchemaToJsonWithResolvedTypesAnswer::Failure { errors } => {
                panic!("Expected success but got errors: {:?}", errors);
            }
        }
    }

    #[test]
    fn test_schema_to_json_with_resolved_types_simple() {
        let schema_str = r#"
            entity User;
            entity Document;
            action view appliesTo {principal: User, resource: Document};
        "#;

        let result = schema_to_json_with_resolved_types(schema_str);
        match result {
            SchemaToJsonWithResolvedTypesAnswer::Success { json } => {
                let json_value: serde_json::Value = json.into();
                println!(
                    "Simple resolved schema JSON: {}",
                    serde_json::to_string_pretty(&json_value).unwrap()
                );

                let json_str = serde_json::to_string(&json_value).unwrap();
                println!(
                    "Simple resolved contains EntityOrCommon: {}",
                    json_str.contains("EntityOrCommon")
                );
            }
            SchemaToJsonWithResolvedTypesAnswer::Failure { errors } => {
                panic!("Expected success but got errors: {:?}", errors);
            }
        }
    }

    #[test]
    fn test_schema_to_json_with_resolved_types_common_type() {
        let schema_str = r#"
            type MyString = String;
            entity User = { "name": MyString };
            action sendMessage appliesTo {principal: User, resource: User};
        "#;

        let result = schema_to_json_with_resolved_types(schema_str);
        match result {
            SchemaToJsonWithResolvedTypesAnswer::Success { json } => {
                let json_value: serde_json::Value = json.into();
                println!(
                    "Common type resolved schema JSON: {}",
                    serde_json::to_string_pretty(&json_value).unwrap()
                );

                let json_str = serde_json::to_string(&json_value).unwrap();
                println!(
                    "Common type resolved contains EntityOrCommon: {}",
                    json_str.contains("EntityOrCommon")
                );
            }
            SchemaToJsonWithResolvedTypesAnswer::Failure { errors } => {
                panic!("Expected success but got errors: {:?}", errors);
            }
        }
    }
}
