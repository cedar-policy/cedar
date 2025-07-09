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

use cedar_policy_core::ast::PolicyID;
use cedar_policy_core::validator::ValidatorSchema;
use itertools::Itertools;
use lsp_types::{GotoDefinitionResponse, Location, Position, Url};
use visitor::PolicyGotoSchemaDefinition;

use crate::{schema::SchemaInfo, utils::position_within_loc};

use super::types::{DocumentContext, PolicyLanguageFeatures};

mod visitor;

/// Provides "go to definition" functionality for Cedar policy elements.
///
/// This function analyzes the Cedar policy at the given cursor position and
/// resolves references to their definitions in the schema document. It enables
/// IDE navigation from policy references to their corresponding schema definitions,
/// helping users understand the structure and constraints of entities being referenced.
///
/// # Supported References
///
/// The function can resolve definitions for:
/// - Entity types in constraint expressions (`principal is User`)
/// - Entity attributes (`principal.department`)
/// - Action references (`action == Action::"read"`)
/// - Context attributes (`context.request.ip`)
///
/// Resolution requires both a valid schema with location information and
/// a schema URI to construct the target locations.
pub(crate) fn policy_goto_definition(
    position: Position,
    policy_src: &str,
    schema: Option<SchemaInfo>,
    schema_uri: Option<&Url>,
) -> Option<GotoDefinitionResponse> {
    let cst = cedar_policy_core::parser::text_to_cst::parse_policies(policy_src)
        .inspect_err(|e| tracing::error!("Error parsing policy to cst: {}", e))
        .ok()?;

    let policies = cst.node.map(|p| p.0).unwrap_or_default();

    let cst = policies
        .into_iter()
        .filter(|p| position_within_loc(position, p.loc.as_ref()))
        .next_back()?;

    let policy = cst
        .to_policy_template(PolicyID::from_smolstr("0".into()))
        .ok()?;
    let (schema_info, schema_uri) = schema.zip(schema_uri)?;

    let validator = ValidatorSchema::try_from(&schema_info).ok()?;
    let d_cx = DocumentContext::new(
        Some(validator),
        policy,
        policy_src,
        position,
        PolicyLanguageFeatures::default(),
    );

    // PANIC SAFETY: We just constructed `d_cx` with a schema, so it will be present here.
    #[allow(clippy::unwrap_used)]
    let validator_ref = d_cx.schema().unwrap();

    let schema_ranges =
        PolicyGotoSchemaDefinition::get_schema_definition_ranges(&d_cx, validator_ref)?;
    match schema_ranges.into_iter().exactly_one() {
        Ok(range) => {
            let location = Location::new(schema_uri.clone(), range);
            Some(GotoDefinitionResponse::Scalar(location))
        }
        Err(schema_ranges) => {
            let locations = schema_ranges
                .into_iter()
                .sorted_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)))
                .map(|range| Location::new(schema_uri.clone(), range))
                .collect::<Vec<_>>();

            Some(GotoDefinitionResponse::Array(locations))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::LazyLock, vec};

    use lsp_types::Url;
    use tracing_test::traced_test;

    use crate::utils::tests::slice_range;
    use crate::{
        schema::SchemaInfo,
        utils::tests::{remove_caret_marker, schema_info},
    };

    static URL: LazyLock<Url> = LazyLock::new(|| Url::parse("https://example.net").ok().unwrap());

    #[track_caller]
    fn goto_def_test(policy: &str, schema: SchemaInfo, mut expected: Vec<&str>) {
        let (policy, position) = remove_caret_marker(policy);

        let ranges =
            super::policy_goto_definition(position, &policy, Some(schema.clone()), Some(&*URL));

        let mut actual = match ranges {
            Some(lsp_types::GotoDefinitionResponse::Scalar(location)) => {
                vec![slice_range(&schema.text, location.range)]
            }
            Some(lsp_types::GotoDefinitionResponse::Array(locations)) => locations
                .into_iter()
                .map(|l| slice_range(&schema.text, l.range))
                .collect(),
            Some(lsp_types::GotoDefinitionResponse::Link(_)) => {
                panic!("Unexpected GotoDefinitionResponse::Link response")
            }
            None => Vec::new(),
        };

        actual.sort();
        expected.sort();
        if actual.len() == 1 && expected.len() == 1 {
            // Nicer error on failure in the common case of one goto
            similar_asserts::assert_eq!(expected[0], actual[0]);
        } else {
            similar_asserts::assert_eq!(expected, actual);
        }
    }

    macro_rules! goto_def_test {
        ($name:ident, $policy:expr, $schema:expr, $( $expected:expr ),* )=> {
            #[test]
            #[traced_test]
            fn $name() {
                goto_def_test($policy, $schema, vec![$( $expected, )*]);
            }
        };
    }

    goto_def_test!(
        go_to_entity_definition_principal_unqualified,
        "permit(princip|caret|al, action, resource);",
        get_schema_info(),
        "entity User in [Group] {\n  viewPermissions: PermissionsMap,\n  memberPermissions: PermissionsMap,\n  hotelAdminPermissions: Set<Hotel>,\n  propertyAdminPermissions: Set<Property>,\n  lastName?: String,\n  property: Property,\n};"
    );

    goto_def_test!(
        go_to_entity_definition_principal_is,
        "permit(princip|caret|al is User, action, resource);",
        get_schema_info(),
        "entity User in [Group] {\n  viewPermissions: PermissionsMap,\n  memberPermissions: PermissionsMap,\n  hotelAdminPermissions: Set<Hotel>,\n  propertyAdminPermissions: Set<Property>,\n  lastName?: String,\n  property: Property,\n};"
    );

    goto_def_test!(
        go_to_entity_definition_principal_in_user,
        "permit(principal in Use|caret|r::\"test\", action, resource);",
        get_schema_info(),
        "entity User in [Group] {\n  viewPermissions: PermissionsMap,\n  memberPermissions: PermissionsMap,\n  hotelAdminPermissions: Set<Hotel>,\n  propertyAdminPermissions: Set<Property>,\n  lastName?: String,\n  property: Property,\n};"
    );

    goto_def_test!(
        go_to_entity_definition_principal_in_group,
        "permit(principal in Gro|caret|up::\"test\", action, resource);",
        get_schema_info(),
        "entity Group;"
    );

    goto_def_test!(
        go_to_entity_definition_principal_is_in_is_type,
        "permit(principal is Use|caret|r in Group::\"test\", action, resource);",
        get_schema_info(),
        "entity User in [Group] {\n  viewPermissions: PermissionsMap,\n  memberPermissions: PermissionsMap,\n  hotelAdminPermissions: Set<Hotel>,\n  propertyAdminPermissions: Set<Property>,\n  lastName?: String,\n  property: Property,\n};"
    );

    goto_def_test!(
        go_to_entity_definition_principal_is_in_in_type,
        "permit(principal is User in Gro|caret|up::\"test\", action, resource);",
        get_schema_info(),
        "entity Group;"
    );

    goto_def_test!(
        go_to_principal_definition_principal_is,
        "permit(princ|caret|ipal is User, action, resource);",
        get_schema_info(),
        "entity User in [Group] {\n  viewPermissions: PermissionsMap,\n  memberPermissions: PermissionsMap,\n  hotelAdminPermissions: Set<Hotel>,\n  propertyAdminPermissions: Set<Property>,\n  lastName?: String,\n  property: Property,\n};"
    );

    goto_def_test!(
        go_to_principal_definition_principal_in_user,
        "permit(pri|caret|ncipal in User::\"test\", action, resource);",
        get_schema_info(),
        "entity User in [Group] {\n  viewPermissions: PermissionsMap,\n  memberPermissions: PermissionsMap,\n  hotelAdminPermissions: Set<Hotel>,\n  propertyAdminPermissions: Set<Property>,\n  lastName?: String,\n  property: Property,\n};"
    );

    goto_def_test!(
        go_to_principal_definition_principal_in_group,
        "permit(princ|caret|ipal in Group::\"test\", action, resource);",
        get_schema_info(),
        "entity User in [Group] {\n  viewPermissions: PermissionsMap,\n  memberPermissions: PermissionsMap,\n  hotelAdminPermissions: Set<Hotel>,\n  propertyAdminPermissions: Set<Property>,\n  lastName?: String,\n  property: Property,\n};"
    );

    goto_def_test!(
        go_to_principal_definition_principal_is_in_is_type,
        "permit(prin|caret|cipal is User in Group::\"test\", action, resource);",
        get_schema_info(),
        "entity User in [Group] {\n  viewPermissions: PermissionsMap,\n  memberPermissions: PermissionsMap,\n  hotelAdminPermissions: Set<Hotel>,\n  propertyAdminPermissions: Set<Property>,\n  lastName?: String,\n  property: Property,\n};"
    );

    goto_def_test!(
        go_to_action_euid_eq,
        "permit(principal, action == Action::\"creat|caret|eHotel\", resource);",
        get_schema_info(),
        "action createProperty, createHotel, viewHotel, updateHotel, grantAccessHotel in [propertyManagerActions]\n  appliesTo {\n    principal: User,\n    resource: Hotel,\n    context: {\n      location: String,\n      other_user: User,\n      other: String\n    }\n  };"
    );

    goto_def_test!(
        go_to_action_euid_type_in,
        "permit(principal, action in [Act|caret|ion::\"createHotel\"], resource);",
        get_schema_info(),
        "action createProperty, createHotel, viewHotel, updateHotel, grantAccessHotel in [propertyManagerActions]\n  appliesTo {\n    principal: User,\n    resource: Hotel,\n    context: {\n      location: String,\n      other_user: User,\n      other: String\n    }\n  };"
    );

    goto_def_test!(
        go_to_action_euid_type_in_2nd,
        "permit(principal, action in [Action::\"createHotel\", Acti|caret|on::\"viewReservation\"], resource);",
        get_schema_info(),
        "action viewReservation, updateReservation, grantAccessReservation in [propertyManagerActions]\n  appliesTo {\n    principal: User,\n    resource: Reservation,\n    context: {\n      complex: ComplexType,\n      location: String,\n      other: Long,\n    }\n  };"
    );

    goto_def_test!(
        go_to_action_euid_type_in_group,
        "permit(principal, action in Action::\"propertyManag|caret|erActions\", resource);",
        get_schema_info(),
        "action propertyManagerActions;"
    );

    goto_def_test!(
        go_to_action_var_eq,
        "permit(principal, act|caret|ion == Action::\"createHotel\", resource);",
        get_schema_info(),
        "action createProperty, createHotel, viewHotel, updateHotel, grantAccessHotel in [propertyManagerActions]\n  appliesTo {\n    principal: User,\n    resource: Hotel,\n    context: {\n      location: String,\n      other_user: User,\n      other: String\n    }\n  };"
    );

    goto_def_test!(
        go_to_action_var_type_in,
        "permit(principal, act|caret|ion in [Action::\"createHotel\"], resource);",
        get_schema_info(),
        "action createProperty, createHotel, viewHotel, updateHotel, grantAccessHotel in [propertyManagerActions]\n  appliesTo {\n    principal: User,\n    resource: Hotel,\n    context: {\n      location: String,\n      other_user: User,\n      other: String\n    }\n  };"
    );

    goto_def_test!(
        go_to_action_var_in_multiple,
        "permit(principal, act|caret|ion in [Action::\"createHotel\", Action::\"viewReservation\"], resource);",
        get_schema_info(),
        "action createProperty, createHotel, viewHotel, updateHotel, grantAccessHotel in [propertyManagerActions]\n  appliesTo {\n    principal: User,\n    resource: Hotel,\n    context: {\n      location: String,\n      other_user: User,\n      other: String\n    }\n  };",
        "action viewReservation, updateReservation, grantAccessReservation in [propertyManagerActions]\n  appliesTo {\n    principal: User,\n    resource: Reservation,\n    context: {\n      complex: ComplexType,\n      location: String,\n      other: Long,\n    }\n  };"
    );

    goto_def_test!(
        go_to_action_var_in_group,
        "permit(principal, act|caret|ion in Action::\"propertyManagerActions\", resource);",
        get_schema_info(),
        "action propertyManagerActions;"
    );

    goto_def_test!(
        go_to_entity_definition_resource_unqualified,
        "permit(principal, action, reso|caret|urce);",
        get_schema_info(),
        "entity Property in [Hotel] {\n  propertyName: String,\n  name: String\n};",
        "entity Hotel in [Hotel] {\n  hotelName: String,\n  complex: ComplexType,\n  name: ComplexType\n};",
        "entity Reservation in [Property] {\n  reservationName: String,\n  name: String\n};"
    );

    goto_def_test!(
        go_to_entity_definition_resource_action_in,
        "permit(principal, action in [Action::\"createReservation\", Action::\"createProperty\"], reso|caret|urce);",
        get_schema_info(),
        "entity Property in [Hotel] {\n  propertyName: String,\n  name: String\n};",
        "entity Hotel in [Hotel] {\n  hotelName: String,\n  complex: ComplexType,\n  name: ComplexType\n};"
    );

    goto_def_test!(
        go_to_entity_definition_resource_is,
        "permit(principal, action, reso|caret|urce is Hotel);",
        get_schema_info(),
        "entity Hotel in [Hotel] {\n  hotelName: String,\n  complex: ComplexType,\n  name: ComplexType\n};"
    );

    goto_def_test!(
        go_to_entity_definition_resource_in_hotel,
        "permit(principal, action, resource in Ho|caret|tel::\"test\");",
        get_schema_info(),
        "entity Hotel in [Hotel] {\n  hotelName: String,\n  complex: ComplexType,\n  name: ComplexType\n};"
    );

    goto_def_test!(
        go_to_entity_definition_resource_in_hotel_reflexive,
        "permit(principal, action == Action::\"createHotel\", resource in Ho|caret|tel::\"test\");",
        get_schema_info(),
        "entity Hotel in [Hotel] {\n  hotelName: String,\n  complex: ComplexType,\n  name: ComplexType\n};"
    );

    goto_def_test!(
        go_to_entity_definition_resource_is_in_is_type_reflexive_is,
        "permit(principal, action, resource is Ho|caret|tel in Hotel::\"hotel\");",
        get_schema_info(),
        "entity Hotel in [Hotel] {\n  hotelName: String,\n  complex: ComplexType,\n  name: ComplexType\n};"
    );

    goto_def_test!(
        go_to_entity_definition_resource_is_in_is_type_reflexive_in,
        "permit(principal, action, resource is Ho|caret|tel in Hotel::\"hotel\");",
        get_schema_info(),
        "entity Hotel in [Hotel] {\n  hotelName: String,\n  complex: ComplexType,\n  name: ComplexType\n};"
    );

    goto_def_test!(
        go_to_entity_definition_resource_is_in_is_type_is,
        "permit(principal, action, resource is Pro|caret|perty in Hotel::\"hotel\");",
        get_schema_info(),
        "entity Property in [Hotel] {\n  propertyName: String,\n  name: String\n};"
    );

    goto_def_test!(
        go_to_entity_definition_resource_is_in_is_type_in,
        "permit(principal, action, resource is Property in Hot|caret|el::\"hotel\");",
        get_schema_info(),
        "entity Hotel in [Hotel] {\n  hotelName: String,\n  complex: ComplexType,\n  name: ComplexType\n};"
    );

    goto_def_test!(
        go_to_resource_definition_is,
        "permit(principal is User, action, res|caret|ource is Hotel);",
        get_schema_info(),
        "entity Hotel in [Hotel] {\n  hotelName: String,\n  complex: ComplexType,\n  name: ComplexType\n};"
    );

    goto_def_test!(
        go_to_resource_definition_resource_in_hotel,
        "permit(principal in User::\"test\", action, res|caret|ource in Hotel::\"test\");",
        get_schema_info(),
        "entity Hotel in [Hotel] {\n  hotelName: String,\n  complex: ComplexType,\n  name: ComplexType\n};",
        "entity Property in [Hotel] {\n  propertyName: String,\n  name: String\n};",
        "entity Reservation in [Property] {\n  reservationName: String,\n  name: String\n};"
    );

    goto_def_test!(
        go_to_resource_definition_is_in_is_type,
        "permit(principal is User in Group::\"test\", action, re|caret|source is Property in Hotel::\"test\");",
        get_schema_info(),
        "entity Property in [Hotel] {\n  propertyName: String,\n  name: String\n};"
    );

    goto_def_test!(
        go_to_resource_definition_is_in_is_type_reflexive,
        "permit(principal is User in Group::\"test\", action, resou|caret|rce is Hotel in Hotel::\"test\");",
        get_schema_info(),
        "entity Hotel in [Hotel] {\n  hotelName: String,\n  complex: ComplexType,\n  name: ComplexType\n};"
    );

    goto_def_test!(
        go_to_entity_type_definition_is_condition,
        "permit(principal, action, resource) when { principal is Us|caret|er };",
        get_schema_info(),
        "entity User in [Group] {
  viewPermissions: PermissionsMap,
  memberPermissions: PermissionsMap,
  hotelAdminPermissions: Set<Hotel>,
  propertyAdminPermissions: Set<Property>,
  lastName?: String,
  property: Property,
};"
    );

    goto_def_test!(
        go_to_entity_type_definition_in_user_condition,
        "permit(principal, action, resource) when { principal in Us|caret|er::\"test\" };",
        get_schema_info(),
        "entity User in [Group] {
  viewPermissions: PermissionsMap,
  memberPermissions: PermissionsMap,
  hotelAdminPermissions: Set<Hotel>,
  propertyAdminPermissions: Set<Property>,
  lastName?: String,
  property: Property,
};"
    );

    goto_def_test!(
        go_to_entity_type_definition_in_group_condition,
        "permit(principal, action, resource) when { principal in Gr|caret|oup::\"test\" };",
        get_schema_info(),
        "entity Group;"
    );

    goto_def_test!(
        go_to_entity_type_definition_in_array_condition,
        "permit(principal, action, resource) when { principal in [Gr|caret|oup::\"test\"] };",
        get_schema_info(),
        "entity Group;"
    );

    goto_def_test!(
        go_to_entity_type_definition_in_array_condition_other,
        "permit(principal, action, resource) when { principal in [Us|caret|er::\"test\", Group::\"test\"] };",
        get_schema_info(),
        "entity User in [Group] {
  viewPermissions: PermissionsMap,
  memberPermissions: PermissionsMap,
  hotelAdminPermissions: Set<Hotel>,
  propertyAdminPermissions: Set<Property>,
  lastName?: String,
  property: Property,
};"
    );

    goto_def_test!(
        go_to_entity_type_definition_eq_entity,
        "permit(principal, action, resource) when { principal == U|caret|ser::\"test\" };",
        get_schema_info(),
        "entity User in [Group] {
  viewPermissions: PermissionsMap,
  memberPermissions: PermissionsMap,
  hotelAdminPermissions: Set<Hotel>,
  propertyAdminPermissions: Set<Property>,
  lastName?: String,
  property: Property,
};"
    );

    goto_def_test!(
        go_to_entity_type_principal_attr,
        "permit(principal is User, action, resource) when { principal.pro|caret|perty.propertyName == \"test\" };",
        get_schema_info(),
        "property: Property,"
    );

    goto_def_test!(
        go_to_entity_type_attr_principal_attr,
        "permit(principal is User, action, resource) when { principal.property.proper|caret|tyName == \"test\" };",
        get_schema_info(),
        "propertyName: String,"
    );

    goto_def_test!(
        go_to_unqual_principal_attr,
        "permit(principal, action, resource) when { principal.property.proper|caret|tyName == \"test\" };",
        get_schema_info(),
        "propertyName: String,"
    );

    goto_def_test!(
        go_to_eq_principal_attr,
        "permit(principal == User::\"alice\", action, resource) when { principal.property.proper|caret|tyName == \"test\" };",
        get_schema_info(),
        "propertyName: String,"
    );

    goto_def_test!(
        go_to_common_type_principal_attr,
        "permit(principal is User, action, resource) when { principal.viewPerm|caret|issions.hotelReservations.isEmpty() };",
        get_schema_info(),
        "viewPermissions: PermissionsMap,"
    );

    goto_def_test!(
        go_to_common_type_attr_principal_attr,
        "permit(principal is User, action, resource) when { principal.viewPermissions.hotel|caret|Reservations.isEmpty() };",
        get_schema_info(),
        "hotelReservations: Set<Hotel>,"
    );

    goto_def_test!(
        go_to_euid_literal,
        "permit(principal, action, resource)
        when { Hot|caret|el::\"x\".complex.hotels.isEmpty() };",
        get_schema_info(),
        "entity Hotel in [Hotel] {\n  hotelName: String,\n  complex: ComplexType,\n  name: ComplexType\n};"
    );

    goto_def_test!(
        go_to_euid_literal_attr,
        "permit(principal, action, resource)
        when { Hotel::\"x\".co|caret|mplex.hotels.isEmpty() };",
        get_schema_info(),
        "complex: ComplexType,"
    );

    goto_def_test!(
        go_to_euid_literal_attr_of_common_type,
        "permit(principal, action, resource)
        when { Hotel::\"x\".complex.hot|caret|els.isEmpty() };",
        get_schema_info(),
        "hotels: Set<Hotel>,"
    );

    goto_def_test!(
        go_to_overloaded_entity_type,
        "permit(principal is User, action, resource) when { resource.na|caret|me };",
        get_schema_info(),
        "name: ComplexType",
        "name: String",
        "name: String"
    );

    goto_def_test!(
        go_to_overloaded_entity_type_get_attr,
        "permit(principal is User, action, resource) when { resource.name.requi|caret|red };",
        get_schema_info(),
        "required: Bool,"
    );

    goto_def_test!(
        go_to_context_definition,
        r#"permit(principal, action == Action::"createReservation", resource)
        when { con|caret|text.hotelReservations.isEmpty() };"#,
        get_schema_info(),
        "context: ComplexType"
    );

    goto_def_test!(
        go_to_context_attr_definition,
        r#"permit(principal, action == Action::"createReservation", resource)
        when { context.hot|caret|els.isEmpty() };"#,
        get_schema_info(),
        "hotels: Set<Hotel>,"
    );

    goto_def_test!(
        go_to_context_attr_overloaded_definition,
        r#"permit(principal,action in [Action::"viewReservation", Action::"createProperty"], resource)
        when { context.locat|caret|ion == "" };"#,
        get_schema_info(),
        "location: String,",
        "location: String,"
    );

    goto_def_test!(
        go_to_context_attr_unqual_action,
        r#"permit(principal,action, resource)
        when { context.oth|caret|er == 0 };"#,
        get_schema_info(),
        "other: Bool,",
        "other: Bool,",
        "other: Bool,",
        "other: Bool,",
        "other: Long,",
        "other: Long,",
        "other: Long,",
        "other: String",
        "other: String",
        "other: String",
        "other: String",
        "other: String"
    );

    goto_def_test!(
        go_to_context_entity_attr,
        r#"permit(principal, action == Action::"viewHotel", resource) when { context.other_user.hotelAdminPermissi|caret|ons.isEmpty() };"#,
        get_schema_info(),
        "hotelAdminPermissions: Set<Hotel>,"
    );

    goto_def_test!(
        go_to_context_record_attr,
        r#"permit(principal, action == Action::"viewReservation", resource) when { context.complex.hot|caret|els.isEmpty() };"#,
        get_schema_info(),
        "hotels: Set<Hotel>,"
    );

    goto_def_test!(
        go_to_has_attr_definition,
        r#"permit(principal, action, resource) when { principal has viewPermissi|caret|ons };"#,
        get_schema_info(),
        "viewPermissions: PermissionsMap,"
    );

    fn get_schema_info() -> SchemaInfo {
        schema_info("goto_def.cedarschema")
    }
}
