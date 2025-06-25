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

use ast::ConditionCompletionVisitor;
use cedar_policy_core::validator::ValidatorSchema;
use cedar_policy_core::{
    ast::PolicyID,
    parser::{cst::Policy, Node},
};
use lsp_types::{CompletionItem, Position};
use process::preprocess_policy;
use tracing::{error, info};

use crate::{
    policy::{
        completion::snippets::{get_snippets, should_show_policy_snippets},
        DocumentContext, PolicyLanguageFeatures,
    },
    utils::position_within_loc,
};

mod ast;
mod process;
mod scope;

pub(crate) use scope::*;

use super::CompletionContextKind;

/// Provides code completion suggestions for Cedar policy documents.
///
/// This provider analyzes the policy content at a given cursor position and
/// generates appropriate LSP completion items based on the policy structure,
/// available schema information, and enabled language features.
///
/// The provider handles various contexts where completion can be requested:
/// - Policy snippets (permit/forbid statements)
/// - Policy scope blocks (principal, action, resource constraints)
/// - Policy condition blocks (the `when\unless` clause expressions)
pub(crate) struct PolicyCompletionProvider {
    cursor_position: Position,
}

impl PolicyCompletionProvider {
    fn new(cursor_position: Position) -> Self {
        Self { cursor_position }
    }

    /// Generates completion suggestions for a policy at the specified cursor position.
    ///
    /// This is the main entry point for getting policy completions. It creates a provider
    /// instance and delegates to the internal implementation.
    pub(crate) fn get_completions(
        cursor_position: Position,
        policy_string: &str,
        schema: Option<ValidatorSchema>,
        features: PolicyLanguageFeatures,
    ) -> Vec<CompletionItem> {
        let mut provider = Self::new(cursor_position);
        provider.inner(policy_string, schema, features)
    }

    fn get_ast_completion_context(document: &DocumentContext<'_>) -> CompletionContextKind {
        ConditionCompletionVisitor::get_completion_context(document)
    }

    /// Internal implementation of completion generation.
    ///
    /// This method:
    /// 1. Preprocesses the policy text to handle incomplete expressions
    /// 2. Parses the policy to create an AST
    /// 3. Creates a document context with schema information
    /// 4. Determines whether to provide scope or condition completions
    /// 5. Generates appropriate completion items
    ///
    /// # Returns
    ///
    /// A vector of LSP completion items appropriate for the current context
    fn inner(
        &mut self,
        policy_string: &str,
        schema: Option<ValidatorSchema>,
        features: PolicyLanguageFeatures,
    ) -> Vec<CompletionItem> {
        let (policy_text, position) = preprocess_policy(policy_string, self.cursor_position);
        self.cursor_position = position;

        let Some(cst_policy) = self.get_cst_policy(&policy_text, features) else {
            info!("No policy found at cursor position");
            if should_show_policy_snippets(policy_string, self.cursor_position) {
                return get_snippets();
            }
            return vec![];
        };

        let Ok(policy) = cst_policy.to_policy_template_tolerant(PolicyID::from_smolstr("0".into()))
        else {
            info!("Error parsing policy to policy template");
            return vec![];
        };

        let document_context =
            DocumentContext::new(schema, policy, &policy_text, self.cursor_position, features);

        let context_kind = if document_context.is_in_scope_block() {
            get_scope_completions(
                self.cursor_position,
                &document_context.policy,
                document_context.policy_text,
            )
        } else {
            Self::get_ast_completion_context(&document_context)
        };

        context_kind.into_completion_items(&document_context)
    }

    /// Parses the policy text to a CST node representing the policy at the cursor position.
    ///
    /// This method handles both single-policy and multi-policy documents based on
    /// the configured language features.
    ///
    /// # Returns
    ///
    /// An optional CST node representing the policy at the cursor position
    fn get_cst_policy(
        &self,
        policy_text: &str,
        features: PolicyLanguageFeatures,
    ) -> Option<Node<Option<Policy>>> {
        if !features.allow_multiple_policies {
            return cedar_policy_core::parser::text_to_cst::parse_policy_tolerant(policy_text)
                .inspect_err(|e| error!("Error parsing policy to cst: {}", e))
                .ok();
        }

        let policies = cedar_policy_core::parser::text_to_cst::parse_policies_tolerant(policy_text)
            .inspect_err(|e| error!("Error parsing policy set to cst: {}", e))
            .ok()
            .and_then(|p| p.node)
            .map(|p| p.0)?;
        policies
            .into_iter()
            .filter(|p| position_within_loc(self.cursor_position, p.loc.as_ref()))
            .next_back()
    }
}

#[allow(clippy::literal_string_with_formatting_args)]
#[cfg(test)]
pub(crate) mod tests {
    use std::vec;

    use super::{PolicyCompletionProvider, PolicyLanguageFeatures};

    use itertools::Itertools;

    use crate::utils::tests::{remove_caret_marker, schema};
    use tracing_test::traced_test;

    macro_rules! schema_completion_test {
        ($name:ident, $policy:expr, $expected:expr) => {
            #[test]
            #[traced_test]
            fn $name() {
                let (policy, position) = remove_caret_marker($policy);

                let completions = PolicyCompletionProvider::get_completions(
                    position,
                    &policy,
                    Some(schema().into()),
                    PolicyLanguageFeatures::default(),
                )
                .into_iter()
                .map(|item| item.insert_text.unwrap_or(item.label))
                .sorted()
                .collect_vec();

                assert_eq!($expected, completions);
            }
        };
    }

    macro_rules! no_schema_completion_test {
        ($name:ident, $policy:expr, $expected:expr) => {
            #[test]
            fn $name() {
                let (policy, position) = remove_caret_marker($policy);

                let completions = PolicyCompletionProvider::get_completions(
                    position,
                    &policy,
                    None,
                    PolicyLanguageFeatures::default(),
                )
                .into_iter()
                .map(|item| item.insert_text.unwrap_or(item.label))
                .sorted()
                .collect_vec();

                assert_eq!($expected, completions);
            }
        };
    }

    macro_rules! no_templates_test {
        ($name:ident, $policy:expr, $expected:expr) => {
            #[test]
            fn $name() {
                let (policy, position) = remove_caret_marker($policy);

                let completions = PolicyCompletionProvider::get_completions(
                    position,
                    &policy,
                    Some(schema().into()),
                    PolicyLanguageFeatures::new(false, true),
                )
                .into_iter()
                .map(|item| item.insert_text.unwrap_or(item.label))
                .sorted()
                .collect_vec();

                assert_eq!($expected, completions);
            }
        };
    }

    schema_completion_test!(
        get_principal_operator_completions_scope,
        r"permit(principal |caret|, action, resource);",
        vec![
            "== ${1:EntityId}",
            "in ${1:expression}",
            "is ${1:Entity}",
            "is ${1:Entity} in ${2:EntityId}"
        ]
    );

    schema_completion_test!(
        get_resource_operator_completions_scope,
        r"permit(principal, action, resource |caret|);",
        vec![
            "== ${1:EntityId}",
            "in ${1:expression}",
            "is ${1:Entity}",
            "is ${1:Entity} in ${2:EntityId}"
        ]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_common_type,
        r"permit(principal is User, action, resource) when { principal.viewPermissions.h|caret| };",
        vec!["hotelReservations", "propertyReservations"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_common_type_trailing_dot,
        r"permit(principal is User, action, resource) when { principal.viewPermissions.|caret| };",
        vec!["hotelReservations", "propertyReservations"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_common_type_multiple_trailing_dot,
        r"permit(principal is User, action, resource) when { principal.viewPermissions.|caret| && principal. };",
        vec!["hotelReservations", "propertyReservations"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_common_type_multiple_trailing_dot_last_token,
        r"permit(principal is User, action, resource is Hotel) when { principal.viewPermissions. && resource.|caret| };",
        vec!["complex", "hotelName"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_common_type_multiple_trailing_dot_last_token_new_line,
        r"permit(principal is User, action, resource is Hotel) when { principal.viewPermissions. &&
            resource.|caret|
        };",
        vec!["complex", "hotelName"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_common_type_even_more_trailing_dot_last_token_new_line,
        r"permit(principal is User, action, resource is Hotel) when { principal.viewPermissions. &&
            context. && resource.|caret| };",
        vec!["complex", "hotelName"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_no_completions_after_space,
        r"permit(principal is User, action, resource is Hotel) when { principal. |caret| };",
        Vec::<String>::new()
    );

    schema_completion_test!(
        get_attr_completions_next_attr_lhs_of_eq,
        r"permit(principal is User, action, resource is Hotel) when
        { principal.viewPermissions.|caret| == true };",
        vec!["hotelReservations", "propertyReservations"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_rhs_of_eq,
        r"permit(principal is User, action, resource is Hotel) when
        { true == principal.viewPermissions.|caret| };",
        vec!["hotelReservations", "propertyReservations"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_lhs_of_in,
        r"permit(principal is User, action, resource is Hotel) when
        { principal.viewPermissions.|caret| in resource };",
        vec!["hotelReservations", "propertyReservations"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_rhs_of_in,
        r"permit(principal is User, action, resource is Hotel) when
        { resource in principal.viewPermissions.|caret| };",
        vec!["hotelReservations", "propertyReservations"]
    );

    schema_completion_test!(
        get_attr_completions_completion_on_receiver_default_completions,
        r"permit(principal, action, resource) when { princ|caret|ipal. };",
        vec![
            "action",
            "context",
            "decimal(${1})",
            "false",
            "has ${1:attribute}",
            "if ${1:true} then ${2:true} else ${3:false}",
            "in ${1:expression}",
            "ip(${1:\"127.0.0.1\"})",
            "like \"${1:pattern}\"",
            "principal",
            "resource",
            "true"
        ]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_common_type_any_principal,
        r"permit(principal, action, resource) when { principal.viewPermissions.h|caret| };",
        vec!["hotelReservations", "propertyReservations"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_brackets_common_type,
        r#"permit(principal is User, action, resource) when { principal["viewPermissions"]["|caret|"] };"#,
        vec!["hotelReservations", "propertyReservations"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_context_single_action,
        r#"permit(principal, action == Action::"viewReservation", resource) when { context.l|caret| };"#,
        vec!["complex", "location"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_context_common_type,
        r#"permit(principal, action == Action::"viewReservation", resource) when { context.complex.h|caret| };"#,
        vec!["hotels", "required"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_principal_type,
        r"permit(principal is User, action, resource) when { principal.v|caret| };",
        vec![
            "hotelAdminPermissions",
            "lastName",
            "memberPermissions",
            "property",
            "propertyAdminPermissions",
            "viewPermissions",
        ]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_principal_type_trailing_dot,
        r"permit(principal is User, action, resource) when { principal.|caret| };",
        vec![
            "hotelAdminPermissions",
            "lastName",
            "memberPermissions",
            "property",
            "propertyAdminPermissions",
            "viewPermissions",
        ]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_brackets_principal_type,
        r#"permit(principal is User, action, resource) when { principal["v|caret|"] };"#,
        vec![
            "hotelAdminPermissions",
            "lastName",
            "memberPermissions",
            "property",
            "propertyAdminPermissions",
            "viewPermissions",
        ]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_principal_type_inferred_by_is_cond,
        r"permit(principal, action, resource) when { principal is User && principal.v|caret| };",
        vec![
            "hotelAdminPermissions",
            "lastName",
            "memberPermissions",
            "property",
            "propertyAdminPermissions",
            "viewPermissions",
        ]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_any_principal_types,
        r"permit(principal, action, resource) when { principal.v|caret| };",
        vec![
            "hotelAdminPermissions",
            "lastName",
            "memberPermissions",
            "property",
            "propertyAdminPermissions",
            "viewPermissions",
        ]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_any_resource_types,
        r"permit(principal, action, resource) when { resource.n|caret| };",
        vec!["complex", "hotelName", "propertyName", "reservationName"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_any_resource_types_common_type,
        r"permit(principal, action, resource) when { resource.complex.h|caret| };",
        vec!["hotels", "required"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_inferred_resource_by_action,
        r#"permit(principal, action == Action::"createHotel", resource) when { resource.n|caret| };"#,
        vec!["complex", "hotelName"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_inferred_resource_by_actions,
        r#"permit(principal, action in [Action::"createHotel"], resource) when { resource.n|caret| };"#,
        vec!["complex", "hotelName"]
    );

    schema_completion_test!(
        get_attr_completions_next_attr_inferred_union_resource_by_actions,
        r#"permit(principal, action in [Action::"createHotel", Action::"updateReservation"], resource) when { resource.n|caret| };"#,
        vec!["complex", "hotelName", "reservationName"]
    );

    schema_completion_test!(
        get_attr_completions_dont_suggest_after_completion,
        r"permit(principal is User, action, resource) when { principal.hotelAdminPermissions |caret|};",
        Vec::<String>::new()
    );

    schema_completion_test!(
        get_attr_completions_within_attr_common_type,
        r"permit(principal is User, action, resource) when { principal.viewPermissions.hotel|caret|.contains({}) };",
        vec!["hotelReservations", "propertyReservations"]
    );

    schema_completion_test!(
        get_attr_completions_within_eq_expression,
        r"permit(principal, action, resource) when { resource.hotelName == principal.property.|caret| };",
        vec!["propertyName"]
    );

    schema_completion_test!(
        get_attr_completions_within_eq_expression_otherside,
        r"permit(principal, action, resource is Hotel) when { resource.|caret| == principal.property.propertyName };",
        vec!["complex", "hotelName"]
    );

    schema_completion_test!(
        is_completions_principal,
        r"permit(principal, action, resource) when { principal is U|caret| };",
        vec!["User"]
    );

    schema_completion_test!(
        is_completions_resource,
        r"permit(principal, action, resource) when { resource is H|caret| };",
        vec!["Hotel", "Property", "Reservation"]
    );

    schema_completion_test!(
        is_completions_dont_suggest_after_completion,
        r"permit(principal, action, resource) when { resource is Hotel |caret|};",
        Vec::<String>::new()
    );

    schema_completion_test!(
        get_attr_completions_has_completions_common_type,
        r"permit(principal is User, action, resource) when { principal has viewPermissions.h|caret| };",
        vec!["hotelReservations", "propertyReservations"]
    );

    schema_completion_test!(
        has_completions_next_attr_principal_type,
        r"permit(principal is User, action, resource) when { principal has v|caret| };",
        vec![
            "hotelAdminPermissions",
            "lastName",
            "memberPermissions",
            "property",
            "propertyAdminPermissions",
            "viewPermissions"
        ]
    );

    schema_completion_test!(
        has_completions_next_attr_any_resource_types_common_type,
        r"permit(principal, action, resource) when { resource has complex.h|caret| };",
        vec!["hotels", "required"]
    );

    schema_completion_test!(
        has_completions_dont_suggest_after_completion,
        r"permit(principal is User, action, resource) when { principal has hotelAdminPermissions |caret|};",
        Vec::<String>::new()
    );

    schema_completion_test!(
        complete_action_in_euids,
        r#"permit(principal, action, resource) when { action in [Action::"v|caret|"] };"#,
        schema()
            .actions()
            .map(|a| a.eid().escaped())
            .sorted()
            .collect_vec()
    );

    schema_completion_test!(
        complete_empty_set_methods,
        r"permit(principal, action, resource) when { [].|caret| };",
        vec![
            "contains(${1:element})",
            "containsAll(${1:other})",
            "containsAny(${1:other})",
            "isEmpty()"
        ]
    );

    schema_completion_test!(
        complete_set_methods,
        r"permit(principal, action, resource) when { [true].|caret| };",
        vec![
            "contains(${1:element})",
            "containsAll(${1:other})",
            "containsAny(${1:other})",
            "isEmpty()"
        ]
    );

    schema_completion_test!(
        complete_vars_within_set,
        r"permit(principal, action, resource) when { [t|caret|] };",
        vec![
            "action",
            "context",
            "decimal(${1})",
            "false",
            "has ${1:attribute}",
            "if ${1:true} then ${2:true} else ${3:false}",
            "in ${1:expression}",
            "ip(${1:\"127.0.0.1\"})",
            "like \"${1:pattern}\"",
            "principal",
            "resource",
            "true"
        ]
    );

    schema_completion_test!(
        complete_get_attr_within_set,
        r"permit(principal, action, resource) when { [principal.h|caret|] };",
        vec![
            "hotelAdminPermissions",
            "lastName",
            "memberPermissions",
            "property",
            "propertyAdminPermissions",
            "viewPermissions"
        ]
    );

    schema_completion_test!(
        complete_extension_methods_ip,
        r#"permit(principal, action, resource) when { ip("127.0.0.1").i|caret| };"#,
        vec![
            "isInRange(${1:ipaddr})",
            "isIpv4()",
            "isIpv6()",
            "isLoopback()",
            "isMulticast()"
        ]
    );

    schema_completion_test!(
        complete_extension_methods_ip_trailing_dot,
        r#"permit(principal, action, resource) when { ip("127.0.0.1").|caret| };"#,
        vec![
            "isInRange(${1:ipaddr})",
            "isIpv4()",
            "isIpv6()",
            "isLoopback()",
            "isMulticast()"
        ]
    );

    schema_completion_test!(
        complete_extension_methods_decimal,
        r#"permit(principal, action, resource) when { decimal("127").g|caret| };"#,
        vec![
            "greaterThan(${1:decimal})",
            "greaterThanOrEqual(${1:decimal})",
            "lessThan(${1:decimal})",
            "lessThanOrEqual(${1:decimal})"
        ]
    );

    schema_completion_test!(
        complete_extension_methods_datetime,
        r#"permit(principal, action, resource) when { datetime("127").t|caret| };"#,
        vec![
            "durationSince(${1:duration})",
            "offset(${1:duration})",
            "toDate()",
            "toDays()",
            "toHours()",
            "toMilliseconds()",
            "toMinutes()",
            "toSeconds()",
            "toTime()"
        ]
    );

    schema_completion_test!(
        complete_action_unqual,
        r"permit(principal, action|caret|, resource);",
        vec![
            "== ${1:Action::\"\"}",
            "in ${1:ActionGroup::\"\"}",
            "in [${1}]"
        ]
    );

    schema_completion_test!(
        complete_action_eq_euids_in_policy_scope,
        r"permit(principal, action == A|caret|, resource);",
        vec![
            "Action::\"createHotel\"",
            "Action::\"createProperty\"",
            "Action::\"createReservation\"",
            "Action::\"grantAccessHotel\"",
            "Action::\"grantAccessProperty\"",
            "Action::\"grantAccessReservation\"",
            "Action::\"updateHotel\"",
            "Action::\"updateProperty\"",
            "Action::\"updateReservation\"",
            "Action::\"viewHotel\"",
            "Action::\"viewProperty\"",
            "Action::\"viewReservation\"",
        ]
    );

    schema_completion_test!(
        complete_action_eq_euids_in_policy_scope_no_character,
        r"permit(principal, action == |caret|, resource);",
        vec![
            "Action::\"createHotel\"",
            "Action::\"createProperty\"",
            "Action::\"createReservation\"",
            "Action::\"grantAccessHotel\"",
            "Action::\"grantAccessProperty\"",
            "Action::\"grantAccessReservation\"",
            "Action::\"updateHotel\"",
            "Action::\"updateProperty\"",
            "Action::\"updateReservation\"",
            "Action::\"viewHotel\"",
            "Action::\"viewProperty\"",
            "Action::\"viewReservation\"",
        ]
    );

    schema_completion_test!(
        complete_action_in_scope_no_character,
        r"permit(principal, action in |caret|, resource);",
        vec!["Action::\"propertyManagerActions\""]
    );

    schema_completion_test!(
        complete_action_in_array_in_policy_scope_no_character,
        r"permit(principal, action in [|caret|], resource);",
        vec![
            "Action::\"createHotel\"",
            "Action::\"createProperty\"",
            "Action::\"createReservation\"",
            "Action::\"grantAccessHotel\"",
            "Action::\"grantAccessProperty\"",
            "Action::\"grantAccessReservation\"",
            "Action::\"propertyManagerActions\"",
            "Action::\"updateHotel\"",
            "Action::\"updateProperty\"",
            "Action::\"updateReservation\"",
            "Action::\"viewHotel\"",
            "Action::\"viewProperty\"",
            "Action::\"viewReservation\""
        ]
    );

    schema_completion_test!(
        complete_action_in_array_with_existing_in_policy_scope_no_character,
        r#"permit(principal, action in [Action::"createHotel", A|caret|], resource);"#,
        vec![
            "Action::\"createHotel\"",
            "Action::\"createProperty\"",
            "Action::\"createReservation\"",
            "Action::\"grantAccessHotel\"",
            "Action::\"grantAccessProperty\"",
            "Action::\"grantAccessReservation\"",
            "Action::\"propertyManagerActions\"",
            "Action::\"updateHotel\"",
            "Action::\"updateProperty\"",
            "Action::\"updateReservation\"",
            "Action::\"viewHotel\"",
            "Action::\"viewProperty\"",
            "Action::\"viewReservation\""
        ]
    );

    schema_completion_test!(
        complete_action_eq_euids_in_conditions,
        r"permit(principal, action, resource) when { action == A|caret| };",
        vec![
            "Action::\"createHotel\"",
            "Action::\"createProperty\"",
            "Action::\"createReservation\"",
            "Action::\"grantAccessHotel\"",
            "Action::\"grantAccessProperty\"",
            "Action::\"grantAccessReservation\"",
            "Action::\"updateHotel\"",
            "Action::\"updateProperty\"",
            "Action::\"updateReservation\"",
            "Action::\"viewHotel\"",
            "Action::\"viewProperty\"",
            "Action::\"viewReservation\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    schema_completion_test!(
        dont_complete_already_completed_action_near_action_var,
        r#"permit(principal, action|caret| == Action::"createHotel", resource);"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_complete_already_completed_action_near_action_literal,
        r#"permit(principal, action == |caret|Action::"createHotel", resource);"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_complete_already_completed_action_after_action_literal,
        r#"permit(principal, action == Action::"createHotel"|caret|, resource);"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        complete_principal_euid_snippet,
        r"permit(principal == U|caret|, action, resource);",
        vec!["?principal", "User::\"${1:entityId}\"",]
    );

    schema_completion_test!(
        complete_principal_euid_snippet_no_character,
        r"permit(principal == |caret|, action, resource);",
        vec!["?principal", "User::\"${1:entityId}\"",]
    );

    schema_completion_test!(
        complete_principal_is_snippet_no_character,
        r"permit(principal is |caret|, action, resource);",
        vec!["User"]
    );

    schema_completion_test!(
        complete_principal_is_snippet,
        r"permit(principal is U|caret|, action, resource);",
        vec!["User"]
    );

    schema_completion_test!(
        complete_principal_is_in_snippet_no_character,
        r"permit(principal is User in |caret|, action, resource);",
        vec![
            "?principal",
            "Group::\"${1:entityId}\"",
            "User::\"${1:entityId}\""
        ]
    );

    schema_completion_test!(
        complete_principal_in_snippet_no_character,
        r"permit(principal in |caret|, action, resource);",
        vec![
            "?principal",
            "Group::\"${1:entityId}\"",
            "User::\"${1:entityId}\""
        ]
    );

    schema_completion_test!(
        complete_principal_in_snippet_with_eq_action_no_character,
        r#"permit(principal in |caret|, action == Action::"createHotel", resource);"#,
        vec![
            "?principal",
            "Group::\"${1:entityId}\"",
            "User::\"${1:entityId}\""
        ]
    );

    schema_completion_test!(
        complete_principal_in_snippet_with_in_action_group_no_character,
        r#"permit(principal in |caret|, action in Action::"propertyManagerActions", resource);"#,
        vec![
            "?principal",
            "Group::\"${1:entityId}\"",
            "User::\"${1:entityId}\""
        ]
    );

    schema_completion_test!(
        dont_complete_principal_in_entity_euid,
        r#"permit(principal in Group::"|caret|", action, resource);"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_complete_principal_eq_entity_euid,
        r#"permit(principal == User::"|caret|", action, resource);"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_complete_principal_is_in_entity_euid,
        r#"permit(principal is User in Group::"|caret|", action, resource);"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_complete_principal_after_in_entity_euid,
        r#"permit(principal in Group::"test" |caret|, action, resource);"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_complete_principal_after_is_in_entity_euid,
        r#"permit(principal is User in Group::"test" |caret|, action, resource);"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_complete_principal_after_eq_entity_euid,
        r#"permit(principal == User::"test" |caret|, action, resource);"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        complete_principal_in_snippet_with_in_action_arr_no_character,
        r#"permit(principal in |caret|, action in [Action::"propertyManagerActions"], resource);"#,
        vec![
            "?principal",
            "Group::\"${1:entityId}\"",
            "User::\"${1:entityId}\""
        ]
    );

    schema_completion_test!(
        complete_principal_eq_snippet_with_eq_action_no_character,
        r#"permit(principal == |caret|, action == Action::"createHotel", resource);"#,
        vec!["?principal", "User::\"${1:entityId}\""]
    );

    schema_completion_test!(
        complete_principal_eq_snippet_with_in_action_group_no_character,
        r#"permit(principal == |caret|, action in Action::"propertyManagerActions", resource);"#,
        vec!["?principal", "User::\"${1:entityId}\""]
    );

    schema_completion_test!(
        complete_principal_eq_snippet_with_in_action_arr_no_character,
        r#"permit(principal == |caret|, action in [Action::"propertyManagerActions"], resource);"#,
        vec!["?principal", "User::\"${1:entityId}\""]
    );

    schema_completion_test!(
        complete_principal_eq_when,
        r"permit(principal, action, resource) when { principal == U|caret| };",
        vec![
            "User::\"${1:entityId}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    schema_completion_test!(
        complete_principal_eq_when_is_bug,
        r"permit(principal is User, action, resource) when { principal == U|caret| };",
        vec![
            "User::\"${1:entityId}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    schema_completion_test!(
        complete_resource_euid_snippet,
        r"permit(principal, action, resource == H|caret|);",
        vec![
            "?resource",
            "Hotel::\"${1:entityId}\"",
            "Property::\"${1:entityId}\"",
            "Reservation::\"${1:entityId}\"",
        ]
    );

    schema_completion_test!(
        complete_resource_euid_snippet_no_character,
        r"permit(principal, action, resource == |caret|);",
        vec![
            "?resource",
            "Hotel::\"${1:entityId}\"",
            "Property::\"${1:entityId}\"",
            "Reservation::\"${1:entityId}\"",
        ]
    );

    schema_completion_test!(
        complete_resource_is_snippet_no_character,
        r"permit(principal, action, resource is |caret|);",
        vec!["Hotel", "Property", "Reservation"]
    );

    schema_completion_test!(
        complete_resource_is_in_snippet_no_character,
        r"permit(principal, action, resource is Property in |caret|);",
        vec![
            "?resource",
            "Hotel::\"${1:entityId}\"",
            "Property::\"${1:entityId}\""
        ]
    );

    schema_completion_test!(
        complete_resource_in_snippet_no_character,
        r"permit(principal, action, resource in |caret|);",
        vec![
            "?resource",
            "Hotel::\"${1:entityId}\"",
            "Property::\"${1:entityId}\"",
            "Reservation::\"${1:entityId}\""
        ]
    );

    schema_completion_test!(
        complete_resource_in_snippet_with_eq_action_no_character,
        r#"permit(principal, action == Action::"createHotel", resource in |caret|);"#,
        vec!["?resource", "Hotel::\"${1:entityId}\""]
    );

    schema_completion_test!(
        complete_resource_in_snippet_with_in_action_group_no_character,
        r#"permit(principal, action in Action::"propertyManagerActions", resource in |caret|);"#,
        vec![
            "?resource",
            "Hotel::\"${1:entityId}\"",
            "Property::\"${1:entityId}\"",
            "Reservation::\"${1:entityId}\""
        ]
    );

    schema_completion_test!(
        complete_resource_in_snippet_with_in_action_arr_no_character,
        r#"permit(principal, action in [Action::"propertyManagerActions"], resource in |caret|);"#,
        vec![
            "?resource",
            "Hotel::\"${1:entityId}\"",
            "Property::\"${1:entityId}\"",
            "Reservation::\"${1:entityId}\""
        ]
    );

    schema_completion_test!(
        complete_resource_eq_snippet_with_eq_action_no_character,
        r#"permit(principal, action == Action::"createHotel", resource == |caret|);"#,
        vec!["?resource", "Hotel::\"${1:entityId}\""]
    );

    schema_completion_test!(
        complete_resource_eq_snippet_with_in_action_group_no_character,
        r#"permit(principal, action in Action::"propertyManagerActions", resource == |caret|);"#,
        vec![
            "?resource",
            "Hotel::\"${1:entityId}\"",
            "Property::\"${1:entityId}\"",
            "Reservation::\"${1:entityId}\""
        ]
    );

    schema_completion_test!(
        complete_resource_eq_snippet_with_in_action_arr_no_character,
        r#"permit(principal, action in [Action::"propertyManagerActions"], resource == |caret|);"#,
        vec![
            "?resource",
            "Hotel::\"${1:entityId}\"",
            "Property::\"${1:entityId}\"",
            "Reservation::\"${1:entityId}\""
        ]
    );

    schema_completion_test!(
        dont_complete_resource_in_entity_euid,
        r#"permit(principal, action, resource in Hotel::"|caret|");"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_complete_resource_eq_entity_euid,
        r#"permit(principal, action, resource == Hotel::"|caret|");"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        complete_unknown_variable_when,
        r"permit(principal, action, resource) when { i|caret| };",
        vec![
            "action",
            "context",
            "decimal(${1})",
            "false",
            "has ${1:attribute}",
            "if ${1:true} then ${2:true} else ${3:false}",
            "in ${1:expression}",
            "ip(${1:\"127.0.0.1\"})",
            "like \"${1:pattern}\"",
            "principal",
            "resource",
            "true"
        ]
    );

    schema_completion_test!(
        complete_unknown_variable_unless,
        r"permit(principal, action, resource) when { i|caret| };",
        vec![
            "action",
            "context",
            "decimal(${1})",
            "false",
            "has ${1:attribute}",
            "if ${1:true} then ${2:true} else ${3:false}",
            "in ${1:expression}",
            "ip(${1:\"127.0.0.1\"})",
            "like \"${1:pattern}\"",
            "principal",
            "resource",
            "true"
        ]
    );

    schema_completion_test!(
        complete_unknown_variable_when_new_line,
        r"permit(principal, action, resource)
        when
        {
            i|caret|
        };",
        vec![
            "action",
            "context",
            "decimal(${1})",
            "false",
            "has ${1:attribute}",
            "if ${1:true} then ${2:true} else ${3:false}",
            "in ${1:expression}",
            "ip(${1:\"127.0.0.1\"})",
            "like \"${1:pattern}\"",
            "principal",
            "resource",
            "true"
        ]
    );

    schema_completion_test!(
        complete_unknown_variable_unless_new_line,
        r"permit(principal, action, resource)
        unless
        {
            i|caret|
        };",
        vec![
            "action",
            "context",
            "decimal(${1})",
            "false",
            "has ${1:attribute}",
            "if ${1:true} then ${2:true} else ${3:false}",
            "in ${1:expression}",
            "ip(${1:\"127.0.0.1\"})",
            "like \"${1:pattern}\"",
            "principal",
            "resource",
            "true"
        ]
    );

    schema_completion_test!(
        complete_unknown_variable_when_unless_new_line_when,
        r"permit(principal, action, resource)
        when
        {
            i|caret|
        }
        unless
        {
            true
        };",
        vec![
            "action",
            "context",
            "decimal(${1})",
            "false",
            "has ${1:attribute}",
            "if ${1:true} then ${2:true} else ${3:false}",
            "in ${1:expression}",
            "ip(${1:\"127.0.0.1\"})",
            "like \"${1:pattern}\"",
            "principal",
            "resource",
            "true"
        ]
    );

    schema_completion_test!(
        complete_unknown_variable_when_no_whitespace,
        r"permit(principal, action, resource)when{i|caret|};",
        vec![
            "action",
            "context",
            "decimal(${1})",
            "false",
            "has ${1:attribute}",
            "if ${1:true} then ${2:true} else ${3:false}",
            "in ${1:expression}",
            "ip(${1:\"127.0.0.1\"})",
            "like \"${1:pattern}\"",
            "principal",
            "resource",
            "true"
        ]
    );

    schema_completion_test!(
        complete_unknown_variable_unless_no_whitespace,
        r"permit(principal, action, resource)unless{i|caret|};",
        vec![
            "action",
            "context",
            "decimal(${1})",
            "false",
            "has ${1:attribute}",
            "if ${1:true} then ${2:true} else ${3:false}",
            "in ${1:expression}",
            "ip(${1:\"127.0.0.1\"})",
            "like \"${1:pattern}\"",
            "principal",
            "resource",
            "true"
        ]
    );

    schema_completion_test!(
        complete_unknown_variable_when_unless_no_whitespace_when,
        r"permit(principal, action, resource)when{i|caret|}unless{true};",
        vec![
            "action",
            "context",
            "decimal(${1})",
            "false",
            "has ${1:attribute}",
            "if ${1:true} then ${2:true} else ${3:false}",
            "in ${1:expression}",
            "ip(${1:\"127.0.0.1\"})",
            "like \"${1:pattern}\"",
            "principal",
            "resource",
            "true"
        ]
    );

    schema_completion_test!(
        complete_unknown_variable_when_unless_no_whitespace_unless,
        r"permit(principal, action, resource)when{true}unless{i|caret|};",
        vec![
            "action",
            "context",
            "decimal(${1})",
            "false",
            "has ${1:attribute}",
            "if ${1:true} then ${2:true} else ${3:false}",
            "in ${1:expression}",
            "ip(${1:\"127.0.0.1\"})",
            "like \"${1:pattern}\"",
            "principal",
            "resource",
            "true"
        ]
    );

    schema_completion_test!(
        complete_unknown_variable_when_unless_new_line_unless,
        r"permit(principal, action, resource)
        when
        {
            true
        }
        unless
        {
            i|caret|
        };",
        vec![
            "action",
            "context",
            "decimal(${1})",
            "false",
            "has ${1:attribute}",
            "if ${1:true} then ${2:true} else ${3:false}",
            "in ${1:expression}",
            "ip(${1:\"127.0.0.1\"})",
            "like \"${1:pattern}\"",
            "principal",
            "resource",
            "true"
        ]
    );

    schema_completion_test!(
        complete_principal_in_entity,
        r"permit(principal in G|caret|, action, resource);",
        vec![
            "?principal",
            "Group::\"${1:entityId}\"",
            "User::\"${1:entityId}\""
        ]
    );

    schema_completion_test!(
        complete_principal_in_entity_condition,
        r"permit(principal, action, resource) when { principal in G|caret|};",
        vec![
            "Group::\"${1:entityId}\"",
            "User::\"${1:entityId}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    schema_completion_test!(
        complete_principal_euid_in_entity_condition,
        r#"permit(principal, action, resource) when { User::"bob" in G|caret|};"#,
        vec![
            "Group::\"${1:entityId}\"",
            "User::\"${1:entityId}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    schema_completion_test!(
        complete_principal_euid_in_array_condition,
        r#"permit(principal, action, resource) when { User::"bob" in [G|caret|]};"#,
        vec![
            "Group::\"${1:entityId}\"",
            "User::\"${1:entityId}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    schema_completion_test!(
        complete_principal_euid_in_array_more_elements_condition,
        r#"permit(principal, action, resource) when { User::"bob" in [Group::"myGroup", G|caret|]};"#,
        vec![
            "Group::\"${1:entityId}\"",
            "User::\"${1:entityId}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    schema_completion_test!(
        complete_action_in_action_group,
        r"permit(principal, action in A|caret|, resource);",
        vec!["Action::\"propertyManagerActions\""]
    );

    schema_completion_test!(
        complete_action_in_action_group_condition,
        r"permit(principal, action, resource) when { action in A|caret| };",
        vec![
            "Action::\"propertyManagerActions\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    schema_completion_test!(
        complete_action_in_array_literal,
        r"permit(principal, action in [A|caret|], resource);",
        vec![
            "Action::\"createHotel\"",
            "Action::\"createProperty\"",
            "Action::\"createReservation\"",
            "Action::\"grantAccessHotel\"",
            "Action::\"grantAccessProperty\"",
            "Action::\"grantAccessReservation\"",
            "Action::\"propertyManagerActions\"",
            "Action::\"updateHotel\"",
            "Action::\"updateProperty\"",
            "Action::\"updateReservation\"",
            "Action::\"viewHotel\"",
            "Action::\"viewProperty\"",
            "Action::\"viewReservation\""
        ]
    );

    schema_completion_test!(
        complete_action_in_array_literal_condition,
        r"permit(principal, action, resource) when { action in [A|caret|]};",
        vec![
            "Action::\"createHotel\"",
            "Action::\"createProperty\"",
            "Action::\"createReservation\"",
            "Action::\"grantAccessHotel\"",
            "Action::\"grantAccessProperty\"",
            "Action::\"grantAccessReservation\"",
            "Action::\"propertyManagerActions\"",
            "Action::\"updateHotel\"",
            "Action::\"updateProperty\"",
            "Action::\"updateReservation\"",
            "Action::\"viewHotel\"",
            "Action::\"viewProperty\"",
            "Action::\"viewReservation\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    schema_completion_test!(
        complete_action_in_array_literal_condition_no_character,
        r"permit(principal, action, resource) when { action in [|caret|]};",
        vec![
            "Action::\"createHotel\"",
            "Action::\"createProperty\"",
            "Action::\"createReservation\"",
            "Action::\"grantAccessHotel\"",
            "Action::\"grantAccessProperty\"",
            "Action::\"grantAccessReservation\"",
            "Action::\"propertyManagerActions\"",
            "Action::\"updateHotel\"",
            "Action::\"updateProperty\"",
            "Action::\"updateReservation\"",
            "Action::\"viewHotel\"",
            "Action::\"viewProperty\"",
            "Action::\"viewReservation\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    schema_completion_test!(
        complete_action_eq_action_id,
        r#"permit(principal, action == Action::"|caret|", resource);"#,
        vec![
            "createHotel",
            "createProperty",
            "createReservation",
            "grantAccessHotel",
            "grantAccessProperty",
            "grantAccessReservation",
            "updateHotel",
            "updateProperty",
            "updateReservation",
            "viewHotel",
            "viewProperty",
            "viewReservation"
        ]
    );

    schema_completion_test!(
        complete_action_eq_action_id_with_char,
        r#"permit(principal, action == Action::"c|caret|", resource);"#,
        vec![
            "createHotel",
            "createProperty",
            "createReservation",
            "grantAccessHotel",
            "grantAccessProperty",
            "grantAccessReservation",
            "updateHotel",
            "updateProperty",
            "updateReservation",
            "viewHotel",
            "viewProperty",
            "viewReservation"
        ]
    );

    schema_completion_test!(
        complete_action_literal_in_array_literal,
        r#"permit(principal, action in [Action::"|caret|"], resource);"#,
        vec![
            "createHotel",
            "createProperty",
            "createReservation",
            "grantAccessHotel",
            "grantAccessProperty",
            "grantAccessReservation",
            "propertyManagerActions",
            "updateHotel",
            "updateProperty",
            "updateReservation",
            "viewHotel",
            "viewProperty",
            "viewReservation"
        ]
    );

    schema_completion_test!(
        complete_action_literal_in_action_literal,
        r#"permit(principal, action in Action::"|caret|", resource);"#,
        vec!["propertyManagerActions",]
    );

    schema_completion_test!(
        complete_resource_in_entity,
        r"permit(principal, action, resource in H|caret|);",
        vec![
            "?resource",
            "Hotel::\"${1:entityId}\"",
            "Property::\"${1:entityId}\"",
            "Reservation::\"${1:entityId}\""
        ]
    );

    schema_completion_test!(
        complete_resource_in_entity_no_character,
        r"permit(principal, action, resource in |caret|);",
        vec![
            "?resource",
            "Hotel::\"${1:entityId}\"",
            "Property::\"${1:entityId}\"",
            "Reservation::\"${1:entityId}\""
        ]
    );

    schema_completion_test!(
        complete_resource_in_entity_condition,
        r"permit(principal, action, resource) when { resource in H|caret| };",
        vec![
            "Hotel::\"${1:entityId}\"",
            "Property::\"${1:entityId}\"",
            "Reservation::\"${1:entityId}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    schema_completion_test!(
        complete_resource_euid_in_entity_condition,
        r#"permit(principal, action, resource) when { Hotel::"bob" in H|caret|};"#,
        vec![
            "Hotel::\"${1:entityId}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    schema_completion_test!(
        complete_resource_euid_in_array_condition,
        r#"permit(principal, action, resource) when { Property::"bob" in [H|caret|]};"#,
        vec![
            "Hotel::\"${1:entityId}\"",
            "Property::\"${1:entityId}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    schema_completion_test!(
        complete_resource_euid_in_array_more_elements_condition,
        r#"permit(principal, action, resource) when { Hotel::"bob" in [Hotel::"hotel", H|caret|]};"#,
        vec![
            "Hotel::\"${1:entityId}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    schema_completion_test!(
        complete_resource_in_sub_attribute_condition,
        r"permit(principal, action, resource) when { resource in principal.|caret| };",
        vec![
            "hotelAdminPermissions",
            "lastName",
            "memberPermissions",
            "property",
            "propertyAdminPermissions",
            "viewPermissions"
        ]
    );

    schema_completion_test!(
        complete_entity_literal_attr,
        r#"permit(principal, action, resource) when { Hotel::"x".|caret| };"#,
        vec!["complex", "hotelName"]
    );

    schema_completion_test!(
        complete_entity_literal_attr_of_common_type,
        r#"permit(principal, action, resource) when { Hotel::"x".complex.|caret| };"#,
        vec!["hotels", "required"]
    );

    schema_completion_test!(
        complete_resource_in_entity_condition_no_character_not_possible_yet,
        r"permit(principal, action, resource) when { resource in |caret| };",
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_within_like_empty_pattern,
        r#"permit(principal, action, resource) when { "test" like "|caret|" };"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_within_like_some_pattern,
        r#"permit(principal, action, resource) when { "test" like "t|caret|" };"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_within_like_wildcard_pattern,
        r#"permit(principal, action, resource) when { "test" like "*|caret|" };"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_within_string_literal,
        r#"permit(principal, action, resource) when { "|caret|" };"#,
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_when_outside_when_conditions_1,
        r"permit(principal, action, resource) when |caret|{ true };",
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_when_outside_when_conditions_2,
        r"permit(principal, action, resource) when { true }|caret|;",
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_when_outside_when_conditions_3,
        r"permit(principal, action, resource) when |caret|
        { true };",
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_when_outside_when_conditions_4,
        r"permit(principal, action, resource) when
        { true } |caret|;",
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_when_outside_unless_conditions_1,
        r"permit(principal, action, resource) unless |caret| { true };",
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_when_outside_unless_conditions_2,
        r"permit(principal, action, resource) unless { true }|caret|;",
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_when_outside_unless_conditions_3,
        r"permit(principal, action, resource) unless |caret|
        { true };",
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_when_outside_unless_conditions_4,
        r"permit(principal, action, resource) unless
        { true } |caret|;",
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_when_outside_multi_conditions_1,
        r"permit(principal, action, resource) when { true } unless |caret| { true };",
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_when_outside_multi_conditions_2,
        r"permit(principal, action, resource) when |caret| { true } unless { true };",
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_when_outside_multi_conditions_3,
        r"permit(principal, action, resource) when |caret| { true } unless { true }|caret|;",
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_when_outside_multi_conditions_4,
        r"permit(principal, action, resource) when { true } unless
        { true } |caret|;",
        Vec::<String>::new()
    );

    schema_completion_test!(
        dont_suggest_when_outside_multi_conditions_5,
        r"permit(principal, action, resource) when |caret| {
            true
        } unless
        { true };",
        Vec::<String>::new()
    );

    no_schema_completion_test!(
        no_schema_complete_unknown_variable,
        r"permit(principal, action, resource) when { i|caret| };",
        vec![
            "action",
            "context",
            "decimal(${1})",
            "false",
            "has ${1:attribute}",
            "if ${1:true} then ${2:true} else ${3:false}",
            "in ${1:expression}",
            "ip(${1:\"127.0.0.1\"})",
            "like \"${1:pattern}\"",
            "principal",
            "resource",
            "true"
        ]
    );

    no_schema_completion_test!(
        no_schema_record_completions,
        r#"permit (principal, action, resource)when {
        {"attr": 1}.at|caret| };"#,
        vec!["attr"]
    );

    no_schema_completion_test!(
        no_schema_record_nested_completions,
        r#"permit (principal, action, resource)when
        {{"attr": {"nested": 1}}.attr.n|caret|};"#,
        vec!["nested"]
    );

    no_schema_completion_test!(
        no_schema_principal_eq_snippet,
        r"permit (principal == U|caret|, action, resource);",
        vec!["${1:EntityType}::\"${2:id}\"", "?principal"]
    );

    no_schema_completion_test!(
        no_schema_principal_eq_snippet_condition,
        r"permit (principal, action, resource) when { principal == H|caret| };",
        vec![
            "${1:EntityType}::\"${2:id}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    no_schema_completion_test!(
        no_schema_principal_in_snippet,
        r"permit (principal in U|caret|, action, resource);",
        vec!["${1:EntityType}::\"${2:id}\"", "?principal"]
    );

    no_schema_completion_test!(
        no_schema_principal_in_snippet_condition,
        r"permit (principal, action, resource) when { principal in H|caret| };",
        vec![
            "${1:EntityType}::\"${2:id}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    no_schema_completion_test!(
        no_schema_action_eq_snippet,
        r"permit (principal, action == A|caret|, resource);",
        vec!["${1:Action}::\"${2:id}\""]
    );

    no_schema_completion_test!(
        no_schema_action_eq_snippet_condition,
        r"permit (principal, action, resource) when { action == A|caret| };",
        vec![
            "${1:Action}::\"${2:id}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    no_schema_completion_test!(
        no_schema_action_in_snippet,
        r"permit (principal, action in A|caret|, resource);",
        vec!["${1:Action}::\"${2:id}\"", "[${1:Action}::\"${2:id}\"${3}]"]
    );

    no_schema_completion_test!(
        no_schema_action_in_snippet_condition,
        r"permit (principal, action, resource) when { action in A|caret| };",
        vec![
            "${1:Action}::\"${2:id}\"",
            "[${1:Action}::\"${2:id}\"${3}]",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    no_schema_completion_test!(
        no_schema_resource_eq_snippet,
        r"permit (principal, action, resource == U|caret|);",
        vec!["${1:EntityType}::\"${2:id}\"", "?resource"]
    );

    no_schema_completion_test!(
        no_schema_resource_eq_snippet_condition,
        r"permit (principal, action, resource) when { resource == H|caret| };",
        vec![
            "${1:EntityType}::\"${2:id}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    no_schema_completion_test!(
        no_schema_resource_in_snippet,
        r"permit (principal, action, resource in U|caret|);",
        vec!["${1:EntityType}::\"${2:id}\"", "?resource"]
    );

    no_schema_completion_test!(
        no_schema_resource_in_snippet_condition,
        r"permit (principal, action, resource) when { resource in H|caret| };",
        vec![
            "${1:EntityType}::\"${2:id}\"",
            "action",
            "context",
            "principal",
            "resource"
        ]
    );

    no_schema_completion_test!(
        no_schema_dont_complete_while_typing_euid_scope,
        r"permit (principal == Entity::|caret|, action, resource);",
        Vec::<String>::new()
    );

    no_schema_completion_test!(
        no_schema_dont_complete_while_typing_euid_condition,
        r"permit (principal, action, resource) when { Entity::|caret| };",
        Vec::<String>::new()
    );

    no_templates_test! {
        dont_provide_principal_template_completion,
        r"permit(principal == |caret|, action, resource);",
        vec!["User::\"${1:entityId}\""]
    }

    no_templates_test! {
        dont_provide_resource_template_completion,
        r"permit(principal, action, resource == |caret|);",
        vec!["Hotel::\"${1:entityId}\"", "Property::\"${1:entityId}\"", "Reservation::\"${1:entityId}\""]
    }

    no_schema_completion_test!(
        policy_snippets_blank,
        "|caret|",
        vec![
            "forbid(principal${1}, action${2}, resource${3})\nunless {\n\t${4:false}\n};",
            "forbid(principal${1}, action${2}, resource${3})\nwhen {\n\t${4:true}\n};",
            "forbid(principal${1}, action${2}, resource${3});",
            "permit(principal${1}, action${2}, resource${3})\nunless {\n\t${4:false}\n};",
            "permit(principal${1}, action${2}, resource${3})\nwhen {\n\t${4:true}\n};",
            "permit(principal${1}, action${2}, resource${3});"
        ]
    );

    no_schema_completion_test!(
        policy_snippets_after_policy,
        "permit(principal,action, resource);\n |caret|",
        vec![
            "forbid(principal${1}, action${2}, resource${3})\nunless {\n\t${4:false}\n};",
            "forbid(principal${1}, action${2}, resource${3})\nwhen {\n\t${4:true}\n};",
            "forbid(principal${1}, action${2}, resource${3});",
            "permit(principal${1}, action${2}, resource${3})\nunless {\n\t${4:false}\n};",
            "permit(principal${1}, action${2}, resource${3})\nwhen {\n\t${4:true}\n};",
            "permit(principal${1}, action${2}, resource${3});"
        ]
    );

    no_schema_completion_test!(
        policy_snippets_before_policy,
        " |caret|\npermit(principal,action, resource);",
        vec![
            "forbid(principal${1}, action${2}, resource${3})\nunless {\n\t${4:false}\n};",
            "forbid(principal${1}, action${2}, resource${3})\nwhen {\n\t${4:true}\n};",
            "forbid(principal${1}, action${2}, resource${3});",
            "permit(principal${1}, action${2}, resource${3})\nunless {\n\t${4:false}\n};",
            "permit(principal${1}, action${2}, resource${3})\nwhen {\n\t${4:true}\n};",
            "permit(principal${1}, action${2}, resource${3});"
        ]
    );

    no_schema_completion_test!(
        policy_snippets_before_invalid_policy,
        " |caret|\npermit(principal",
        vec![
            "forbid(principal${1}, action${2}, resource${3})\nunless {\n\t${4:false}\n};",
            "forbid(principal${1}, action${2}, resource${3})\nwhen {\n\t${4:true}\n};",
            "forbid(principal${1}, action${2}, resource${3});",
            "permit(principal${1}, action${2}, resource${3})\nunless {\n\t${4:false}\n};",
            "permit(principal${1}, action${2}, resource${3})\nwhen {\n\t${4:true}\n};",
            "permit(principal${1}, action${2}, resource${3});"
        ]
    );

    no_schema_completion_test!(
        no_policy_snippets_after_invalid_policy,
        "permit(principal, action\n |caret|",
        Vec::<String>::new()
    );
}
