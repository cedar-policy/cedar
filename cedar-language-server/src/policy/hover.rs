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

use crate::{
    documentation::{
        ActionDocumentation, EqualsDocumentation, InDocumentation, IsDocumentation,
        PrincipalDocumentation, ResourceDocumentation, ToDocumentationString,
    },
    policy::types::cedar::CedarTypeKind,
    utils::{PolicyScopeVariable, ToRange},
};
use cedar_policy_core::ast::{
    ActionConstraint, ExprVisitor, PolicyID, PrincipalConstraint, PrincipalOrResourceConstraint,
    ResourceConstraint,
};
use cedar_policy_core::validator::ValidatorSchema;
use lsp_types::{Hover, HoverContents, MarkupKind, Position};
use visitor::HoverVisitor;

use crate::{schema::SchemaInfo, utils::position_within_loc};

use super::types::{cedar::EntityTypeKind, DocumentContext, PolicyLanguageFeatures};

mod visitor;

/// Provides hover documentation for Cedar policy elements at a specified position.
///
/// This function analyzes the Cedar policy content at the given cursor position
/// and generates appropriate hover documentation based on the element under the cursor.
/// It supports hover information for both policy scope declarations (principal, action,
/// resource) and condition expressions.
///
/// When schema information is provided, the documentation is enriched with
/// type details and available attributes specific to the hovered element.
///
/// # Returns
///
/// An `Option<Hover>` containing LSP hover information for the element under the cursor,
/// or `None` if no relevant documentation can be provided.
#[must_use]
pub fn policy_hover(
    position: Position,
    policy_string: &str,
    schema: Option<SchemaInfo>,
) -> Option<Hover> {
    let cst = cedar_policy_core::parser::text_to_cst::parse_policies(policy_string)
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

    let validator = schema.and_then(|schema| ValidatorSchema::try_from(&schema).ok());

    let d_cx = DocumentContext::new(
        validator,
        policy,
        policy_string,
        position,
        PolicyLanguageFeatures::default(),
    );

    if d_cx.is_in_scope_block() {
        let scope_info = d_cx.get_scope_variable_info();
        match scope_info.variable_type {
            PolicyScopeVariable::Principal => {
                return d_cx.policy.principal_constraint().to_hover(&d_cx)
            }
            PolicyScopeVariable::Action => return d_cx.policy.action_constraint().to_hover(&d_cx),
            PolicyScopeVariable::Resource => {
                return d_cx.policy.resource_constraint().to_hover(&d_cx)
            }
            PolicyScopeVariable::None => return None,
        };
    }

    let mut hover_visitor = HoverVisitor::new(&d_cx);
    hover_visitor.visit_expr(&d_cx.policy.condition())
}

trait ToHover {
    fn to_hover(&self, cx: &DocumentContext<'_>) -> Option<Hover>;

    fn to_hover_with_range(
        &self,
        cx: &DocumentContext<'_>,
        range: lsp_types::Range,
    ) -> Option<Hover> {
        self.to_hover(cx).map(|mut h| {
            h.range = Some(range);
            h
        })
    }
}

impl<T> ToHover for T
where
    T: ToDocumentationString,
{
    fn to_hover(&self, cx: &DocumentContext<'_>) -> Option<Hover> {
        Some(Hover {
            contents: HoverContents::Markup(lsp_types::MarkupContent {
                kind: MarkupKind::Markdown,
                value: self.to_documentation_string(cx.schema()).into_owned(),
            }),
            range: None,
        })
    }
}

impl ToHover for ActionConstraint {
    fn to_hover(&self, cx: &DocumentContext<'_>) -> Option<Hover> {
        let word_under_cursor = cx.get_word_under_cursor()?;

        for euid in self.iter_euids() {
            if cx.is_cursor_over_loc(euid.loc()) && euid.to_string().contains(word_under_cursor) {
                let loc = euid.loc()?;
                return euid.to_hover_with_range(cx, loc.to_range());
            }
        }

        if word_under_cursor == "action" {
            return ActionDocumentation::new(Some(self)).to_hover(cx);
        }

        if word_under_cursor == "in" {
            return InDocumentation.to_hover(cx);
        }

        if word_under_cursor == "==" {
            return EqualsDocumentation.to_hover(cx);
        }

        None
    }
}

impl ToHover for PrincipalConstraint {
    fn to_hover(&self, cx: &DocumentContext<'_>) -> Option<Hover> {
        let word_under_cursor = cx.get_word_under_cursor()?;

        let euid = self.as_inner().get_euid();
        if let Some(euid) = euid {
            if cx.is_cursor_over_loc(euid.loc()) && euid.to_string().contains(word_under_cursor) {
                let ty: CedarTypeKind = euid.as_ref().into();
                let loc = euid.loc()?;
                return ty.to_hover_with_range(cx, loc.to_range());
            }
        }

        if let PrincipalOrResourceConstraint::Is(et) = self.as_inner() {
            if word_under_cursor == "is" {
                return IsDocumentation.to_hover(cx);
            }
            if cx.is_cursor_over_loc(et.loc()) {
                return et.to_hover(cx);
            }
        }

        if word_under_cursor == "principal" {
            let principal_type = cx.resolve_principal_type();
            return PrincipalDocumentation::new(principal_type).to_hover(cx);
        }

        if word_under_cursor == "in" {
            return InDocumentation.to_hover(cx);
        }

        if word_under_cursor == "is" {
            return IsDocumentation.to_hover(cx);
        }

        if word_under_cursor == "==" {
            return EqualsDocumentation.to_hover(cx);
        }

        None
    }
}

impl ToHover for ResourceConstraint {
    fn to_hover(&self, cx: &DocumentContext<'_>) -> Option<Hover> {
        let word_under_cursor = cx.get_word_under_cursor()?;

        let euid = self.as_inner().get_euid();
        if let Some(euid) = euid {
            if cx.is_cursor_over_loc(euid.loc()) && euid.to_string().contains(word_under_cursor) {
                let ty: CedarTypeKind = euid.as_ref().into();
                let loc = euid.loc()?;
                return ty.to_hover_with_range(cx, loc.to_range());
            }
        }

        if let PrincipalOrResourceConstraint::Is(et) = self.as_inner() {
            if word_under_cursor == "is" {
                return IsDocumentation.to_hover(cx);
            }
            if cx.is_cursor_over_loc(et.loc()) {
                let ty = CedarTypeKind::EntityType(EntityTypeKind::Concrete(et.clone()));
                return ty.to_hover(cx);
            }
        }

        if word_under_cursor == "resource" {
            let resource_type = cx.resolve_resource_type();
            return ResourceDocumentation::new(resource_type).to_hover(cx);
        }

        if word_under_cursor == "in" {
            return InDocumentation.to_hover(cx);
        }

        if word_under_cursor.contains('=') {
            return EqualsDocumentation.to_hover(cx);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use super::policy_hover;
    use crate::{
        documentation::{
            ActionDocumentation, AddDocumentation, AndDocumentation, BoolDocumentation,
            ContainsAllDocumentation, ContainsAnyDocumentation, ContainsDocumentation,
            DecimalDocumentation, DecimalGreaterThanDocumentation,
            DecimalGreaterThanOrEqualDocumentation, DecimalLessThanDocumentation,
            DecimalLessThanOrEqualDocumentation, EqualsDocumentation, GreaterThanDocumentation,
            GreaterThanOrEqualsDocumentation, HasDocumentation, IfDocumentation, InDocumentation,
            IpDocumentation, IsDocumentation, IsEmptyDocumentation, IsInRangeDocumentation,
            IsIpv4Documentation, IsIpv6Documentation, IsLoopbackDocumentation,
            IsMulticastDocumentation, LessThanDocumentation, LessThanOrEqualsDocumentation,
            LongDocumentation, MultiplyDocumentation, NotDocumentation, NotEqualsDocumentation,
            OrDocumentation, PrincipalDocumentation, ResourceDocumentation, SetDocumentation,
            StringDocumentation, SubtractDocumentation,
        },
        policy::{cedar::EntityTypeKind, hover::ToHover, types::cedar::CedarTypeKind},
        utils::tests::{remove_caret_marker, schema_document_context, schema_info},
    };
    use cedar_policy_core::ast::EntityType;

    use tracing_test::traced_test;

    macro_rules! schema_hover_test {
        ($name:ident, $policy:expr, ty: $expected:ty) => {
            #[test]
            #[traced_test]
            fn $name() {
                let (policy, position) = remove_caret_marker($policy);
                let hover = policy_hover(
                    position,
                    &policy,
                    schema_info("policies.cedarschema").into(),
                );
                let cx = schema_document_context(&policy, position);

                let expected_type = <$expected>::from(&cx);
                match (expected_type.to_hover(&cx), hover) {
                    (Some(expected), Some(actual)) => {
                        assert_eq!(expected.contents, actual.contents);
                        if let (Some(expected_range), Some(actual_range)) =
                            (expected.range, actual.range)
                        {
                            assert_eq!(expected_range, actual_range);
                        }
                    }
                    (expected, actual) => {
                        panic!(
                            "Hover mismatch:nExpected: {:?}nActual: {:?}",
                            expected, actual
                        );
                    }
                }
            }
        };

        ($name:ident, $policy:expr, expr: $expected:expr) => {
            #[test]
            #[traced_test]
            fn $name() {
                let (policy, position) = remove_caret_marker($policy);
                let hover = policy_hover(
                    position,
                    &policy,
                    schema_info("policies.cedarschema").into(),
                );
                let cx = schema_document_context(&policy, position);

                match ($expected.to_hover(&cx), hover) {
                    (None, None) => (),
                    (Some(expected), Some(actual)) => {
                        assert_eq!(expected.contents, actual.contents);
                        if let (Some(expected_range), Some(actual_range)) =
                            (expected.range, actual.range)
                        {
                            assert_eq!(expected_range, actual_range);
                        }
                    }
                    (expected, actual) => {
                        panic!(
                            "Hover mismatch:nExpected: {:?}nActual: {:?}",
                            expected, actual
                        );
                    }
                }
            }
        };
    }

    schema_hover_test!(
        hover_over_principal_in_scope,
        r"permit(pri|caret|ncipal is User, action, resource) when { true };",
        ty: PrincipalDocumentation
    );

    schema_hover_test!(
        hover_over_action_in_scope,
        r"permit(principal is User, act|caret|ion, resource) when { true };",
        ty: ActionDocumentation<'_>
    );

    schema_hover_test!(
        hover_over_resource_in_scope,
        r"permit(principal is User, action, resou|caret|rce) when { true };",
        ty: ResourceDocumentation
    );

    schema_hover_test!(
        hover_over_resource_in_scope_multiline,
        "permit(principal is User,action,\nresou|caret|rce) when { true };",
        ty: ResourceDocumentation
    );

    schema_hover_test!(
        hover_over_in_within_scope,
        r#"permit(principal i|caret|n User::"bob", action, resource) when { true };"#,
        expr: InDocumentation
    );

    schema_hover_test!(
        hover_over_in_within_scope_multiline,
        "permit(principal\n i|caret|n\n User::\"bob\", action, resource) when { true };",
        expr: InDocumentation
    );

    schema_hover_test!(
        hover_over_in_within_principal_dec,
        r#"permit(principal i|caret|n User::"bob", action, resource) when { true };"#,
        expr: InDocumentation
    );

    schema_hover_test!(
        hover_over_in_within_action_dec,
        r#"permit(principal in User::"bob", action i|caret|n Action::"foo", resource) when { true };"#,
        expr: InDocumentation
    );

    schema_hover_test!(
        hover_over_in_within_resource_dec,
        r#"permit(principal in User::"bob", action in Action::"foo", resource i|caret|n Hotel::"bar") when { true };"#,
        expr: InDocumentation
    );

    schema_hover_test!(
        hover_over_eq_within_principal_dec,
        r#"permit(principal =|caret|= User::"bob", action, resource) when { true };"#,
        expr: EqualsDocumentation
    );

    schema_hover_test!(
        hover_over_eq_within_action_dec,
        r#"permit(principal in User::"bob", action =|caret|= Action::"foo", resource) when { true };"#,
        expr: EqualsDocumentation
    );

    schema_hover_test!(
        hover_over_eq_within_resource_dec,
        r#"permit(principal in User::"bob", action in Action::"foo", resource =|caret|= Hotel::"bar") when { true };"#,
        expr: EqualsDocumentation
    );

    schema_hover_test!(
        hover_over_is_entity_type_within_principal_dec,
        r"permit(principal is Us|caret|er, action, resource) when { true };",
        expr: entity_type("User")
    );

    schema_hover_test!(
        hover_over_is_entity_type_within_resource_dec,
        r"permit(principal, action, resource is Hot|caret|el) when { true };",
        expr: entity_type("Hotel")
    );

    schema_hover_test!(
        hover_over_is_entity_type_within_resource_dec_multiline,
        "permit(principal, \naction, resource \nis\n\n Hot|caret|el) when { true };",
        expr: entity_type("Hotel")
    );

    schema_hover_test!(
        hover_over_true_in_condition,
        r"permit(principal is User, action, resource) when { tr|caret|ue };",
        expr: BoolDocumentation
    );

    schema_hover_test!(
        hover_over_false_in_condition,
        r"permit(principal, action, resource) when { fa|caret|lse };",
        expr: BoolDocumentation
    );

    schema_hover_test!(
        hover_over_contains,
        r"permit(principal, action, resource) when { [].cont|caret|ains({}) };",
        expr: ContainsDocumentation
    );

    schema_hover_test!(
        hover_over_contains_all,
        r"permit(principal, action, resource) when { [].cont|caret|ainsAll([]) };",
        expr: ContainsAllDocumentation
    );

    schema_hover_test!(
        hover_over_contains_any,
        r"permit(principal, action, resource) when { [].cont|caret|ainsAny([]) };",
        expr: ContainsAnyDocumentation
    );

    schema_hover_test!(
        hover_over_contains_is_empty,
        r"permit(principal, action, resource) when { [].is|caret|Empty() };",
        expr: IsEmptyDocumentation
    );

    schema_hover_test!(
        hover_over_not,
        r"permit(principal, action, resource) when { |caret|![].isEmpty() };",
        expr: NotDocumentation
    );

    schema_hover_test!(
        hover_over_principal_in_condition,
        r"permit(principal, action, resource) when { pri|caret|ncipal.hotelAdminPermissions.isEmpty() };",
        ty: PrincipalDocumentation
    );

    schema_hover_test!(
        hover_over_action_in_condition,
        r"permit(principal, action, resource) when { acti|caret|on };",
        ty: ActionDocumentation<'_>
    );

    schema_hover_test!(
        hover_over_resource_in_condition,
        r"permit(principal, action, resource) when { res|caret|ource };",
        ty: ResourceDocumentation
    );

    schema_hover_test!(
        hover_over_set,
        r"permit(principal, action, resource) when { principal.hotelAd|caret|minPermissions.isEmpty() };",
        expr: SetDocumentation::new("Hotel".to_string())
    );

    schema_hover_test!(
        hover_over_in_within_condition,
        r"permit(principal, action, resource) when { principal i|caret|n [] };",
        expr: InDocumentation
    );

    schema_hover_test!(
        hover_over_eq_within_condition,
        r"permit(principal, action, resource) when { principal =|caret|= principal };",
        expr: EqualsDocumentation
    );

    schema_hover_test!(
        hover_over_not_eq,
        r"permit(principal, action, resource) when { principal !|caret|= principal };",
        expr: NotEqualsDocumentation
    );

    schema_hover_test!(
        hover_over_greater,
        r"permit(principal, action, resource) when { 1 |caret|> 1 };",
        expr: GreaterThanDocumentation
    );

    schema_hover_test!(
        hover_over_greater_than_eq,
        r"permit(principal, action, resource) when { 1 |caret|>= 1 };",
        expr: GreaterThanOrEqualsDocumentation
    );

    schema_hover_test!(
        hover_over_less,
        r"permit(principal, action, resource) when { 1 |caret|< 1 };",
        expr: LessThanDocumentation
    );

    schema_hover_test!(
        hover_over_less_than_eq,
        r"permit(principal, action, resource) when { 1 |caret|<= 1 };",
        expr: LessThanOrEqualsDocumentation
    );

    schema_hover_test!(
        hover_over_and,
        r"permit(principal, action, resource) when { principal.bool &|caret|& true };",
        expr: AndDocumentation
    );

    schema_hover_test!(
        hover_over_or,
        r"permit(principal, action, resource) when { true |caret||| principal.bool };",
        expr: OrDocumentation
    );

    schema_hover_test!(
        hover_over_ip,
        r#"permit(principal, action, resource) when { i|caret|p("127.0.0.1") };"#,
        expr: IpDocumentation
    );

    schema_hover_test!(
        hover_over_ip_ipv4,
        r#"permit(principal, action, resource) when { ip("127.0.0.1").i|caret|sIpv4() };"#,
        expr: IsIpv4Documentation
    );

    schema_hover_test!(
        hover_over_ip_ipv6,
        r#"permit(principal, action, resource) when { ip("127.0.0.1").i|caret|sIpv6() };"#,
        expr: IsIpv6Documentation
    );

    schema_hover_test!(
        hover_over_ip_loopback,
        r#"permit(principal, action, resource) when { ip("127.0.0.1").i|caret|sLoopback() };"#,
        expr: IsLoopbackDocumentation
    );

    schema_hover_test!(
        hover_over_ip_multicast,
        r#"permit(principal, action, resource) when { ip("127.0.0.1").i|caret|sMulticast() };"#,
        expr: IsMulticastDocumentation
    );

    schema_hover_test!(
        hover_over_ip_range,
        r#"permit(principal, action, resource) when { ip("127.0.0.1").i|caret|sInRange() };"#,
        expr: IsInRangeDocumentation
    );

    schema_hover_test!(
        hover_over_decimal,
        r#"permit(principal, action, resource) when { d|caret|ecimal("1.23") };"#,
        expr: DecimalDocumentation
    );

    schema_hover_test!(
        hover_over_decimal_less_than,
        r#"permit(principal, action, resource) when { decimal("1.23").l|caret|essThan(decimal("2.34")) };"#,
        expr: DecimalLessThanDocumentation
    );

    schema_hover_test!(
        hover_over_decimal_less_than_or_equal,
        r#"permit(principal, action, resource) when { decimal("1.23").l|caret|essThanOrEqual(decimal("2.34")) };"#,
        expr: DecimalLessThanOrEqualDocumentation
    );

    schema_hover_test!(
        hover_over_decimal_greater_than,
        r#"permit(principal, action, resource) when { decimal("3.45").g|caret|reaterThan(decimal("2.34")) };"#,
        expr: DecimalGreaterThanDocumentation
    );

    schema_hover_test!(
        hover_over_decimal_greater_than_or_equal,
        r#"permit(principal, action, resource) when { decimal("3.45").g|caret|reaterThanOrEqual(decimal("2.34")) };"#,
        expr: DecimalGreaterThanOrEqualDocumentation
    );

    schema_hover_test!(
        hover_over_add_within_condition,
        r"permit(principal, action, resource) when { 1 |caret|+ 1 == 2 };",
        expr: AddDocumentation
    );

    schema_hover_test!(
        hover_over_sub_within_condition,
        r"permit(principal, action, resource) when { 1 |caret|- 1 == 2 };",
        expr: SubtractDocumentation
    );

    schema_hover_test!(
        hover_over_mul_within_condition,
        r"permit(principal, action, resource) when { 1 |caret|* 1 == 2 };",
        expr: MultiplyDocumentation
    );

    schema_hover_test!(
        hover_over_long_within_condition,
        r"permit(principal, action, resource) when { |caret|1 * 1 == 2 };",
        expr: LongDocumentation
    );

    schema_hover_test!(
        hover_over_string_within_condition,
        r#"permit(principal, action, resource) when { "h|caret|ello" == "hello" };"#,
        expr: StringDocumentation
    );

    schema_hover_test!(
        hover_over_entity_literal_within_condition,
        r#"permit(principal, action, resource) when { Us|caret|er::"cole" == principal };"#,
        expr: entity_type("User")
    );

    schema_hover_test!(
        hover_over_is_operator_type_within_condition,
        r"permit(principal, action, resource) when { principal i|caret|s User };",
        expr: IsDocumentation
    );

    schema_hover_test!(
        hover_over_is_entity_type_within_condition,
        r"permit(principal, action, resource) when { principal is Us|caret|er };",
        expr: entity_type("User")
    );

    schema_hover_test!(
        hover_over_if_if_keyword,
        r"permit(principal, action, resource) when { i|caret|f true then true else false };",
        expr: IfDocumentation
    );

    schema_hover_test!(
        hover_over_if_then_keyword,
        r"permit(principal, action, resource) when { if true th|caret|en true else false };",
        expr: IfDocumentation
    );

    schema_hover_test!(
        hover_over_if_else_keyword,
        r"permit(principal, action, resource) when { if true then true el|caret|se false };",
        expr: IfDocumentation
    );

    schema_hover_test!(
        hover_over_within_if,
        r"permit(principal, action, resource) when { if tr|caret|ue then true else false };",
        expr: BoolDocumentation
    );

    schema_hover_test!(
        hover_over_has,
        r"permit(principal, action, resource) when { principal h|caret|as attr };",
        expr: HasDocumentation
    );

    fn entity_type(name: &str) -> CedarTypeKind {
        CedarTypeKind::EntityType(EntityTypeKind::Concrete(Arc::new(
            EntityType::from_str(name).unwrap(),
        )))
    }
}
