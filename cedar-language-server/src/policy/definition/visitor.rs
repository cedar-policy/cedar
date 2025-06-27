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

use std::{sync::Arc, vec};

use cedar_policy_core::validator::{
    types::{EntityRecordKind, Type},
    ValidatorSchema,
};
use cedar_policy_core::{
    ast::{
        ActionConstraint, EntityReference, EntityType, Expr, ExprVisitor, Literal,
        PrincipalOrResourceConstraint, Var,
    },
    parser::Loc,
};
use itertools::Itertools;
use lsp_types::Range;
use smol_str::SmolStr;

use crate::{
    policy::{
        context::ReceiverContext,
        types::{
            cedar::{ContextKind, EntityTypeKind},
            DocumentContext, GetType, TypeInferenceContext,
        },
        SchemaActionLoc,
    },
    utils::{PolicyScopeVariable, ToRange},
};

/// Provides "go to definition" functionality for schema elements in Cedar policies.
///
/// This visitor traverses the Cedar AST to find schema references at the cursor position
/// and locates their definitions in the schema document. It enables
/// "go to definition" for entity types, attributes, actions, and other schema-defined
/// elements within Cedar policies.
///
/// The visitor handles references from both policy scope blocks (principal, action, resource)
/// and condition expressions, mapping them to their corresponding locations in the schema
/// definition file.
///
/// # Supported Schema Elements
///
/// * Entity types (e.g., `User`, `Photo`)
/// * Entity attributes (e.g., `principal.department`, `resource.owner`)
/// * Action definitions (e.g., `Action::"view"`)
/// * Context definitions and their attributes
pub(crate) struct PolicyGotoSchemaDefinition<'a> {
    doc_context: &'a DocumentContext<'a>,
    schema: &'a ValidatorSchema,
}

impl<'a> PolicyGotoSchemaDefinition<'a> {
    fn new(cx: &'a DocumentContext<'_>, schema: &'a ValidatorSchema) -> Self {
        PolicyGotoSchemaDefinition {
            doc_context: cx,
            schema,
        }
    }

    pub(crate) fn get_schema_definition_ranges(
        cx: &DocumentContext<'_>,
        schema: &ValidatorSchema,
    ) -> Option<Vec<Range>> {
        let mut visitor = PolicyGotoSchemaDefinition::new(cx, schema);
        if visitor.doc_context.is_in_scope_block() {
            return visitor.get_scope_ranges();
        }

        let ranges = visitor.visit_expr(cx.policy.non_scope_constraints())?;
        if ranges.is_empty() {
            None
        } else {
            Some(ranges)
        }
    }

    fn get_scope_ranges(&self) -> Option<Vec<Range>> {
        let scope_var = self.doc_context.get_scope_variable_info();
        let ranges = match scope_var.variable_type {
            v @ (PolicyScopeVariable::Principal | PolicyScopeVariable::Resource) => {
                self.p_r_constraint_to_range(v)
            }
            PolicyScopeVariable::Action => self.action_constraint_to_range(),
            PolicyScopeVariable::None => None,
        };
        match ranges {
            Some(ranges) if !ranges.is_empty() => Some(ranges),
            _ => None,
        }
    }

    fn entity_type_to_range(&self, et: &EntityTypeKind) -> Option<Vec<Range>> {
        match et {
            EntityTypeKind::Concrete(entity_type) => {
                let vet = self.schema.get_entity_type(entity_type)?;
                let loc = vet.loc.as_ref()?;
                Some(vec![loc.to_range()])
            }
            EntityTypeKind::AnyPrincipal => {
                let ranges = self
                    .schema
                    .principals()
                    .unique()
                    .sorted()
                    .filter_map(|et| self.schema.get_entity_type(et))
                    .filter_map(|vet| vet.loc.as_ref())
                    .map(ToRange::to_range)
                    .collect::<Vec<Range>>();
                Some(ranges)
            }
            EntityTypeKind::AnyResource => {
                let ranges = self
                    .schema
                    .resources()
                    .unique()
                    .sorted()
                    .filter_map(|et| self.schema.get_entity_type(et))
                    .filter_map(|vet| vet.loc.as_ref())
                    .map(ToRange::to_range)
                    .collect::<Vec<Range>>();
                Some(ranges)
            }
            EntityTypeKind::Set(btree_set) => {
                let ranges = btree_set
                    .iter()
                    .filter_map(|entity_type| {
                        let vet = self.schema.get_entity_type(entity_type)?;
                        let loc = vet.loc.as_ref()?;
                        Some(loc.to_range())
                    })
                    .collect::<Vec<Range>>();
                Some(ranges)
            }
        }
    }

    fn context_type_to_range(&self, ctx: &ContextKind) -> Option<Vec<Range>> {
        let schema = self.doc_context.schema()?;
        match ctx {
            ContextKind::AnyContext => schema
                .action_ids()
                .filter_map(|vat| {
                    if let Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) =
                        vat.context_type()
                    {
                        attrs.keys().peekable().peek()?;
                    }
                    vat.loc()
                })
                .map(SchemaActionLoc::new)
                .filter_map(|s| s.context_loc())
                .unique()
                .map(|loc| loc.to_range())
                .collect::<Vec<Range>>()
                .into(),
            ContextKind::Action(entity_uid) => {
                let vat = schema.get_action_id(entity_uid)?;
                let loc = vat.loc()?;
                let loc = SchemaActionLoc::new(loc).context_loc()?;
                Some(vec![loc.to_range()])
            }
            ContextKind::ActionSet(btree_set) => btree_set
                .iter()
                .filter_map(|entity_uid| {
                    let vat = schema.get_action_id(entity_uid)?;
                    if let Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) =
                        vat.context_type()
                    {
                        attrs.keys().peekable().peek()?;
                    }
                    vat.loc()
                })
                .map(SchemaActionLoc::new)
                .filter_map(|s| s.context_loc())
                .unique()
                .map(|loc| loc.to_range())
                .collect::<Vec<Range>>()
                .into(),
        }
    }

    fn p_r_constraint_to_range(&self, var: PolicyScopeVariable) -> Option<Vec<Range>> {
        let constraint = match var {
            PolicyScopeVariable::Principal => {
                self.doc_context.policy.principal_constraint().as_inner()
            }
            PolicyScopeVariable::Resource => {
                self.doc_context.policy.resource_constraint().as_inner()
            }
            _ => return None,
        };
        let word_under_cursor = self.doc_context.get_word_under_cursor()?;

        if let Some(euid) = constraint.get_euid() {
            if self.doc_context.is_cursor_over_loc(euid.loc()) {
                let vet = self.schema.get_entity_type(euid.entity_type())?;
                let loc = vet.loc.as_ref()?;
                return Some(vec![loc.to_range()]);
            }
        }

        match constraint {
            PrincipalOrResourceConstraint::Is(et)
                if self.doc_context.is_cursor_over_loc(et.loc()) =>
            {
                let vet = self.schema.get_entity_type(et)?;
                let loc = vet.loc.as_ref()?;
                Some(vec![loc.to_range()])
            }
            PrincipalOrResourceConstraint::IsIn(et, ..)
                if self.doc_context.is_cursor_over_loc(et.loc()) =>
            {
                let vet = self.schema.get_entity_type(et)?;
                let loc = vet.loc.as_ref()?;
                Some(vec![loc.to_range()])
            }
            PrincipalOrResourceConstraint::In(EntityReference::EUID(et))
                if self.doc_context.is_cursor_over_loc(et.loc()) =>
            {
                let vet = self.schema.get_entity_type(et.entity_type())?;
                let loc = vet.loc.as_ref()?;
                Some(vec![loc.to_range()])
            }
            PrincipalOrResourceConstraint::Eq(EntityReference::EUID(et))
                if self.doc_context.is_cursor_over_loc(et.loc()) =>
            {
                let vet = self.schema.get_entity_type(et.entity_type())?;
                let loc = vet.loc.as_ref()?;
                Some(vec![loc.to_range()])
            }
            _ if var == PolicyScopeVariable::Principal && word_under_cursor == "principal" => {
                self.entity_type_to_range(&self.doc_context.resolve_principal_type())
            }
            _ if var == PolicyScopeVariable::Resource && word_under_cursor == "resource" => {
                self.entity_type_to_range(&self.doc_context.resolve_resource_type())
            }
            _ => None,
        }
    }

    fn action_constraint_to_range(&self) -> Option<Vec<Range>> {
        let word_under_cursor = self.doc_context.get_word_under_cursor()?;

        for euid in self.doc_context.policy.action_constraint().iter_euids() {
            if self.doc_context.is_cursor_over_loc(euid.loc())
                && euid.to_string().contains(word_under_cursor)
            {
                let vet = self.schema.get_action_id(euid)?;
                let loc = vet.loc()?;
                return Some(vec![loc.to_range()]);
            }
        }

        if word_under_cursor == "action" {
            let ranges = match self.doc_context.policy.action_constraint() {
                ActionConstraint::Any => self
                    .schema
                    .action_ids()
                    .filter_map(|action_id| action_id.loc())
                    .unique()
                    .map(ToRange::to_range)
                    .collect_vec(),
                constraint => constraint
                    .iter_euids()
                    .filter_map(|euid| self.schema.get_action_id(euid))
                    .filter_map(|action_id| action_id.loc())
                    .unique()
                    .map(ToRange::to_range)
                    .collect_vec(),
            };

            return Some(ranges);
        }

        None
    }

    fn visit_attr(
        &mut self,
        expr: &Arc<Expr>,
        attr: &SmolStr,
        loc: Option<&Loc>,
    ) -> Option<Vec<Range>> {
        if self.doc_context.is_cursor_over_loc(loc)
            && self.doc_context.get_word_under_cursor() == attr.as_str().into()
        {
            let mut cx = TypeInferenceContext::from(self.doc_context);
            let rx_cx = ReceiverContext::new(expr.clone());
            let _ = rx_cx.get_type_with_cx(&mut cx)?;
            // visitor only goes up to type before cursor
            cx.add_attr(attr);

            let attrs = cx.get_base_type_attrs();

            if let Some(attrs) = attrs {
                let attrs = cx.follow_attribute_path(attrs);
                return attrs
                    .into_iter()
                    .filter_map(|info| info.attr_type.loc.as_ref())
                    .map(ToRange::to_range)
                    .collect_vec()
                    .into();
            }
        }

        self.visit_expr(expr)
    }
}

impl ExprVisitor for PolicyGotoSchemaDefinition<'_> {
    type Output = Vec<Range>;

    fn visit_var(&mut self, var: Var, loc: Option<&Loc>) -> Option<Self::Output> {
        if self.doc_context.is_cursor_over_loc(loc) {
            return match var {
                Var::Principal => {
                    let principal_type = self.doc_context.resolve_principal_type();
                    self.entity_type_to_range(&principal_type)
                }
                Var::Action => self.action_constraint_to_range(),
                Var::Resource => {
                    let resource_type = self.doc_context.resolve_resource_type();
                    self.entity_type_to_range(&resource_type)
                }
                Var::Context => {
                    let context_type = self.doc_context.resolve_context_type();
                    self.context_type_to_range(&context_type)
                }
            };
        }

        None
    }

    fn visit_literal(&mut self, lit: &Literal, _loc: Option<&Loc>) -> Option<Self::Output> {
        if let Literal::EntityUID(euid) = lit {
            if self.doc_context.is_cursor_over_loc(euid.loc()) {
                let vet = self.schema.get_entity_type(euid.entity_type())?;
                let loc = vet.loc.as_ref()?;
                return Some(vec![loc.to_range()]);
            }
        }
        None
    }

    fn visit_is(
        &mut self,
        expr: &Arc<Expr>,
        entity_type: &EntityType,
        _loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        if self.doc_context.is_cursor_over_loc(entity_type.loc()) {
            let vet = self.schema.get_entity_type(entity_type)?;
            let loc = vet.loc.as_ref()?;
            return Some(vec![loc.to_range()]);
        }

        self.visit_expr(expr)
    }

    fn visit_get_attr(
        &mut self,
        expr: &Arc<Expr>,
        attr: &SmolStr,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_attr(expr, attr, loc)
    }

    fn visit_has_attr(
        &mut self,
        expr: &Arc<Expr>,
        attr: &SmolStr,
        loc: Option<&Loc>,
    ) -> Option<Self::Output> {
        self.visit_attr(expr, attr, loc)
    }
}
