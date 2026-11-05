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

//! Stack-safe depth computation for the Cedar schema syntax AST

use itertools::Either;
use yaspar_macros::stack_safe;

use super::ast::{ActionDecl, Annotated, AppDecl, AttrDecl, Declaration, EntityDecl, Schema, Type};
use crate::parser::Node;

/// The nesting depth of the deepest type in `schema`, as written
pub(crate) fn schema_type_depth(schema: &Schema) -> usize {
    schema
        .iter()
        .flat_map(|ns| &ns.data.decls)
        .map(|decl| match &decl.data.node {
            Declaration::Type(decl) => type_depth(&decl.def),
            Declaration::Entity(EntityDecl::Standard(decl)) => {
                record_depth(&decl.attrs.node).max(decl.tags.as_ref().map_or(0, type_depth))
            }
            Declaration::Entity(EntityDecl::Enum(_) | EntityDecl::External(_)) => 0,
            Declaration::Action(ActionDecl::Defined(decl)) => decl
                .app_decls
                .iter()
                .flat_map(|decls| &decls.node)
                .map(|decl| match &decl.node {
                    AppDecl::Context(Either::Right(attrs)) => record_depth(&attrs.node),
                    AppDecl::Context(Either::Left(_)) | AppDecl::PR(_) => 0,
                })
                .max()
                .unwrap_or(0),
            Declaration::Action(ActionDecl::External(_)) => 0,
        })
        .max()
        .unwrap_or(0)
}

fn record_depth(attrs: &[Node<Annotated<AttrDecl>>]) -> usize {
    attrs
        .iter()
        .map(|attr| 1 + type_depth(&attr.node.data.ty))
        .max()
        .unwrap_or(0)
}

#[stack_safe]
fn type_depth(ty: &Node<Type>) -> usize {
    match &ty.node {
        Type::Ident(_) => 0,
        Type::Set(inner) => 1 + type_depth(inner),
        Type::Record(attrs) => {
            let mut depth = 0;
            for attr in attrs {
                depth = depth.max(1 + type_depth(&attr.node.data.ty));
            }
            depth
        }
    }
}
