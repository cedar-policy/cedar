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

fn type_depth(ty: &Node<Type>) -> usize {
    let mut max = 0;
    let mut stack = vec![(ty, 0)];
    while let Some((ty, depth)) = stack.pop() {
        max = max.max(depth);
        match &ty.node {
            Type::Ident(_) => {}
            Type::Set(inner) => stack.push((inner.as_ref(), depth + 1)),
            Type::Record(attrs) => {
                stack.extend(attrs.iter().map(|attr| (&attr.node.data.ty, depth + 1)));
            }
        }
    }
    max
}
