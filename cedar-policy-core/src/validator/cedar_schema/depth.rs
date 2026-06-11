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

//! Iterative depth computation for Cedar schema type AST.

use itertools::Either;

use super::ast::{ActionDecl, AppDecl, Declaration, EntityDecl, Namespace, Schema, Type};
use crate::parser::Node;

/// Iteratively compute the maximum nesting depth across all types in a schema.
pub(crate) fn schema_type_depth(schema: &Schema) -> usize {
    schema
        .iter()
        .map(|ns| namespace_type_depth(&ns.data))
        .max()
        .unwrap_or(0)
}

fn namespace_type_depth(ns: &Namespace) -> usize {
    ns.decls
        .iter()
        .map(|d| declaration_type_depth(&d.data.node))
        .max()
        .unwrap_or(0)
}

fn declaration_type_depth(decl: &Declaration) -> usize {
    match decl {
        Declaration::Entity(entity_decl) => entity_decl_type_depth(entity_decl),
        Declaration::Action(action_decl) => action_decl_type_depth(action_decl),
        Declaration::Type(type_decl) => type_depth(&type_decl.def),
    }
}

fn entity_decl_type_depth(decl: &EntityDecl) -> usize {
    match decl {
        EntityDecl::Standard(standard) => {
            let attrs_d = standard
                .attrs
                .node
                .iter()
                .map(|a| 1 + type_depth(&a.node.data.ty))
                .max()
                .unwrap_or(0);
            let tags_d = standard
                .tags
                .iter()
                .map(|a| type_depth(&a))
                .max()
                .unwrap_or(0);
            attrs_d.max(tags_d)
        }
        EntityDecl::Enum(_) => 0,
    }
}

fn action_decl_type_depth(decl: &ActionDecl) -> usize {
    let Some(app_decls) = &decl.app_decls else {
        return 0;
    };
    app_decls
        .node
        .iter()
        .map(|decl| app_decl_type_depth(&decl.node))
        .max()
        .unwrap_or(0)
}

fn app_decl_type_depth(decl: &AppDecl) -> usize {
    match decl {
        AppDecl::Context(Either::Right(attrs)) => attrs
            .node
            .iter()
            .map(|a| 1 + type_depth(&a.node.data.ty))
            .max()
            .unwrap_or(0),
        AppDecl::PR(_) | AppDecl::Context(Either::Left(_)) => 0,
    }
}

fn type_depth(root: &Node<Type>) -> usize {
    let mut stack: Vec<(&Node<Type>, usize)> = vec![(root, 0)];
    let mut max_depth: usize = 0;

    while let Some((ty, depth)) = stack.pop() {
        max_depth = max_depth.max(depth);

        match &ty.node {
            Type::Ident(_) => {}
            Type::Set(inner) => {
                stack.push((inner, depth + 1));
            }
            Type::Record(attrs) => {
                for attr_node in attrs {
                    stack.push((&attr_node.node.data.ty, depth + 1));
                }
            }
        }
    }

    max_depth
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::cedar_schema::parser::parse_schema;
    use rstest::rstest;

    fn schema_depth_of(src: &str) -> usize {
        let schema = parse_schema(src).expect("parse failed");
        schema_type_depth(&schema)
    }

    #[rstest]
    #[case::primitive_entity("entity Foo;", 0)]
    #[case::entity_with_attribute("entity Foo = { bar: Long };", 1)]
    #[case::nested_record("entity Foo = { bar: { baz: Long } };", 2)]
    #[case::set_of_long("entity Foo = { bar: Set<Long> };", 2)]
    #[case::set_of_set("entity Foo = { bar: Set<Set<Long>> };", 3)]
    #[case::deeply_nested_record("entity Foo = { a: { b: { c: Long } } };", 3)]
    #[case::common_type("type T = Set<Set<Long>>;", 2)]
    #[case::entity_tags("entity Foo tags Set<Long>;", 1)]
    #[case::entity_tags_nested("entity Foo tags Set<Set<Long>>;", 2)]
    #[case::enum_entity(r#"entity Flavor enum ["Vanilla", "Chocolate"];"#, 0)]
    #[case::action_context(
        "entity User; entity File; action Read appliesTo { principal: User, resource: File, context: { level: Set<Long> } };",
        2
    )]
    #[case::multiple_namespaces(
        "namespace A { entity Foo = { x: Long }; } namespace B { entity Bar = { x: { y: { z: Long } } }; }",
        3
    )]
    fn schema_depth(#[case] src: &str, #[case] expected: usize) {
        assert_eq!(schema_depth_of(src), expected);
    }
}
