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

//! AST types for the Cedar entity data syntax

use std::collections::BTreeMap;

use crate::ast::{Annotation, Annotations, AnyId};
use crate::parser::Node;
use smol_str::SmolStr;

use super::err::UserError;

/// Top-level parse result: a list of annotated namespaces
pub type EntityDataAst = Vec<Annotated<EntityNamespace>>;

/// A value with associated annotations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotated<T> {
    /// The annotated data
    pub data: T,
    /// Annotations
    pub annotations: Annotations,
}

/// A namespace block containing instance declarations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityNamespace {
    /// Namespace path (None for top-level bare declarations)
    pub name: Option<Node<Vec<Node<SmolStr>>>>,
    /// Instance declarations within this namespace
    pub instances: Vec<Annotated<Node<EntityInstance>>>,
}

/// A single entity instance declaration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityInstance {
    /// The entity reference (Type::"id")
    pub entity_ref: Node<EntityReference>,
    /// Parent entities (`in [...]` or `in EntityRef`)
    pub parents: Vec<Node<EntityReference>>,
    /// Attributes (`= { ... }` or `{ ... }`)
    pub attrs: Option<Node<Vec<(Node<SmolStr>, Node<EntityValue>)>>>,
    /// Tags (`tags { ... }`)
    pub tags: Option<Node<Vec<(Node<SmolStr>, Node<EntityValue>)>>>,
}

/// A typed entity reference: Type::"id" or Namespace::Type::"id"
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityReference {
    /// Type path segments (e.g., ["PhotoApp", "User"] or ["User"])
    pub type_path: Vec<Node<SmolStr>>,
    /// Entity ID string
    pub id: SmolStr,
}

/// A value in entity data
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityValue {
    /// An integer literal
    Long(i64),
    /// A string literal
    String(SmolStr),
    /// A boolean literal
    Bool(bool),
    /// An entity reference
    EntityRef(Node<EntityReference>),
    /// A set literal
    Set(Vec<Node<EntityValue>>),
    /// A record literal
    Record(Vec<(Node<SmolStr>, Node<EntityValue>)>),
    /// An extension function call
    ExtensionCall {
        /// Function name path (e.g., ["ip"] or ["decimal"])
        fn_name: Vec<Node<SmolStr>>,
        /// Arguments
        args: Vec<Node<EntityValue>>,
    },
}

/// Deduplicate annotations, returning an error if duplicates are found
#[expect(
    clippy::type_complexity,
    reason = "complex generic type required by LALRPOP grammar actions"
)]
pub fn deduplicate_annotations<T>(
    data: T,
    annotations: Vec<Node<(Node<AnyId>, Option<Node<SmolStr>>)>>,
) -> Result<Annotated<T>, UserError> {
    let mut unique_annotations: BTreeMap<Node<AnyId>, Option<Node<SmolStr>>> = BTreeMap::new();
    for annotation in annotations {
        let (key, value) = annotation.node;
        if let Some((old_key, _)) = unique_annotations.get_key_value(&key) {
            return Err(UserError::DuplicateAnnotations(
                key.node.clone(),
                Node::with_maybe_source_loc((), old_key.loc.clone()),
                Node::with_maybe_source_loc((), key.loc),
            ));
        } else {
            unique_annotations.insert(key, value);
        }
    }
    Ok(Annotated {
        data,
        annotations: unique_annotations
            .into_iter()
            .map(|(key, value)| {
                let (val, loc) = match value {
                    Some(n) => (Some(n.node), n.loc),
                    None => (None, None),
                };
                (key.node, Annotation::with_optional_value(val, loc))
            })
            .collect(),
    })
}
