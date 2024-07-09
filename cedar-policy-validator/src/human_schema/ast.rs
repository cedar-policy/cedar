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

use std::iter::once;

use cedar_policy_core::{
    ast::Id,
    parser::{Loc, Node},
};
use itertools::{Either, Itertools};
use nonempty::NonEmpty;
use smol_str::SmolStr;
// We don't need this import on macOS but CI fails without it
#[allow(unused_imports)]
use smol_str::ToSmolStr;

use crate::{RawName, SchemaTypeVariant};

pub const BUILTIN_TYPES: [&str; 3] = ["Long", "String", "Bool"];

pub(super) const CEDAR_NAMESPACE: &str = "__cedar";

pub type Schema = Vec<Node<Namespace>>;

/// A path is a non empty list of identifiers that forms a namespace + type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Path(Node<PathInternal>);
impl Path {
    /// Create a [`Path`] with a single entry
    pub fn single(basename: Id, loc: Loc) -> Self {
        Self(Node::with_source_loc(
            PathInternal {
                basename,
                namespace: vec![],
            },
            loc,
        ))
    }

    /// Create [`Path`] with a head and an iterator. Most significant name first.
    pub fn new(basename: Id, namespace: impl IntoIterator<Item = Id>, loc: Loc) -> Self {
        let namespace = namespace.into_iter().collect();
        Self(Node::with_source_loc(
            PathInternal {
                basename,
                namespace,
            },
            loc,
        ))
    }

    /// Borrowed iteration of the [`Path`]'s elements. Most significant name first
    pub fn iter(&self) -> impl Iterator<Item = &Id> {
        self.0.node.iter()
    }

    /// Source [`Loc`] of this [`Path`]
    pub fn loc(&self) -> &Loc {
        &self.0.loc
    }

    /// Consume the [`Path`] and get an owned iterator over the elements. Most significant name first
    pub fn into_iter(self) -> impl Iterator<Item = Node<Id>> {
        let loc = self.0.loc;
        self.0
            .node
            .into_iter()
            .map(move |x| Node::with_source_loc(x, loc.clone()))
    }

    /// Get the base type name as well as the (potentially empty) prefix
    pub fn split_last(self) -> (Vec<Id>, Id) {
        (self.0.node.namespace, self.0.node.basename)
    }

    /// Is this referring to a name in the `__cedar` namespace (eg: `__cedar::Bool`) or the unqualified namespace
    pub fn is_in_unqualified_or_cedar(&self) -> bool {
        self.0.node.is_in_unqualified_or_cedar()
    }

    /// Is this referring to a name in the `__cedar` namespace (eg: `__cedar::Bool`)
    pub fn is_in_cedar(&self) -> bool {
        self.0.node.is_in_cedar()
    }

    /// Is this name exactly the cedar namespace?
    pub fn is_cedar(&self) -> bool {
        self.0.node.is_cedar()
    }
}

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.node)
    }
}

impl From<Path> for RawName {
    fn from(value: Path) -> Self {
        RawName::from_components(
            value.0.node.basename,
            value.0.node.namespace,
            Some(value.0.loc),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PathInternal {
    basename: Id,
    namespace: Vec<Id>,
}

impl PathInternal {
    fn iter(&self) -> impl Iterator<Item = &Id> {
        self.namespace.iter().chain(once(&self.basename))
    }

    fn into_iter(self) -> impl Iterator<Item = Id> {
        self.namespace.into_iter().chain(once(self.basename))
    }

    /// Is this referring to a name _in_ the `__cedar` namespace (ex: `__cedar::Bool`)
    fn is_in_cedar(&self) -> bool {
        // `0` is the position of the most significant namespace
        self.namespace
            .first()
            .map(|id| id.as_ref() == CEDAR_NAMESPACE)
            .unwrap_or(false)
    }

    /// Is this name exactly the cedar namespace?
    fn is_cedar(&self) -> bool {
        self.namespace.is_empty() && self.basename.as_ref() == CEDAR_NAMESPACE
    }

    /// Is this referring to a name _in_ the `__cedar` namespace (ex: `__cedar::Bool`) or the unqualified namespace
    fn is_in_unqualified_or_cedar(&self) -> bool {
        self.namespace.is_empty() || self.is_in_cedar()
    }
}

impl std::fmt::Display for PathInternal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.namespace.is_empty() {
            write!(f, "{}", self.basename)
        } else {
            let namespace = self.namespace.iter().map(|id| id.as_ref()).join("::");
            write!(f, "{namespace}::{}", self.basename)
        }
    }
}

/// This struct represents Entity Uids in the Schema Syntax
#[derive(Debug, Clone)]
pub struct QualName {
    pub path: Option<Path>,
    pub eid: SmolStr,
}

impl QualName {
    pub fn unqualified(eid: SmolStr) -> Self {
        Self { path: None, eid }
    }

    pub fn qualified(path: Path, eid: SmolStr) -> Self {
        Self {
            path: Some(path),
            eid,
        }
    }
}

/// A [`Namespace`] has a name and a collection declaration
/// A schema is made up of a series of fragments
/// A fragment is a series of namespaces
#[derive(Debug, Clone)]
pub struct Namespace {
    /// The name of this namespace. If [`None`], then this is the unqualified namespace
    pub name: Option<Node<Path>>,
    /// The [`Declaration`]s contained in this namespace
    pub decls: Vec<Node<Declaration>>,
}

impl Namespace {
    /// Is this [`Namespace`] unqualfiied?
    pub fn is_unqualified(&self) -> bool {
        self.name.is_none()
    }

    /// Get the name of this [`Namespace`] as a fully-qualified [`cedar_policy_core::ast::Name`],
    /// or `None` for the empty namespace
    pub fn name(&self) -> Option<cedar_policy_core::ast::Name> {
        self.name.as_ref().map(|path| {
            // `.qualify_with(None)` is OK because the `path` is already fully-qualified
            crate::RawName::from(path.clone().node).qualify_with(None)
        })
    }
}

pub trait Decl {
    fn names(&self) -> Vec<Node<SmolStr>>;
}

/// Schema Declarations,
/// Defines either entity types, action types, or common types
#[derive(Debug, Clone)]
pub enum Declaration {
    Entity(EntityDecl),
    Action(ActionDecl),
    Type(TypeDecl),
}

#[derive(Debug, Clone)]
pub struct TypeDecl {
    pub name: Node<Id>,
    pub def: Node<Type>,
}

impl Decl for TypeDecl {
    fn names(&self) -> Vec<Node<SmolStr>> {
        vec![self.name.clone().map(|id| id.to_smolstr())]
    }
}

/// Declaration of an entity type
#[derive(Debug, Clone)]
pub struct EntityDecl {
    /// Entity Type Names bound by this declaration.
    /// More than one name can be bound if they have the same definition, for convenience
    pub names: Vec<Node<Id>>,
    /// Entity Types this type is allowed to be related to via the `in` relation
    pub member_of_types: Vec<Path>,
    /// Attributes this entity has
    pub attrs: Vec<Node<AttrDecl>>,
}

/// Type definitions
#[derive(Debug, Clone)]
pub enum Type {
    /// A set of types
    Set(Box<Node<Type>>),
    /// A [`Path`] that could either refer to a Common Type or an Entity Type
    Ident(Path),
    /// A Record
    Record(Vec<Node<AttrDecl>>),
}

/// Primitive Type Definitions
#[derive(Debug, Clone)]
pub enum PrimitiveType {
    /// Cedar Longs
    Long,
    /// Cedar Strings
    String,
    /// Cedar booleans
    Bool,
}

impl<N> From<PrimitiveType> for SchemaTypeVariant<N> {
    fn from(value: PrimitiveType) -> Self {
        match value {
            PrimitiveType::Long => SchemaTypeVariant::Long,
            PrimitiveType::String => SchemaTypeVariant::String,
            PrimitiveType::Bool => SchemaTypeVariant::Boolean,
        }
    }
}

/// Attribute declarations , used in records and entity types
#[derive(Debug, Clone)]
pub struct AttrDecl {
    /// Name of this attribute
    pub name: Node<SmolStr>,
    /// Whether or not it is a required attribute (implicitly `true`)
    pub required: bool,
    /// The type of this attribute
    pub ty: Node<Type>,
}

/// The target of a [`PRAppDecl`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PR {
    /// Applies to the `principal` variable
    Principal,
    /// Applies to the `resource` variable
    Resource,
}

impl std::fmt::Display for PR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PR::Principal => write!(f, "principal"),
            PR::Resource => write!(f, "resource"),
        }
    }
}

/// A declaration that defines what kind of entities this action can be applied against
#[derive(Debug, Clone)]
pub struct PRAppDecl {
    /// Is this constraining the `principal` or the `resource`
    pub kind: Node<PR>,
    /// What entity types are allowed?
    pub entity_tys: NonEmpty<Path>,
}

/// A declaration of constraints on an action type
#[derive(Debug, Clone)]
pub enum AppDecl {
    /// Constraints on the `principal` or `resource`
    PR(PRAppDecl),
    /// Constraints on the `context`
    Context(Either<Path, Vec<Node<AttrDecl>>>),
}

/// An action declaration
#[derive(Debug, Clone)]
pub struct ActionDecl {
    /// The names this declaration is binding.
    /// More than one name can be bound if they have the same definition, for convenience.
    pub names: NonEmpty<Node<SmolStr>>,
    /// The parents of this action
    pub parents: Option<NonEmpty<Node<QualName>>>,
    /// The constraining clauses in this declarations
    pub app_decls: Option<Node<NonEmpty<Node<AppDecl>>>>,
}

impl Decl for ActionDecl {
    fn names(&self) -> Vec<Node<SmolStr>> {
        self.names.iter().cloned().collect()
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;

    fn loc() -> Loc {
        Loc::new((1, 1), Arc::from("foo"))
    }

    #[test]
    fn in_unqual() {
        let p = Path::single("foo".parse().unwrap(), loc());
        assert!(!p.is_cedar());
        assert!(!p.is_in_cedar());
        assert!(p.is_in_unqualified_or_cedar());
    }

    #[test]
    fn qual() {
        let p = Path::new("foo".parse().unwrap(), ["bar".parse().unwrap()], loc());
        assert!(!p.is_cedar());
        assert!(!p.is_in_cedar());
        assert!(!p.is_in_unqualified_or_cedar());
    }

    #[test]
    fn in_cedar() {
        let p = Path::new("foo".parse().unwrap(), ["__cedar".parse().unwrap()], loc());
        assert!(!p.is_cedar());
        assert!(p.is_in_cedar());
        assert!(p.is_in_unqualified_or_cedar());
    }

    #[test]
    fn in_cedar2() {
        let p = Path::new(
            "foo".parse().unwrap(),
            ["__cedar".parse().unwrap(), "bar".parse().unwrap()],
            loc(),
        );
        assert!(!p.is_cedar());
        assert!(p.is_in_cedar());
        assert!(p.is_in_unqualified_or_cedar());
    }

    #[test]
    fn in_cedar3() {
        let p = Path::new(
            "foo".parse().unwrap(),
            ["bar".parse().unwrap(), "__cedar".parse().unwrap()],
            loc(),
        );
        assert!(!p.is_cedar());
        assert!(!p.is_in_cedar());
        assert!(!p.is_in_unqualified_or_cedar());
    }

    #[test]
    fn is_cedar() {
        let p = Path::new("__cedar".parse().unwrap(), [], loc());
        assert!(p.is_cedar());
        assert!(!p.is_in_cedar());
        assert!(p.is_in_unqualified_or_cedar());
    }

    #[test]
    fn is_cedar2() {
        let p = Path::new("__cedar".parse().unwrap(), ["foo".parse().unwrap()], loc());
        assert!(!p.is_cedar());
        assert!(!p.is_in_cedar());
        assert!(!p.is_in_unqualified_or_cedar());
    }

    // Ensure the iterators over [`Path`]s return most significant names first
    #[test]
    fn path_iter() {
        let p = Path::new(
            "baz".parse().unwrap(),
            ["foo".parse().unwrap(), "bar".parse().unwrap()],
            loc(),
        );

        let expected: Vec<Id> = vec![
            "foo".parse().unwrap(),
            "bar".parse().unwrap(),
            "baz".parse().unwrap(),
        ];

        let expected_borrowed = expected.iter().collect::<Vec<_>>();

        let borrowed = p.iter().collect::<Vec<_>>();
        assert_eq!(borrowed, expected_borrowed);
        let moved = p.into_iter().map(|n| n.node).collect::<Vec<_>>();
        assert_eq!(moved, expected);
    }
}
