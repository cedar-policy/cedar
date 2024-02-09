use cedar_policy_core::{
    ast::Id,
    parser::{
        cst::{Name, Ref},
        Loc, Node,
    },
};
use itertools::Either;
use itertools::Itertools;
use nonempty::NonEmpty;
use smol_str::SmolStr;

const IPADDR_EXTENSION: &str = "ipaddr";
const DECIMAL_EXTENSION: &str = "decimal";
const EXTENSIONS: [&str; 2] = [IPADDR_EXTENSION, DECIMAL_EXTENSION];
pub(super) const CEDAR_NAMESPACE: &str = "__cedar";

pub type IdentOrString = Either<Node<Id>, Node<SmolStr>>;
pub type Schema = Vec<Node<Namespace>>;

/// A path is a non empty list of identifiers that forms a namespace + type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Path(pub Node<NonEmpty<Id>>);

impl Path {
    /// Create a [`Path`] with a single entry
    pub fn single(node: Id, loc: Loc) -> Self {
        Self(Node::with_source_loc(NonEmpty::new(node), loc))
    }

    /// Create [`Path`] with a head and an iterator
    pub fn new(head: Id, rest: impl IntoIterator<Item = Id>, loc: Loc) -> Self {
        let tail = rest.into_iter().collect();
        Self(Node::with_source_loc(NonEmpty { head, tail }, loc))
    }

    /// Borrowed iteration of the [`Path`]'s elements
    pub fn iter(&self) -> impl Iterator<Item = &Id> {
        self.0.node.iter()
    }

    /// Source [`Loc`] of this [`Path`]
    pub fn loc(&self) -> &Loc {
        &self.0.loc
    }

    /// Consume the [`Path`] and get an owned iterator over the elements
    pub fn into_inner(self) -> impl Iterator<Item = Node<Id>> {
        let loc = self.0.loc;
        self.0
            .node
            .into_iter()
            .map(move |x| Node::with_source_loc(x, loc.clone()))
    }
}

/// Is this string sharing a name with a Cedar extension?
pub fn is_extension_name(s: impl AsRef<str>) -> bool {
    EXTENSIONS.contains(&s.as_ref())
}

/// A [`Namespace`] has a name and a collection declaration
/// A schema is made up of a series of fragments
/// A fragment is a series of namespaces
#[derive(Debug, Clone)]
pub struct Namespace {
    /// The name of this name. If [`None`], then this is the unqualified namespace
    pub name: Option<Path>,
    /// The [`Declaration`]s contained in this namespace
    pub decls: Vec<Node<Declaration>>,
}

impl Namespace {
    /// Is this [`Namespace`] unqualfiied?
    pub fn is_unqualified(&self) -> bool {
        self.name.is_none()
    }

    /// Is this [`Namespace`] the builtin `__cedar` namespace?
    pub fn is_cedar_namespace(&self) -> bool {
        match &self.name {
            Some(path) => path.iter().exactly_one().map(is_cedar).unwrap_or(false),
            None => false,
        }
    }
}

fn is_cedar(id: &Id) -> bool {
    id.as_ref() == CEDAR_NAMESPACE
}

/// Schema Declarations,
/// Defines either entity types, action types, or common types
#[derive(Debug, Clone)]
pub enum Declaration {
    Entity(EntityDecl),
    Action(ActionDecl),
    Type(Node<Id>, Node<Type>),
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
    /// A primitive type
    Prim(PrimitiveType),
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
#[derive(Debug, Clone, PartialEq)]
pub enum PR {
    /// Applies to the `principal` variable
    Principal,
    /// Applies to the `resource` variable
    Resource,
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
    /// Constraints on the `principal`` or `resource``
    PR(PRAppDecl),
    /// Constraints on the `context`
    Context(Vec<Node<AttrDecl>>),
}

/// An action declaration
#[derive(Debug, Clone)]
pub struct ActionDecl {
    /// The names this declaration is bindings
    /// More than one name can be bound if they have the same definition, for convenience
    pub names: Vec<Node<SmolStr>>,
    /// The parents of this action
    pub parents: Option<Vec<Node<SmolStr>>>,
    /// The constraining clauses in this declarations
    pub app_decls: Option<NonEmpty<Node<AppDecl>>>,
}
