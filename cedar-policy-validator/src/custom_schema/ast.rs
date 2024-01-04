use cedar_policy_core::{
    ast::{Id, Name as CName},
    parser::Node,
};
use itertools::Either;
use nonempty::NonEmpty;
use smol_str::SmolStr;

const IPADDR_EXTENSION: &str = "ipaddr";
const DECIMAL_EXTENSION: &str = "decimal";
const CEDAR_NAMESPACE: &str = "__cedar";

pub type Ident = Node<Id>;
pub type Str = Node<SmolStr>;
pub type Name = Either<Ident, Str>;
pub type Schema = Vec<Node<Namespace>>;

#[derive(Debug, Clone)]
pub struct Path {
    pub base: Ident,
    pub prefix: Vec<Ident>,
}

impl Path {
    pub fn is_ipaddr_extension(&self) -> bool {
        self.is_cedar_builtin() && self.base.node.clone().to_smolstr() == IPADDR_EXTENSION
    }

    pub fn is_decimal_extension(&self) -> bool {
        self.is_cedar_builtin() && self.base.node.clone().to_smolstr() == DECIMAL_EXTENSION
    }

    pub fn to_smolstr(self) -> SmolStr {
        <Path as Into<CName>>::into(self).to_string().into()
    }

    pub fn is_unqualified_ipaddr(&self) -> bool {
        self.prefix.is_empty() && self.base.node.clone().to_smolstr() == IPADDR_EXTENSION
    }

    pub fn is_unqualified_decimal(&self) -> bool {
        self.prefix.is_empty() && self.base.node.clone().to_smolstr() == DECIMAL_EXTENSION
    }

    fn is_cedar_builtin(&self) -> bool {
        matches!(self.prefix.as_slice(), [Node { node, loc: _ }] if node.as_ref() == CEDAR_NAMESPACE)
    }
}

// Convert `Path` to `cedar_policy_core::ast::Name` and drop all its source locations
impl From<Path> for CName {
    fn from(value: Path) -> Self {
        CName::new(
            value.base.node,
            value.prefix.iter().map(|id| id.node.clone()),
        )
    }
}

#[derive(Debug, Clone)]
pub struct Namespace {
    pub name: Option<Node<Path>>,
    pub decls: Vec<Node<Declaration>>,
}

#[derive(Debug, Clone)]
pub enum Declaration {
    Entity(EntityDecl),
    Action(ActionDecl),
    Type(Ident, Node<Type>),
}

#[derive(Debug, Clone)]
pub struct EntityDecl {
    pub names: Vec<Ident>,
    pub member_of_types: Option<Vec<Node<Path>>>,
    pub attrs: Vec<Node<AttrDecl>>,
}

#[derive(Debug, Clone)]
pub enum Type {
    Long,
    Bool,
    String,
    Set(Box<Node<Type>>),
    Ident(Path),
    Record(Vec<Node<AttrDecl>>),
}

#[derive(Debug, Clone)]
pub struct AttrDecl {
    pub name: Name,
    pub required: Option<()>,
    pub ty: Node<Type>,
}

#[derive(Debug, Clone)]
pub enum PR {
    Principal,
    Resource,
}

#[derive(Debug, Clone)]
pub struct PRAppDecl {
    pub ty: Node<PR>,
    pub entity_tys: NonEmpty<Node<Path>>,
}

#[derive(Debug, Clone)]
pub enum AppDecl {
    PR(PRAppDecl),
    Context(Vec<Node<AttrDecl>>),
}

#[derive(Debug, Clone)]
pub struct Ref {
    pub ty: Option<Path>,
    pub id: Name,
}

#[derive(Debug, Clone)]
pub struct ActionDecl {
    pub names: Vec<Name>,
    pub parents: Option<Vec<Ref>>,
    pub app_decls: Option<NonEmpty<Node<AppDecl>>>,
}
