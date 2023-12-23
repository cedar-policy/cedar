use cedar_policy_core::{ast::Id, parser::Node};
use itertools::Either;
use smol_str::SmolStr;

pub type Ident = Node<Id>;
pub type Str = Node<SmolStr>;
pub type Name = Either<Ident, Str>;
pub type Schema = Vec<Node<Namespace>>;

#[derive(Debug, Clone)]
pub struct Path {
    pub base: Ident,
    pub prefix: Vec<Ident>,
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
    Ident(Ident),
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
    pub entity_tys: Vec<Node<Path>>,
}

#[derive(Debug, Clone)]
pub enum AppDecl {
    PR(PRAppDecl),
    Context(Vec<Node<AttrDecl>>),
}

#[derive(Debug, Clone)]
pub struct ActionDecl {
    pub names: Vec<Name>,
    pub parents: Option<Vec<Name>>,
    pub app_decls: Vec<Node<AppDecl>>,
    pub attrs: Vec<Node<AttrDecl>>,
}
