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
    Type(TypeDecl),
}

#[derive(Debug, Clone)]
pub struct EntityDecl {
    pub names: Vec<Ident>,
    pub member_of_types: Option<Node<Vec<Node<Path>>>>,
}

#[derive(Debug, Clone)]
pub struct ActionDecl {
    pub names: Vec<Name>,
}

#[derive(Debug, Clone)]
pub struct TypeDecl {
    pub name: Vec<Ident>,
}

pub struct AttrDecl {
    pub name: Name,
    pub required: bool,
}
