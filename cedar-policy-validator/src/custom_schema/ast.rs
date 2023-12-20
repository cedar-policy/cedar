use cedar_policy_core::{ast::Id, parser::Node};
use smol_str::SmolStr;

pub type Ident = Node<Id>;
pub type Str = Node<SmolStr>;
pub type Name = Node<SmolStr>;
pub type Path = Node<cedar_policy_core::ast::Name>;

pub enum Declaration {
    Entity(EntityDecl),
    Action(ActionDecl),
    Type(TypeDecl),
}

pub struct EntityDecl {
    pub names: Vec<Ident>,
    pub member_of_types: Vec<Path>,
}

pub struct ActionDecl {
    pub names: Vec<Name>,
}

pub struct TypeDecl {
    pub name: Vec<Ident>,
}

pub struct AttrDecl {
    pub name: Name,
    pub required: bool,
}
