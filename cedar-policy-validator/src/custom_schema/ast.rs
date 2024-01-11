use cedar_policy_core::{
    ast::{Id, Name as CName},
    parser::{Loc, Node},
};
use itertools::Either;
use miette::SourceSpan;
use nonempty::NonEmpty;
use smol_str::SmolStr;

const IPADDR_EXTENSION: &str = "ipaddr";
const DECIMAL_EXTENSION: &str = "decimal";
pub(super) const CEDAR_NAMESPACE: &str = "__cedar";

pub type Ident = Node<Id>;
pub type Str = Node<SmolStr>;
pub type Name = Either<Ident, Str>;
pub type Schema = Vec<Node<Namespace>>;

#[derive(Debug, Clone)]
pub struct Path {
    pub base: Ident,
    pub prefix: Vec<Ident>,
}

impl From<Ident> for Path {
    fn from(value: Ident) -> Self {
        Path {
            base: value,
            prefix: vec![],
        }
    }
}

impl Path {
    pub fn is_ipaddr_extension(&self) -> bool {
        self.is_cedar_builtin() && self.base.node.clone().to_smolstr() == IPADDR_EXTENSION
    }

    pub fn is_decimal_extension(&self) -> bool {
        self.is_cedar_builtin() && self.base.node.clone().to_smolstr() == DECIMAL_EXTENSION
    }

    pub fn is_builtin_bool(&self) -> bool {
        self.is_cedar_builtin() && self.base.node.clone().to_smolstr() == "Bool"
    }

    pub fn is_builtin_string(&self) -> bool {
        self.is_cedar_builtin() && self.base.node.clone().to_smolstr() == "String"
    }

    pub fn is_builtin_long(&self) -> bool {
        self.is_cedar_builtin() && self.base.node.clone().to_smolstr() == "Long"
    }

    pub fn to_smolstr(self) -> SmolStr {
        <Path as Into<CName>>::into(self).to_string().into()
    }

    pub fn is_unqualified_bool(&self) -> bool {
        self.prefix.is_empty() && self.base.node.clone().to_smolstr() == "Bool"
    }

    pub fn is_unqualified_string(&self) -> bool {
        self.prefix.is_empty() && self.base.node.clone().to_smolstr() == "String"
    }

    pub fn is_unqualified_long(&self) -> bool {
        self.prefix.is_empty() && self.base.node.clone().to_smolstr() == "Long"
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

    pub fn is_unqualified_builtin(&self) -> bool {
        self.is_unqualified_bool()
            || self.is_unqualified_decimal()
            || self.is_unqualified_ipaddr()
            || self.is_unqualified_long()
            || self.is_unqualified_string()
    }

    pub(super) fn get_loc(&self) -> Loc {
        let base_loc = self.base.loc.clone();
        if let Some(head) = self.prefix.first() {
            let start = head.loc.span.offset();
            let length = base_loc.span.offset() + base_loc.span.len() - start;
            Loc::new(SourceSpan::new(start.into(), length.into()), base_loc.src)
        } else {
            base_loc
        }
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
