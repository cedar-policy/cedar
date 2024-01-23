use cedar_policy_core::{
    ast::{Id, Name as CName},
    parser::{Loc, Node},
};
use itertools::Either;
use miette::SourceSpan;
use nonempty::NonEmpty;
use smol_str::SmolStr;

use super::to_json_schema::PrimitiveType;

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
    pub(super) kind: PathKind,
}

#[derive(Debug, Clone)]
pub(super) enum PathKind {
    CedarBuiltin(Option<PrimOrExtension>),
    Unqualified(Option<PrimOrExtension>),
    Other,
}

#[derive(Debug, Clone)]
pub(super) enum PrimOrExtension {
    IpAddr,
    Decimal,
    Prim(PrimitiveType),
}

impl From<Ident> for Path {
    fn from(base: Ident) -> Self {
        let prefix = vec![];
        let kind = Self::path_kind(&prefix, &base);
        Path { base, prefix, kind }
    }
}

impl Path {
    pub fn new(base: Ident, prefix: impl IntoIterator<Item = Node<Id>>) -> Self {
        let prefix = prefix.into_iter().collect::<Vec<_>>();
        let kind = Self::path_kind(&prefix, &base);
        Path { base, prefix, kind }
    }

    fn path_kind(prefix: &[Ident], base: &Ident) -> PathKind {
        if Self::is_builtin(prefix) {
            PathKind::CedarBuiltin(Self::parse_prim_or_ext(base))
        } else if Self::is_unqualified(prefix) {
            PathKind::Unqualified(Self::parse_prim_or_ext(base))
        } else {
            PathKind::Other
        }
    }

    fn parse_prim_or_ext(base: &Ident) -> Option<PrimOrExtension> {
        match base.node.as_ref() {
            IPADDR_EXTENSION => Some(PrimOrExtension::IpAddr),
            DECIMAL_EXTENSION => Some(PrimOrExtension::Decimal),
            _ => Self::parse_prim_type(base).map(PrimOrExtension::Prim),
        }
    }

    fn parse_prim_type(base: &Ident) -> Option<PrimitiveType> {
        match base.node.as_ref() {
            "Bool" => Some(PrimitiveType::Bool),
            "String" => Some(PrimitiveType::String),
            "Long" => Some(PrimitiveType::Long),
            _ => None,
        }
    }

    fn is_builtin(prefix: &[Ident]) -> bool {
        matches!(prefix, [Node { node, loc: _ }] if node.as_ref() == CEDAR_NAMESPACE)
    }

    fn is_unqualified(prefix: &[Ident]) -> bool {
        prefix.is_empty()
    }

    pub fn is_unqualified_builtin(&self) -> bool {
        matches!(self.kind, PathKind::Unqualified(Some(_)))
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

impl From<Path> for SmolStr {
    fn from(p: Path) -> Self {
        <Path as Into<CName>>::into(p).to_string().into()
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

#[derive(Debug, Clone, PartialEq)]
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
