mod action;
mod arithmetic;
mod comparison;
mod context;
mod entity;
mod extension;
mod hierarchy;
mod logical;
mod primitive;
mod principal;
mod resource;

pub(crate) use action::*;
pub(crate) use arithmetic::*;
use cedar_policy_core::ast::{BinaryOp, UnaryOp};
use cedar_policy_core::validator::ValidatorSchema;
pub(crate) use comparison::*;
pub(crate) use context::*;
pub(crate) use extension::*;
pub(crate) use hierarchy::*;
pub(crate) use logical::*;
pub(crate) use primitive::*;
pub(crate) use principal::*;
pub(crate) use resource::*;

use super::ToDocumentationString;

impl ToDocumentationString for UnaryOp {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> String {
        match self {
            Self::Not => NotDocumentation.to_documentation_string(schema),
            Self::Neg => SubtractDocumentation.to_documentation_string(schema),
            Self::IsEmpty => IsEmptyDocumentation.to_documentation_string(schema),
        }
    }
}

impl ToDocumentationString for BinaryOp {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> String {
        match self {
            Self::Eq => EqualsDocumentation.to_documentation_string(schema),
            Self::Less => LessThanDocumentation.to_documentation_string(schema),
            Self::LessEq => LessThanOrEqualsDocumentation.to_documentation_string(schema),
            Self::Add => AddDocumentation.to_documentation_string(schema),
            Self::Sub => SubtractDocumentation.to_documentation_string(schema),
            Self::Mul => MultiplyDocumentation.to_documentation_string(schema),
            Self::In => InDocumentation.to_documentation_string(schema),
            Self::Contains => ContainsDocumentation.to_documentation_string(schema),
            Self::ContainsAll => ContainsAllDocumentation.to_documentation_string(schema),
            Self::ContainsAny => ContainsAnyDocumentation.to_documentation_string(schema),
            Self::GetTag => "GetTag".to_string(),
            Self::HasTag => "HasTag".to_string(),
        }
    }
}
