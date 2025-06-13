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

use std::borrow::Cow;

use cedar_policy_core::ast::{BinaryOp, UnaryOp};
use cedar_policy_core::validator::ValidatorSchema;

pub(crate) use action::*;
pub(crate) use arithmetic::*;
pub(crate) use comparison::*;
pub(crate) use context::*;
pub(crate) use extension::*;
pub(crate) use hierarchy::*;
pub(crate) use logical::*;
pub(crate) use primitive::*;
pub(crate) use principal::*;
pub(crate) use resource::*;

pub(crate) trait ToDocumentationString {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> Cow<'static, str>;
}

#[macro_export]
macro_rules! impl_documentation_from_markdown_file {
    ($i: ident, $f: literal) => {
        pub(crate) struct $i;
        impl crate::documentation::ToDocumentationString for $i {
            fn to_documentation_string(
                &self,
                _schema: Option<&cedar_policy_core::validator::ValidatorSchema>,
            ) -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed(include_str!($f))
            }
        }
    };
}

impl ToDocumentationString for UnaryOp {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> Cow<'static, str> {
        match self {
            Self::Not => NotDocumentation.to_documentation_string(schema),
            Self::Neg => SubtractDocumentation.to_documentation_string(schema),
            Self::IsEmpty => IsEmptyDocumentation.to_documentation_string(schema),
        }
    }
}

impl ToDocumentationString for BinaryOp {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> Cow<'static, str> {
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
            Self::GetTag => GetTagDocumentation.to_documentation_string(schema),
            Self::HasTag => HasTagDocumentation.to_documentation_string(schema),
        }
    }
}

impl_documentation_from_markdown_file!(GetTagDocumentation, "documentation/markdown/get_tag.md");
impl_documentation_from_markdown_file!(HasTagDocumentation, "documentation/markdown/has_tag.md");
