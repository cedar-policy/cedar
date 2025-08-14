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

//! This module includes functions to convert
//! concrete Cedar values, requests, and entities to
//! (literal) symbolic terms or environments.

use cedar_policy_core::ast::{Literal, Value, ValueKind};
use cedar_policy_core::validator::types::{EntityRecordKind, OpenTag, Type};
use miette::Diagnostic;
use thiserror::Error;

use super::factory;
use super::term::Term;
use super::term_type::TermType;
use super::type_abbrevs::EntityUID;
use super::CompileError;

/// Errors that happen when converting concrete
/// values to symbolic terms
#[derive(Debug, Diagnostic, Error)]
pub enum SymbolizeError {
    #[error("unable to symbolize value {0}")]
    UnableToSymbolizeValue(Value),
    #[error("compile error")]
    CompileError(#[from] CompileError),
}

impl Term {
    /// Corresponds to `Prim.symbolize`
    pub fn from_literal(l: &Literal) -> Self {
        match l {
            Literal::Bool(b) => (*b).into(),
            Literal::Long(i) => (*i).into(),
            Literal::String(s) => s.clone().into(),
            Literal::EntityUID(euid) => EntityUID::from(euid.as_ref().clone()).into(),
        }
    }

    /// Corresponds to `Value.symbolize?` in Lean.
    pub fn from_value(v: &Value, ty: &Type) -> Result<Self, SymbolizeError> {
        match (v.value_kind(), ty) {
            (ValueKind::Lit(l), _) => Ok(Term::from_literal(l)),
            (
                ValueKind::Set(s),
                Type::Set {
                    element_type: Some(elem_ty),
                },
            ) => {
                let elems = s
                    .iter()
                    .map(|elem| Term::from_value(elem, elem_ty))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(factory::set_of(elems, TermType::of_type(elem_ty.as_ref())?))
            }
            (
                ValueKind::Record(rec),
                Type::EntityOrRecord(EntityRecordKind::Record {
                    attrs,
                    open_attributes: OpenTag::ClosedAttributes,
                }),
            ) => {
                let attrs = attrs
                    .iter()
                    .map(|(attr, attr_ty)| {
                        Ok::<_, SymbolizeError>(if let Some(attr_val) = rec.get(attr) {
                            if attr_ty.is_required() {
                                (
                                    attr.clone(),
                                    Term::from_value(attr_val, &attr_ty.attr_type)?,
                                )
                            } else {
                                (
                                    attr.clone(),
                                    factory::some_of(Term::from_value(
                                        attr_val,
                                        &attr_ty.attr_type,
                                    )?),
                                )
                            }
                        } else {
                            (
                                attr.clone(),
                                factory::none_of(TermType::of_type(&attr_ty.attr_type)?),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(factory::record_of(attrs))
            }
            (ValueKind::ExtensionValue(_), _) => todo!("symbolizing extension values"),
            _ => Err(SymbolizeError::UnableToSymbolizeValue(v.clone())),
        }
    }
}
