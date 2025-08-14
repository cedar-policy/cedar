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

use std::sync::Arc;

use cedar_policy_core::ast::{Literal, RepresentableExtensionValue, Value, ValueKind};
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
    #[error("unsupported extension value: {0:?}")]
    UnsupportedExtension(Arc<RepresentableExtensionValue>),
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
            // TODO: Support extension values.
            // This branch would be more complicated than the Lean version,
            // since `Value` in Rust Cedar uses a different representation for
            // extension values than Rust SymCC `Term`.
            (ValueKind::ExtensionValue(ext), _) => {
                Err(SymbolizeError::UnsupportedExtension(ext.clone()))
            }
            _ => Err(SymbolizeError::UnableToSymbolizeValue(v.clone())),
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use cedar_policy_core::ast::{EntityType, EntityUIDEntry, Expr, Request, SlotEnv};
    use cedar_policy_core::entities::Entities;
    use cedar_policy_core::evaluator::Evaluator;
    use cedar_policy_core::extensions::Extensions;
    use cedar_policy_core::validator::ValidatorSchema;

    use super::*;

    fn parse_value(s: &str) -> Value {
        let expr = Expr::from_str(s).unwrap();
        let dummy_request = Request::new_with_unknowns::<ValidatorSchema>(
            EntityUIDEntry::unknown(),
            EntityUIDEntry::unknown(),
            EntityUIDEntry::unknown(),
            None,
            None,
            Extensions::all_available(),
        )
        .unwrap();
        let entities = Entities::new();
        let eval = Evaluator::new(dummy_request, &entities, Extensions::all_available());
        eval.interpret(&expr, &SlotEnv::new()).unwrap()
    }

    fn parse_type(s: &str) -> Type {
        let schema = ValidatorSchema::from_cedarschema_str(
            &format!("entity A; entity _ {{ x: {s} }};"),
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        let ety = schema
            .get_entity_type(&EntityType::from_str("_").unwrap())
            .unwrap();
        ety.attr("x").unwrap().attr_type.clone()
    }

    fn assert_from_value_roundtrip_eq(v: &str, ty: &str) {
        let v = parse_value(v);
        let ty = parse_type(ty);
        assert_eq!(
            Value::try_from(&Term::from_value(&v, &ty).unwrap()).unwrap(),
            v
        );
    }

    /// Symbolizer should be a right-inverse of the concretizer.
    #[test]
    fn test_from_value_roundtrip() {
        assert_from_value_roundtrip_eq("1", "Long");
        assert_from_value_roundtrip_eq("true", "Bool");
        assert_from_value_roundtrip_eq("false", "Bool");
        assert_from_value_roundtrip_eq("\"hello\"", "String");
        assert_from_value_roundtrip_eq("{ a: 10 }", "{ a: Long }");
        assert_from_value_roundtrip_eq("{ a: 10 }", "{ a?: Long }");
        assert_from_value_roundtrip_eq("{ a: 10, b: \"hello\" }", "{ a?: Long, b: String }");
        assert_from_value_roundtrip_eq("{ a: 10, b: \"hello\" }", "{ b?: String, a?: Long }");
        assert_from_value_roundtrip_eq("[ \"a\", \"b\", \"a\" ]", "Set<String>");
        assert_from_value_roundtrip_eq("[ true, false, true, false, false ]", "Set<Bool>");
        assert_from_value_roundtrip_eq("[ A::\"alice\", A::\"bob\" ]", "Set<A>");
    }
}
