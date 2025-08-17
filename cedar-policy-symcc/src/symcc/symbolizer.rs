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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use cedar_policy::entities_errors::EntitiesError;
use cedar_policy::{Entities, Request, RequestEnv, Schema};
use cedar_policy_core::ast::{
    Context, Literal, PartialValue, RepresentableExtensionValue, RestrictedExpr, Value, ValueKind,
};
use cedar_policy_core::validator::types::{EntityRecordKind, OpenTag, Type};
use miette::Diagnostic;
use thiserror::Error;

use crate::extension_types::decimal;
use crate::symcc::env::{EntitySchemaEntry, SymEntityData};
use crate::symcc::function::{self, UnaryFunction};
use crate::type_abbrevs::core_entity_type_into_entity_type;

use super::env::{StandardEntitySchemaEntry, SymEntities, SymRequest};
use super::ext::Ext;
use super::extension_types::{datetime, ipaddr};
use super::tags::SymTags;
use super::term::Term;
use super::term_type::TermType;
use super::type_abbrevs::{core_uid_into_uid, EntityType, EntityUID};
use super::{factory, Env, Environment};
use super::{CompileError, SymEnv};

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
    #[error("partial request not supported")]
    PartialRequest,
    #[error("entities error")]
    EntitiesError(#[from] EntitiesError),
    #[error("partial value not supported")]
    PartialValue,
    #[error("ill-formed type environment")]
    IllFormedTypeEnv,
}

impl Term {
    /// Converts a concrete [`Literal`] to a symbolic [`Term`].
    /// Corresponds to `Prim.symbolize` in Lean.
    pub fn from_literal(l: &Literal) -> Self {
        match l {
            Literal::Bool(b) => (*b).into(),
            Literal::Long(i) => (*i).into(),
            Literal::String(s) => s.clone().into(),
            Literal::EntityUID(euid) => EntityUID::from(euid.as_ref().clone()).into(),
        }
    }

    /// Helper function for [`Term::from_value`].
    fn from_ext_value(rexp: &RestrictedExpr) -> Option<Self> {
        let (name, args) = rexp.as_extn_fn_call()?;
        let args = args.collect::<Vec<_>>();

        // Recover the string representation of supported extension values
        // and then convert them to corresponding `Term`s.
        match (name.as_ref().to_string().as_str(), args.as_slice()) {
            ("decimal", &[arg]) => Some(
                Ext::Decimal {
                    d: decimal::parse(arg.as_string()?.as_str())?,
                }
                .into(),
            ),
            ("duration", &[arg]) => Some(
                Ext::Duration {
                    d: datetime::Duration::parse(arg.as_string()?.as_str())?,
                }
                .into(),
            ),
            ("datetime", &[arg]) => Some(
                Ext::Datetime {
                    dt: datetime::Datetime::parse(arg.as_string()?.as_str())?,
                }
                .into(),
            ),
            // Datetime is sometimes represented as `datetime(<epoch>).offset(<...>)`
            ("offset", &[arg1, arg2]) => {
                let (arg1_name, arg1_args) = arg1.as_extn_fn_call()?;
                let (arg2_name, arg2_args) = arg2.as_extn_fn_call()?;
                let arg1_args = arg1_args.collect::<Vec<_>>();
                let arg2_args = arg2_args.collect::<Vec<_>>();
                if arg1_name.as_ref().to_string() != "datetime"
                    || arg1_args.len() != 1
                    || arg2_name.as_ref().to_string() != "duration"
                    || arg2_args.len() != 1
                {
                    return None;
                }

                #[allow(
                    clippy::indexing_slicing,
                    reason = "arg1_args.len() == 1 thus indexing by 0 should not panic"
                )]
                let dt = datetime::Datetime::parse(arg1_args[0].as_string()?.as_str())?;
                #[allow(
                    clippy::indexing_slicing,
                    reason = "arg2_args.len() == 1 thus indexing by 0 should not panic"
                )]
                let d = datetime::Duration::parse(arg2_args[0].as_string()?.as_str())?;
                Some(Ext::Datetime { dt: dt.offset(&d)? }.into())
            }
            ("ip", &[arg]) => Some(
                Ext::Ipaddr {
                    ip: ipaddr::parse(arg.as_string()?.as_str())?,
                }
                .into(),
            ),
            _ => None,
        }
    }

    /// Converts a concrete [`Value`] to a symbolic [`Term`].
    /// The type of the value must be specified, in order to
    /// correctly encode records.
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
                let rexp: RestrictedExpr = ext.as_ref().clone().into();
                Self::from_ext_value(&rexp).ok_or(SymbolizeError::UnsupportedExtension(ext.clone()))
            }
            _ => Err(SymbolizeError::UnableToSymbolizeValue(v.clone())),
        }
    }
}

impl SymRequest {
    /// Converts a concrete [`Request`] to [`SymRequest`].
    ///
    /// Corresponds to `Request.symbolize?` in Lean, although
    /// directly returning a `SymRequest` instead of a variable
    /// interpretation.
    fn from_request(env: &Environment<'_>, req: &Request) -> Result<Self, SymbolizeError> {
        let context = match req
            .context()
            .ok_or(SymbolizeError::PartialRequest)?
            .as_ref()
        {
            Context::Value(attrs) => Value::record_arc(attrs.clone(), None),
            _ => return Err(SymbolizeError::PartialRequest),
        };

        Ok(SymRequest {
            principal: Term::from_literal(
                &req.principal()
                    .ok_or(SymbolizeError::PartialRequest)?
                    .as_ref()
                    .clone()
                    .into(),
            ),
            action: Term::from_literal(
                &req.action()
                    .ok_or(SymbolizeError::PartialRequest)?
                    .as_ref()
                    .clone()
                    .into(),
            ),
            resource: Term::from_literal(
                &req.resource()
                    .ok_or(SymbolizeError::PartialRequest)?
                    .as_ref()
                    .clone()
                    .into(),
            ),
            context: Term::from_value(&context, &env.context_type())?,
        })
    }
}

impl SymEntityData {
    /// Implements `Entities.symbolizeAttrs?` in Lean
    fn symbolize_attrs(
        sym_env: &SymEnv,
        ety: &EntityType,
        sch: &StandardEntitySchemaEntry,
        entities: &Entities,
    ) -> Result<UnaryFunction, SymbolizeError> {
        let attr_udf_out_ty = Type::EntityOrRecord(EntityRecordKind::Record {
            attrs: sch.attrs.clone(),
            open_attributes: OpenTag::ClosedAttributes,
        });
        let attrs_udf_out = TermType::of_type(&attr_udf_out_ty)?;
        let attrs_udf_default = attrs_udf_out.default_literal(sym_env);

        let mut attrs_udf_table = BTreeMap::new();
        for ent in entities.iter() {
            if ent.uid().type_name() == ety {
                // Check if there's any partial attributes
                let attrs = ent
                    .as_ref()
                    .attrs()
                    .map(|(attr, attr_val)| match attr_val {
                        PartialValue::Value(v) => Ok((attr.clone(), v.clone())),
                        PartialValue::Residual(..) => Err(SymbolizeError::PartialValue),
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()?;
                attrs_udf_table.insert(
                    ent.uid().clone().into(),
                    Term::from_value(&Value::record_arc(Arc::new(attrs), None), &attr_udf_out_ty)?,
                );
            }
        }

        Ok(UnaryFunction::Udf(function::Udf {
            arg: TermType::Entity { ety: ety.clone() },
            out: attrs_udf_out,
            table: attrs_udf_table,
            default: attrs_udf_default,
        }))
    }

    /// Implements `Entities.symbolizeAncs?` in Lean
    fn symbolize_ancs(
        sym_env: &SymEnv,
        ety: &EntityType,
        anc_ty: &EntityType,
        entities: &Entities,
    ) -> Result<UnaryFunction, SymbolizeError> {
        let anc_term_ty = TermType::Entity {
            ety: anc_ty.clone(),
        };
        let mut ancs_udf_table = BTreeMap::new();

        for ent in entities.iter() {
            if ent.uid().type_name() == ety {
                let anc_terms = ent.as_ref().ancestors().filter_map(|anc| {
                    if anc.entity_type() == anc_ty.as_ref() {
                        Some(core_uid_into_uid(anc).clone().into())
                    } else {
                        None
                    }
                });

                ancs_udf_table.insert(
                    ent.uid().clone().into(),
                    factory::set_of(anc_terms, anc_term_ty.clone()),
                );
            }
        }

        let ancs_udf_out = TermType::set_of(anc_term_ty);
        let ancs_udf_default = ancs_udf_out.default_literal(sym_env);

        Ok(UnaryFunction::Udf(function::Udf {
            arg: TermType::Entity { ety: ety.clone() },
            out: ancs_udf_out,
            table: ancs_udf_table,
            default: ancs_udf_default,
        }))
    }

    /// Implements `Entities.symbolizeTags?` in Lean
    fn symbolize_tags(
        sym_env: &SymEnv,
        ety: &EntityType,
        tag_ty: &Type,
        entities: &Entities,
    ) -> Result<SymTags, SymbolizeError> {
        let keys_udf_out = TermType::set_of(TermType::String);
        let vals_udf_out = TermType::of_type(tag_ty)?;

        let keys_udf_default = keys_udf_out.default_literal(sym_env);
        let vals_udf_default = vals_udf_out.default_literal(sym_env);

        let mut keys_udf_table = BTreeMap::new();
        let mut vals_udf_table = BTreeMap::new();

        // `Entities.symbolizeTags?.keysUDF`
        for ent in entities.iter() {
            if ent.uid().type_name() == ety {
                keys_udf_table.insert(
                    ent.uid().clone().into(),
                    factory::set_of(
                        ent.as_ref().tag_keys().map(|s| s.clone().into()),
                        TermType::String,
                    ),
                );
            }
        }

        // `Entities.symbolizeTags?.valsUDF`
        for ent in entities.iter() {
            if ent.uid().type_name() == ety {
                for (key, val) in ent.as_ref().tags() {
                    let PartialValue::Value(val) = val else {
                        return Err(SymbolizeError::PartialValue);
                    };
                    vals_udf_table.insert(
                        factory::tag_of(ent.uid().clone().into(), key.clone().into()),
                        Term::from_value(val, tag_ty)?,
                    );
                }
            }
        }

        Ok(SymTags {
            keys: UnaryFunction::Udf(function::Udf {
                arg: TermType::Entity { ety: ety.clone() }, // more efficient than the Lean: avoids `TermType::of_type()` and constructs the `TermType` directly
                out: TermType::set_of(TermType::String),
                table: keys_udf_table,
                default: keys_udf_default,
            }),
            vals: UnaryFunction::Udf(function::Udf {
                arg: TermType::tag_for(ety.clone()), // record representing the pair type (ety, .string)
                out: TermType::of_type(tag_ty)?,
                table: vals_udf_table,
                default: vals_udf_default,
            }),
        })
    }

    /// Encodes a literal [`SymEntityData`] from the given entities.
    ///
    /// Corresponds to a combination of these Lean functions:
    /// - `Entities.symbolizeAttrs?`
    /// - `Entities.symbolizeAncs?`
    /// - `Entities.symbolizeTags?`
    fn from_entities(
        sym_env: &SymEnv,
        ety: &EntityType,
        entry: &EntitySchemaEntry,
        entities: &Entities,
    ) -> Result<Self, SymbolizeError> {
        match entry {
            EntitySchemaEntry::Standard(sch) => Ok(SymEntityData {
                attrs: Self::symbolize_attrs(sym_env, ety, sch, entities)?,
                ancestors: sch
                    .ancestors
                    .iter()
                    .map(|anc_ty| {
                        Ok::<_, SymbolizeError>((
                            anc_ty.clone(),
                            Self::symbolize_ancs(sym_env, ety, anc_ty, entities)?,
                        ))
                    })
                    .collect::<Result<_, _>>()?,
                members: None,
                tags: if let Some(tag_ty) = &sch.tags {
                    Some(Self::symbolize_tags(sym_env, ety, tag_ty, entities)?)
                } else {
                    None
                },
            }),

            EntitySchemaEntry::Enum(eids) => {
                // Same as `SymEntityData::of_entity_type` since it does not
                // contain `UUF`s or variables.
                let attrs_udf = UnaryFunction::Udf(function::Udf {
                    arg: TermType::Entity { ety: ety.clone() },
                    out: TermType::Record {
                        rty: Arc::new(BTreeMap::new()),
                    },
                    table: BTreeMap::new(),
                    default: Term::Record(Arc::new(BTreeMap::new())),
                });
                Ok(SymEntityData {
                    attrs: attrs_udf,
                    ancestors: BTreeMap::new(),
                    members: Some(eids.iter().map(|s| s.to_string()).collect()),
                    tags: None,
                })
            }
        }
    }
}

impl SymEntities {
    /// Converts a concrete [`Entities`] to [`SymEntities`].
    ///
    /// Corresponds to `Entities.symbolize?` in Lean, but directly
    /// returning a `SymEntities` instead of an [`UUF`] interpretation.
    fn from_entities(env: &Environment<'_>, entities: &Entities) -> Result<Self, SymbolizeError> {
        let schema = env.schema();

        // Create a symbolic environment so that we can compute the default literals.
        let sym_env = SymEnv::of_env(env)?;

        let entities = schema.entity_types().map(|ent| {
            let ety = core_entity_type_into_entity_type(ent.name());
            let entry = EntitySchemaEntry::of_schema(ety, ent, schema);
            SymEntityData::from_entities(&sym_env, ety, &entry, entities)
                .map(|sym_edata| (ety.clone(), sym_edata))
        });

        // Action entities are compiled the same way as `SymEntities::of_schema`,
        // since they do not contain `UUF`s or variables.
        let acts = schema.action_entities()?;
        let act_tys = acts
            .iter()
            .map(|act| core_entity_type_into_entity_type(act.uid().entity_type()))
            .collect::<BTreeSet<_>>();
        let actions = act_tys.iter().map(|&act_ty| {
            Ok((
                act_ty.clone(),
                SymEntityData::of_action_type(act_ty, act_tys.clone(), schema),
            ))
        });

        Ok(SymEntities(
            entities
                .into_iter()
                .chain(actions)
                .collect::<Result<_, _>>()?,
        ))
    }
}

impl SymEnv {
    /// Converts a concrete [`Env`] to [`SymEnv`].
    ///
    /// Corresponds to `Env.symbolize?` in Lean, but directly
    /// returning a [`SymEnv`] instead of an [`super::Interpretation`].
    pub fn from_concrete_env(
        req_env: &RequestEnv,
        schema: &Schema,
        env: &Env,
    ) -> Result<Self, SymbolizeError> {
        let type_env = Environment::from_request_env(req_env, schema.as_ref())
            .ok_or(SymbolizeError::IllFormedTypeEnv)?;
        Ok(SymEnv {
            request: SymRequest::from_request(&type_env, &env.request)?,
            entities: SymEntities::from_entities(&type_env, &env.entities)?,
        })
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
        assert_from_value_roundtrip_eq("decimal(\"123.32\")", "decimal");
        assert_from_value_roundtrip_eq("duration(\"1212312324ms\")", "duration");
        assert_from_value_roundtrip_eq("datetime(\"2025-08-14\")", "datetime");
        assert_from_value_roundtrip_eq("ip(\"192.6.6.6/12\")", "ipaddr");
        assert_from_value_roundtrip_eq("ip(\"::1/12\")", "ipaddr");
    }
}
