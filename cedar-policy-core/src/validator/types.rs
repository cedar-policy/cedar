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

//! Defines the type structure for typechecking and various utilities for
//! constructing and manipulating types.

mod capability;
pub use capability::*;
mod request_env;
use educe::Educe;
pub use request_env::*;

use itertools::Itertools;
use serde::Serialize;
use smol_str::SmolStr;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Display,
};

use crate::{
    ast::{
        BorrowedRestrictedExpr, EntityType, EntityUID, Name, PartialValue, RestrictedExpr, Value,
    },
    entities::{
        conformance::typecheck_restricted_expr_against_schematype,
        AttributeType as CoreAttributeType, SchemaType as CoreSchemaType,
    },
    extensions::{ExtensionFunctionLookupError, Extensions},
};

#[cfg(feature = "extended-schema")]
use crate::parser::Loc;

use crate::validator::{validation_errors::LubHelp, ValidationMode};

use super::schema::{ValidatorActionId, ValidatorEntityType, ValidatorSchema};

/// The main type structure.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Serialize)]
pub enum Type {
    /// Bottom type. Sub-type of all types.
    Never,

    /// Singleton boolean type true
    True,
    /// Singleton boolean type false
    False,

    /// Primitive types: bool, long, and string.
    Primitive {
        /// Which primitive type: bool, long, or string
        #[serde(rename = "primitiveType")]
        primitive_type: Primitive,
    },

    /// The type of sets containing some type.
    Set {
        /// The type of the elements in the set, or None if it represents an
        /// arbitrary set type. This should only be None when the type is being
        /// used in a subtype comparison (commonly done through `expect_type` in
        /// `typecheck.rs`) or for error reporting through the `TypeError`
        /// structure.
        #[serde(rename = "elementType")]
        element_type: Option<Box<Type>>,
    },

    /// Record and entity types
    EntityOrRecord(EntityRecordKind),

    /// Extension types
    ExtensionType {
        /// Name of the extension type
        name: Name,
    },
}

impl Type {
    /// Construct a singleton type, either `True` or `False` depending on `val`
    pub fn singleton_boolean(val: bool) -> Type {
        if val {
            Type::True
        } else {
            Type::False
        }
    }

    /// The Boolean type
    pub fn primitive_boolean() -> Type {
        Type::Primitive {
            primitive_type: Primitive::Bool,
        }
    }

    /// The Long (integer) type
    pub fn primitive_long() -> Type {
        Type::Primitive {
            primitive_type: Primitive::Long,
        }
    }

    /// The String type
    pub fn primitive_string() -> Type {
        Type::Primitive {
            primitive_type: Primitive::String,
        }
    }

    /// Construct a type for a literal EUID. This type will be a named entity
    /// type for the type of the [`EntityUID`].
    pub(crate) fn euid_literal(entity: &EntityUID, schema: &ValidatorSchema) -> Option<Type> {
        if entity.entity_type().is_action() {
            schema
                .get_action_id(entity)
                .map(Type::entity_reference_from_action_id)
        } else {
            schema
                .get_entity_type(entity.entity_type())
                .map(Type::entity_reference_from_entity_type)
        }
    }

    pub(crate) fn any_set() -> Type {
        Type::Set { element_type: None }
    }

    /// The Set type, with the element type `ety`
    pub fn set(ety: Type) -> Type {
        Type::Set {
            element_type: Some(Box::new(ety)),
        }
    }

    pub(crate) fn any_record() -> Type {
        // OpenAttributes <: ClosedAttributes, so this makes `any_record` a
        // super type of all records.
        Type::record_with_attributes(None, OpenTag::OpenAttributes)
    }

    /// Record type with given attribute types, all required
    pub fn record_with_required_attributes(
        required_attrs: impl IntoIterator<Item = (SmolStr, Type)>,
        open_attributes: OpenTag,
    ) -> Type {
        Type::EntityOrRecord(EntityRecordKind::Record {
            attrs: Attributes::with_required_attributes(required_attrs),
            open_attributes,
        })
    }

    /// Record type with given attribute types
    pub fn record_with_attributes(
        attrs: impl IntoIterator<Item = (SmolStr, AttributeType)>,
        open_attributes: OpenTag,
    ) -> Type {
        Type::EntityOrRecord(EntityRecordKind::Record {
            attrs: Attributes::with_attributes(attrs),
            open_attributes,
        })
    }

    pub(crate) fn entity_reference_from_entity_type(
        validator_entity_type: &ValidatorEntityType,
    ) -> Type {
        Type::named_entity_reference(validator_entity_type.name.clone())
    }

    pub(crate) fn entity_reference_from_action_id(validator_action_id: &ValidatorActionId) -> Type {
        Type::EntityOrRecord(EntityRecordKind::ActionEntity {
            name: validator_action_id.name.entity_type().clone(),
            attrs: Attributes::with_attributes(validator_action_id.attribute_types.clone()),
        })
    }

    pub(crate) fn named_entity_reference(name: EntityType) -> Type {
        Type::EntityOrRecord(EntityRecordKind::Entity(EntityLUB::single_entity(name)))
    }

    pub(crate) fn any_entity_reference() -> Type {
        Type::EntityOrRecord(EntityRecordKind::AnyEntity)
    }

    pub(crate) fn extension(name: Name) -> Type {
        Type::ExtensionType { name }
    }

    /// Implements a subtype relation for the type structure. This requires a
    /// `schema` so that the declared attributes for named entity types can be
    /// retrieved. This is used to determine subtyping between a named entity
    /// type and a record type.
    pub(crate) fn is_subtype(
        schema: &ValidatorSchema,
        ty0: &Type,
        ty1: &Type,
        mode: ValidationMode,
    ) -> bool {
        match (ty0, ty1) {
            // Never is a subtype of every type.
            (Type::Never, _) => true,

            (
                Type::True | Type::False,
                Type::Primitive {
                    primitive_type: Primitive::Bool,
                },
            ) => true,
            (Type::True, Type::True) => true,
            (Type::False, Type::False) => true,

            // Subtypes between two primitives only occurs when the primitive
            // types are the same.
            (Type::Primitive { primitive_type: _ }, Type::Primitive { primitive_type: _ }) => {
                ty0 == ty1
            }

            // A set type is a subtype other set type when its element type is a subtype.
            (
                Type::Set {
                    element_type: e_ty0,
                },
                Type::Set {
                    element_type: e_ty1,
                },
            ) => match (e_ty0, e_ty1) {
                (Some(e_ty0), Some(e_ty1)) => Type::is_subtype(schema, e_ty0, e_ty1, mode),
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => true,
            },

            (Type::EntityOrRecord(rk0), Type::EntityOrRecord(rk1)) => {
                EntityRecordKind::is_subtype(schema, rk0, rk1, mode)
            }

            // Subtypes between extension types only occurs when the extension
            // types are the same.
            (Type::ExtensionType { .. }, Type::ExtensionType { .. }) => ty0 == ty1,

            // If none of the above apply, then ty0 is not a subtype of ty1.
            _ => false,
        }
    }

    /// Compute the least upper bound of two types. This is a type such that each
    /// type is a subtype of the least upper bound.
    pub(crate) fn least_upper_bound(
        schema: &ValidatorSchema,
        ty0: &Type,
        ty1: &Type,
        mode: ValidationMode,
    ) -> Result<Type, LubHelp> {
        match (ty0, ty1) {
            _ if Type::is_subtype(schema, ty0, ty1, mode) => Ok(ty1.clone()),
            _ if Type::is_subtype(schema, ty1, ty0, mode) => Ok(ty0.clone()),

            (Type::True | Type::False, Type::True | Type::False) => Ok(Type::primitive_boolean()),

            // `None` as an element type represents the top type for the set
            // element, so every other set is a subtype of set<None>, making a
            // least upper bound containing set<None> and another set type
            // equal to set<None>. This case should be impossible due to the
            // subtype checks in the first two match cases, but we handle it
            // explicitly as an alternative to panicking if it occurs.
            (Type::Set { element_type: None }, Type::Set { .. })
            | (Type::Set { .. }, Type::Set { element_type: None }) => {
                Ok(Type::Set { element_type: None })
            }

            // The least upper bound of two set types is a set with
            // an element type that is the element type least upper bound.
            (
                Type::Set {
                    element_type: Some(te0),
                },
                Type::Set {
                    element_type: Some(te1),
                },
            ) => Ok(Type::set(Type::least_upper_bound(schema, te0, te1, mode)?)),

            (Type::EntityOrRecord(rk0), Type::EntityOrRecord(rk1)) => Ok(Type::EntityOrRecord(
                EntityRecordKind::least_upper_bound(schema, rk0, rk1, mode)?,
            )),

            _ => Err(LubHelp::None),
        }
    }

    // Return `true` if the parameter types are definitely disjoint, i.e., there
    // are no values which inhabit both types. It is tempting to say that types
    // are disjoint if neither is a subtype of the other, but this would be
    // incorrect for set types where the set can be empty.  set<int> and
    // set<bool> would then be considered disjoint, but both are inhabited by
    // the empty set. This function could safely decide that more types are
    // disjoint than it currently does, e.g., it is correct to say `long` and
    // `bool` are disjoint, but it is also safe to conservatively approximate
    // this function by deciding that fewer types are disjoint than are in
    // reality. Declaring types disjoint when they are not disjoint would, on
    // the other hand, cause soundness errors in the typechecker.
    pub(crate) fn are_types_disjoint(ty1: &Type, ty2: &Type) -> bool {
        match (ty1, ty2) {
            (Type::EntityOrRecord(k1), Type::EntityOrRecord(k2)) => {
                if let (Some(lub1), Some(lub2)) = (k1.as_entity_lub(), k2.as_entity_lub()) {
                    // Entity types least-upper-bounds that have no entity types in
                    // common, are disjoint types.
                    // Entity types least-upper-bounds that have entity types in
                    // common, are not disjoint types.
                    lub1.is_disjoint(&lub2)
                } else {
                    false // conservatively false, not promising disjointness; see notes on this function
                }
            }
            _ => false, // conservatively false, not promising disjointness; see notes on this function
        }
    }

    /// Given a list of types, compute the least upper bound of all types in the
    /// list. The least upper bound of an empty list is Never.
    pub(crate) fn reduce_to_least_upper_bound<'a>(
        schema: &ValidatorSchema,
        tys: impl IntoIterator<Item = &'a Type>,
        mode: ValidationMode,
    ) -> Result<Type, LubHelp> {
        tys.into_iter().try_fold(Type::Never, |lub, next| {
            Type::least_upper_bound(schema, &lub, next, mode)
        })
    }

    /// Get the type of the specified attribute of an entity or record type,
    /// if it is known.
    ///
    /// - If `ty` is not an entity or record type, returns `None`.
    /// - If the attribute is known to not exist on `ty`, returns `None`.
    /// - If the attribute is known to be optional on `ty`, returns `Some` with
    ///   the type.
    ///   (Note that [`AttributeType`] contains an `is_required` flag, so you can
    ///   distinguish this case.)
    /// - If the attribute may exist, but multiple types are possible for the
    ///   attribute (e.g., `AnyEntity`), returns `None`.
    pub(crate) fn lookup_attribute_type(
        schema: &ValidatorSchema,
        ty: &Type,
        attr: &str,
    ) -> Option<AttributeType> {
        match ty {
            Type::EntityOrRecord(rk) => rk.get_attr(schema, attr),
            _ => None,
        }
    }

    /// Get all statically known attributes of an entity or record type.
    /// Returns an empty vector if no attributes or type is not an entity or record type.
    pub fn all_attributes(&self, schema: &ValidatorSchema) -> Vec<SmolStr> {
        match self {
            Type::EntityOrRecord(e) => e.all_known_attrs(schema),
            _ => vec![],
        }
    }

    /// Return true if the Type `ty` could possibly contain the attribute
    /// `attr`. Record and entity types can contain attributes, so we check if
    /// the type can contain the specific attribute. Other types cannot have
    /// attributes, so we return false.
    pub(crate) fn may_have_attr(schema: &ValidatorSchema, ty: &Type, attr: &str) -> bool {
        match ty {
            // Never, being the bottom type, is a subtype of EntityOrRecord, so
            // it could have any attributes.
            Type::Never => true,
            // An EntityOrRecord might have an open attributes record, in which
            // case it could have any attribute.
            Type::EntityOrRecord(k) if k.has_open_attributes_record(schema) => true,
            // In this case and all following `EntityOrRecord` cases, we know it
            // does not have an open attributes record, so we know that an
            // attribute may not exist if it is not explicitly listed in the
            // type. For an entity, we look this up in the schema.  For an
            // entity least upper bound resulting from multiple entity
            // types, the type might have the attribute if any of the
            // constituent entity types have the attribute in the schema.
            Type::EntityOrRecord(EntityRecordKind::Entity(entity_lub)) => {
                entity_lub.lub_elements.iter().any(|entity| {
                    schema
                        .get_entity_type(entity)
                        .is_some_and(|entity_type| entity_type.attr(attr).is_some())
                })
            }
            // UBs of ActionEntities are AnyEntity. So if we have an ActionEntity here its attrs are known.
            Type::EntityOrRecord(EntityRecordKind::ActionEntity { attrs, .. }) => {
                attrs.iter().any(|(found_attr, _)| attr.eq(found_attr))
            }
            // A record will have an attribute if the attribute is in its
            // attributes map. Records computed as a LUB may have an open
            // attributes record, but that is handled by the first match case.
            Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) => {
                attrs.get_attr(attr).is_some()
            }
            // `AnyEntity` is handled by the open-attribute match case.
            // No other types may have attributes.
            _ => false,
        }
    }

    /// Is this validator type "consistent with" the given Core `SchemaType`.
    /// Meaning, is there at least some value that could have this `SchemaType` and
    /// this validator type simultaneously.
    pub(crate) fn is_consistent_with(&self, core_type: &CoreSchemaType) -> bool {
        match core_type {
            CoreSchemaType::Bool => matches!(
                self,
                Type::True
                    | Type::False
                    | Type::Primitive {
                        primitive_type: Primitive::Bool
                    }
            ),
            CoreSchemaType::Long => matches!(
                self,
                Type::Primitive {
                    primitive_type: Primitive::Long
                }
            ),
            CoreSchemaType::String => matches!(
                self,
                Type::Primitive {
                    primitive_type: Primitive::String
                }
            ),
            CoreSchemaType::Set { element_ty } => {
                matches!(self, Type::Set { element_type: Some(element_type) } if element_type.is_consistent_with(element_ty))
            }
            CoreSchemaType::EmptySet => {
                // for any given validator Set type, there is some value (namely, the empty set)
                // that could have the EmptySet CoreSchemaType and that validator Set type.
                matches!(self, Type::Set { .. })
            }
            CoreSchemaType::Record {
                attrs: core_attrs,
                open_attrs: core_open,
            } => match self {
                Type::EntityOrRecord(kind) => match kind {
                    EntityRecordKind::Record {
                        attrs: self_attrs,
                        open_attributes: self_open,
                    } => {
                        core_attrs.iter().all(|(k, core_attr_ty)| {
                            match self_attrs.get_attr(k) {
                                Some(self_attr_ty) => {
                                    // both have the attribute, doesn't matter
                                    // if one or both consider it required or
                                    // optional
                                    self_attr_ty
                                        .attr_type
                                        .is_consistent_with(core_attr_ty.schema_type())
                                }
                                None => {
                                    // core_attrs has the attribute, self_attrs does not.
                                    // if required in core_attrs, incompatible.
                                    // otherwise fine
                                    !core_attr_ty.is_required() || self_open.is_open()
                                }
                            }
                        }) && self_attrs.iter().all(|(k, self_attr_ty)| {
                            match core_attrs.get(k) {
                                Some(core_attr_ty) => {
                                    // both have the attribute, doesn't matter
                                    // if one or both consider it required or
                                    // optional
                                    self_attr_ty
                                        .attr_type
                                        .is_consistent_with(core_attr_ty.schema_type())
                                }
                                None => {
                                    // self_attrs has the attribute, core_attrs does not.
                                    // if required in self_attrs, incompatible.
                                    // otherwise fine
                                    !self_attr_ty.is_required || *core_open
                                }
                            }
                        })
                    }
                    EntityRecordKind::Entity(_)
                    | EntityRecordKind::AnyEntity
                    | EntityRecordKind::ActionEntity { .. } => false,
                },
                _ => false,
            },
            CoreSchemaType::Entity { ty: concrete_name } => match self {
                Type::EntityOrRecord(kind) => match kind {
                    EntityRecordKind::Entity(lub) => {
                        lub.lub_elements.iter().any(|n| n == concrete_name)
                    }
                    EntityRecordKind::AnyEntity => true,
                    EntityRecordKind::Record { .. } => false,
                    EntityRecordKind::ActionEntity { name, .. } => concrete_name.eq(name),
                },
                _ => false,
            },
            CoreSchemaType::Extension { name } => {
                matches!(self, Type::ExtensionType { name: n } if name == n)
            }
        }
    }

    /// Does the given `PartialValue` have this validator type?
    ///
    /// If the `PartialValue` is a residual with not enough information to
    /// determine conclusively that it either does or does not typecheck (i.e.,
    /// it does typecheck for some permissible substitutions of the unknowns,
    /// but does not typecheck for other permissible substitutions), this is
    /// reported as an error.
    ///
    /// TODO(#437): Handling of `Unknown`s is not yet complete and doesn't
    /// properly behave according to the above description, as of this writing.
    pub(crate) fn typecheck_partial_value(
        &self,
        value: &PartialValue,
        extensions: &Extensions<'_>,
    ) -> Result<bool, ExtensionFunctionLookupError> {
        match value {
            PartialValue::Value(value) => self.typecheck_value(value, extensions),
            PartialValue::Residual(expr) => match BorrowedRestrictedExpr::new(expr) {
                Ok(rexpr) => self.typecheck_restricted_expr(rexpr, extensions),
                Err(_) => Ok(false), // TODO(#437): instead of just reporting typecheck fails for all nontrivial residuals, we should do something more intelligent
            },
        }
    }

    /// Does the given `Value` have this validator type?
    pub(crate) fn typecheck_value(
        &self,
        value: &Value,
        extensions: &Extensions<'_>,
    ) -> Result<bool, ExtensionFunctionLookupError> {
        // we accept the overhead of cloning the `Value` and converting to
        // `RestrictedExpr` in order to improve code reuse and maintainability
        let rexpr = RestrictedExpr::from(value.clone());
        self.typecheck_restricted_expr(rexpr.as_borrowed(), extensions)
    }

    /// Does the given `BorrowedRestrictedExpr` have this validator type?
    ///
    /// TODO(#437): Handling of restricted exprs containing `Unknown`s is not
    /// yet complete or correct, as of this writing.
    pub(crate) fn typecheck_restricted_expr(
        &self,
        restricted_expr: BorrowedRestrictedExpr<'_>,
        extensions: &Extensions<'_>,
    ) -> Result<bool, ExtensionFunctionLookupError> {
        match self {
            Type::Never => Ok(false), // no expr has type Never
            Type::Primitive {
                primitive_type: Primitive::Bool,
            } => Ok(restricted_expr.as_bool().is_some()),
            Type::Primitive {
                primitive_type: Primitive::Long,
            } => Ok(restricted_expr.as_long().is_some()),
            Type::Primitive {
                primitive_type: Primitive::String,
            } => Ok(restricted_expr.as_string().is_some()),
            Type::True => Ok(restricted_expr.as_bool() == Some(true)),
            Type::False => Ok(restricted_expr.as_bool() == Some(false)),
            Type::Set { element_type: None } => Ok(restricted_expr.as_set_elements().is_some()),
            Type::Set {
                element_type: Some(el_type),
            } => match restricted_expr.as_set_elements() {
                Some(elts) => {
                    for elt in elts {
                        if !el_type.typecheck_restricted_expr(elt, extensions)? {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                None => Ok(false),
            },
            Type::EntityOrRecord(EntityRecordKind::Entity(lub)) => {
                match restricted_expr.as_euid() {
                    Some(euid) => Ok(lub.contains(euid.entity_type())),
                    None => Ok(false),
                }
            }
            Type::EntityOrRecord(EntityRecordKind::ActionEntity { name, .. }) => {
                match restricted_expr.as_euid() {
                    Some(euid) if euid.is_action() => Ok(euid.entity_type() == name),
                    _ => Ok(false),
                }
            }
            Type::EntityOrRecord(EntityRecordKind::AnyEntity) => {
                Ok(restricted_expr.as_euid().is_some())
            }
            Type::EntityOrRecord(EntityRecordKind::Record {
                attrs,
                open_attributes,
            }) => match restricted_expr.as_record_pairs() {
                Some(pairs) => {
                    let record: HashMap<_, BorrowedRestrictedExpr<'_>> = pairs.collect();
                    for (k, attr_val) in &record {
                        match attrs.get_attr(k) {
                            Some(attr_ty) => {
                                if !attr_ty
                                    .attr_type
                                    .typecheck_restricted_expr(attr_val.to_owned(), extensions)?
                                {
                                    return Ok(false);
                                }
                            }
                            None => {
                                if open_attributes != &OpenTag::OpenAttributes {
                                    // the restricted expr has an attribute not
                                    // listed in the Type, and the Type doesn't
                                    // have open attributes
                                    return Ok(false);
                                }
                            }
                        }
                    }
                    // we've now checked that all of the attrs in `restricted_expr` are OK and have the right types.
                    // what remains is making sure that all the required attrs are actually in `restricted_expr`
                    for (k, attr_ty) in attrs.iter() {
                        if attr_ty.is_required && !record.contains_key(k) {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                None => Ok(false),
            },
            Type::ExtensionType { name } => match restricted_expr.as_extn_fn_call() {
                Some((fn_name, args)) => {
                    let func = extensions.func(fn_name)?;
                    match func.return_type() {
                        Some(CoreSchemaType::Extension { name: actual_name }) => {
                            if actual_name != name {
                                return Ok(false);
                            }
                        }
                        _ => return Ok(false),
                    }
                    for (actual_arg, expected_arg_ty) in args.zip(func.arg_types()) {
                        if typecheck_restricted_expr_against_schematype(
                            actual_arg,
                            expected_arg_ty,
                            extensions,
                        )
                        .is_err()
                        {
                            return Ok(false);
                        }
                    }
                    // if we got here, then the return type and arg types typecheck
                    Ok(true)
                }
                None => Ok(false), // no other kinds of restricted expr (other than fn calls) can produce extension-typed values
            },
        }
    }

    /// Returns `true` when the type is a type of an entity
    #[cfg(feature = "entity-manifest")]
    pub(crate) fn is_entity_type(&self) -> bool {
        matches!(
            self,
            Type::EntityOrRecord(EntityRecordKind::Entity(_))
                | Type::EntityOrRecord(EntityRecordKind::AnyEntity)
                | Type::EntityOrRecord(EntityRecordKind::ActionEntity { .. })
        )
    }
}

impl Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Type::Never => write!(f, "__cedar::internal::Never"),
            Type::True => write!(f, "__cedar::internal::True"),
            Type::False => write!(f, "__cedar::internal::False"),
            Type::Primitive {
                primitive_type: Primitive::Long,
            } => write!(f, "Long"),
            Type::Primitive {
                primitive_type: Primitive::Bool,
            } => write!(f, "Bool"),
            Type::Primitive {
                primitive_type: Primitive::String,
            } => write!(f, "String"),
            Type::Set { element_type } => match element_type {
                Some(element_type) => write!(f, "Set<{element_type}>"),
                None => write!(f, "Set<__cedar::internal::Any>"),
            },
            Type::EntityOrRecord(EntityRecordKind::AnyEntity) => {
                write!(f, "__cedar::internal::AnyEntity")
            }
            // Ignoring action attributes for display purposes.
            Type::EntityOrRecord(EntityRecordKind::ActionEntity {
                name,
                attrs: _attrs,
            }) => write!(f, "{name}"),
            Type::EntityOrRecord(EntityRecordKind::Entity(elub)) => {
                match elub.get_single_entity() {
                    Some(e) => write!(f, "{e}"),
                    None => write!(
                        f,
                        "__cedar::internal::Union<{}>",
                        elub.iter().map(ToString::to_string).join(", ")
                    ),
                }
            }
            Type::EntityOrRecord(EntityRecordKind::Record {
                attrs,
                open_attributes,
            }) => {
                if open_attributes.is_open() {
                    write!(f, "__cedar::internal::OpenRecord")?;
                }
                write!(f, "{{")?;
                for (name, ty) in attrs.iter() {
                    write!(f, "{name}")?;
                    if !ty.is_required() {
                        write!(f, "?")?;
                    }
                    write!(f, ": ")?;
                    ty.display_type(f)?;
                    write!(f, ",")?;
                }
                write!(f, "}}")
            }
            Type::ExtensionType { name } => write!(f, "{name}"),
        }
    }
}

impl TryFrom<Type> for CoreSchemaType {
    type Error = String;
    fn try_from(ty: Type) -> Result<CoreSchemaType, String> {
        match ty {
            Type::Never => Err("'Never' type is not representable in core::SchemaType".into()),
            Type::True | Type::False => Ok(CoreSchemaType::Bool),
            Type::Primitive {
                primitive_type: Primitive::Bool,
            } => Ok(CoreSchemaType::Bool),
            Type::Primitive {
                primitive_type: Primitive::Long,
            } => Ok(CoreSchemaType::Long),
            Type::Primitive {
                primitive_type: Primitive::String,
            } => Ok(CoreSchemaType::String),
            Type::Set {
                element_type: Some(element_type),
            } => Ok(CoreSchemaType::Set {
                element_ty: Box::new(CoreSchemaType::try_from(*element_type)?),
            }),
            Type::Set { element_type: None } => Ok(CoreSchemaType::EmptySet),
            Type::EntityOrRecord(kind @ EntityRecordKind::AnyEntity) => Err(format!(
                "any-entity type is not representable in core::SchemaType: {kind:?}"
            )),
            Type::EntityOrRecord(EntityRecordKind::ActionEntity { name, .. }) => {
                Ok(CoreSchemaType::Entity { ty: name })
            }
            Type::EntityOrRecord(EntityRecordKind::Record {
                attrs,
                open_attributes,
            }) => Ok(CoreSchemaType::Record {
                attrs: {
                    attrs
                        .into_iter()
                        .map(|(k, v)| {
                            let schema_type = v.attr_type.try_into()?;
                            Ok((
                                k,
                                match v.is_required {
                                    true => CoreAttributeType::required(schema_type),
                                    false => CoreAttributeType::optional(schema_type),
                                },
                            ))
                        })
                        .collect::<Result<_, String>>()?
                },
                open_attrs: open_attributes.is_open(),
            }),
            Type::EntityOrRecord(EntityRecordKind::Entity(lub)) => match lub.into_single_entity() {
                Some(name) => Ok(CoreSchemaType::Entity { ty: name }),
                None => Err(
                    "non-singleton LUB type is not representable in core::SchemaType".to_string(),
                ),
            },
            Type::ExtensionType { name } => Ok(CoreSchemaType::Extension { name }),
        }
    }
}

/// Represents the least upper bound of multiple entity types. This can be used
/// to represent the least upper bound of a single entity type, in which case it
/// is exactly that entity type.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Serialize)]
pub struct EntityLUB {
    /// We store `EntityType` here because these are entity types.
    /// As of this writing, `EntityType` is backed by `Name` (rather than
    /// `InternalName`), so this excludes entity types containing `__cedar`.
    /// As of this writing, there are no valid entity types that contain
    /// `__cedar`.
    /// If that changes in the future, we will have to change this here to
    /// `InternalName`, or change `EntityType` to be backed by `InternalName`
    /// instead of `Name`.
    //
    // INVARIANT: Non-empty set.
    lub_elements: BTreeSet<EntityType>,
}

impl EntityLUB {
    /// Create a least upper bound of a single entity type. This is the same as
    /// just that entity type.
    pub fn single_entity(entity_type_name: EntityType) -> Self {
        Self {
            lub_elements: BTreeSet::from([entity_type_name]),
        }
    }

    /// Check if this LUB is a singleton, and if so, return a reference to its entity type
    pub fn get_single_entity(&self) -> Option<&EntityType> {
        let mut names = self.lub_elements.iter();
        // PANIC SAFETY: Invariant on `lub_elements` guarantees the set is non-empty.
        #[allow(clippy::expect_used)]
        let first = names.next().expect("should have one element by invariant");
        match names.next() {
            Some(_) => None, // there are two or more names
            None => Some(first),
        }
    }

    /// Like `get_single_entity()`, but consumes the [`EntityLUB`] and produces an
    /// owned entity type name
    pub fn into_single_entity(self) -> Option<EntityType> {
        let mut names = self.lub_elements.into_iter();
        // PANIC SAFETY: Invariant on `lub_elements` guarantees the set is non-empty.
        #[allow(clippy::expect_used)]
        let first = names.next().expect("should have one element by invariant");
        match names.next() {
            Some(_) => None, // there are two or more names
            None => Some(first),
        }
    }

    /// Check if the entity least upper bound is a subtype of another. This is
    /// the case when the entity types in the least upper bound are a subset of
    /// the entity types in the other.
    fn is_subtype(&self, other: &EntityLUB) -> bool {
        self.lub_elements.is_subset(&other.lub_elements)
    }

    /// Retrieve the attributes and their types. If this is a single entity type,
    /// then return exactly the attributes stored in schema for that entity
    /// type. Otherwise, retrieve all attribute maps for all entities in the
    /// least upper bound and compute the least upper bound of these maps. This
    /// will keep only the common attributes with a type that is the least upper
    /// bound of the all the attribute type.
    fn get_attribute_types(&self, schema: &ValidatorSchema) -> Attributes {
        let mut lub_element_attributes = self.lub_elements.iter().map(|name| {
            schema
                .get_entity_type(name)
                .map(ValidatorEntityType::attributes)
                .cloned()
                .unwrap_or_else(|| Attributes::with_attributes(None))
        });

        // If I wanted to write this as a fold over a possibly empty set, I
        // would need a bottom record type that would contain every attribute with a
        // bottom type. We don't have that, so I instead restrict EntityLUB to
        // be a least upper bound of one or more entities.
        // PANIC SAFETY: Invariant on `lub_elements` guarantees the set is non-empty.
        #[allow(clippy::expect_used)]
        let arbitrary_first = Attributes::with_attributes(
            lub_element_attributes
                .next()
                .expect("Invariant violated: EntityLUB set must be non-empty."),
        );
        lub_element_attributes.fold(arbitrary_first, |acc, elem| {
            // Use the permissive version of least upper bound here for two
            // reasons. First, when in permissive mode, the attributes least
            // upper bound can never fail. We could call the main lub function
            // with an unwrap, but this avoids a chance at a panic. Second, when
            // in strict mode, an entity LUB will only ever have a single
            // element, so that LUB can never fail, and the strict
            // attributes lub is the same as permissive if there is only one
            // attribute.
            Attributes::permissive_least_upper_bound(
                schema,
                &acc,
                &Attributes::with_attributes(elem),
            )
        })
    }

    /// Generate the least upper bound of this [`EntityLUB`] and another. This
    /// returns an [`EntityLUB`] for the union of the entity types in both argument
    /// LUBs. The attributes of the LUB are not computed.
    pub(crate) fn least_upper_bound(&self, other: &EntityLUB) -> EntityLUB {
        EntityLUB {
            lub_elements: self
                .lub_elements
                .union(&other.lub_elements)
                .cloned()
                .collect::<BTreeSet<_>>(),
        }
    }

    /// Return true if the set of entity types composing this [`EntityLUB`] is
    /// disjoint from th entity types composing another [`EntityLUB`].
    pub(crate) fn is_disjoint(&self, other: &EntityLUB) -> bool {
        self.lub_elements.is_disjoint(&other.lub_elements)
    }

    /// Return true if the given entity type [`Name`] is in the set of entity
    /// types comprising this [`EntityLUB`].
    pub(crate) fn contains(&self, ty: &EntityType) -> bool {
        self.lub_elements.contains(ty)
    }

    /// An iterator over the entity type [`Name`]s in the set of entity types
    /// comprising this [`EntityLUB`].
    pub(crate) fn iter(&self) -> impl Iterator<Item = &EntityType> {
        self.lub_elements.iter()
    }

    // Check if this [`EntityLUB`] contains a particular entity type.
    pub(crate) fn contains_entity_type(&self, ety: &EntityType) -> bool {
        self.lub_elements.contains(ety)
    }
}

/// Represents the attributes of a record or entity type. Each attribute has an
/// identifier, a flag indicating weather it is required, and a type.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Serialize, Default)]
pub struct Attributes {
    /// Attributes map
    attrs: BTreeMap<SmolStr, AttributeType>,
}

impl Attributes {
    /// Construct an [`Attributes`] with some required attributes.
    pub fn with_required_attributes(
        required_attrs: impl IntoIterator<Item = (SmolStr, Type)>,
    ) -> Self {
        Self::with_attributes(
            required_attrs
                .into_iter()
                .map(|(attr, ty)| (attr, AttributeType::required_attribute(ty))),
        )
    }

    /// Construct a [`Attributes`] with some attributes that may be required or
    /// optional.
    pub fn with_attributes(attrs: impl IntoIterator<Item = (SmolStr, AttributeType)>) -> Self {
        Self {
            attrs: attrs.into_iter().collect(),
        }
    }

    /// Iterate over the attributes of this record with their types
    pub fn iter(&self) -> impl Iterator<Item = (&SmolStr, &AttributeType)> {
        self.attrs.iter()
    }

    /// Iterate over the attribute names of this record
    pub fn keys(&self) -> impl Iterator<Item = &SmolStr> {
        self.attrs.keys()
    }

    /// Get the `AttributeType` of the given attribute, or `None` if the
    /// attribute is not in the record or entity
    pub fn get_attr(&self, attr: &str) -> Option<&AttributeType> {
        self.attrs.get(attr)
    }

    pub(crate) fn is_subtype(
        &self,
        schema: &ValidatorSchema,
        other: &Attributes,
        mode: ValidationMode,
    ) -> bool {
        // For a one record type to subtype another, all the attributes of the
        // second must be present in the first, and each attribute types must
        // subtype the corresponding attribute type. If an attribute in the
        // first is not required (optional), then that attribute must also be
        // optional in the second.
        other.attrs.iter().all(|(k, other_ty)| {
            self.attrs
                .get(k)
                .map(|self_ty| AttributeType::is_subtype(schema, self_ty, other_ty, mode))
                .unwrap_or(false)
        })
    }

    // Determine if the attributes subtype while only allowing for depth
    // subtyping. This forbids width subtyping, so there may not be attributes
    // present in the subtype that do not exist in the super type.
    pub(crate) fn is_subtype_depth_only(
        &self,
        schema: &ValidatorSchema,
        other: &Attributes,
        mode: ValidationMode,
    ) -> bool {
        other.attrs.keys().collect::<HashSet<_>>() == self.attrs.keys().collect::<HashSet<_>>()
            && self.is_subtype(schema, other, mode)
    }

    pub(crate) fn least_upper_bound(
        schema: &ValidatorSchema,
        attrs0: &Attributes,
        attrs1: &Attributes,
        mode: ValidationMode,
    ) -> Result<Attributes, LubHelp> {
        if mode.is_strict() {
            Self::strict_least_upper_bound(schema, attrs0, attrs1)
        } else {
            Ok(Self::permissive_least_upper_bound(schema, attrs0, attrs1))
        }
    }

    fn attributes_lub_iter<'a>(
        schema: &'a ValidatorSchema,
        attrs0: &'a Attributes,
        attrs1: &'a Attributes,
        mode: ValidationMode,
    ) -> impl Iterator<Item = Result<(&'a SmolStr, AttributeType), LubHelp>> + 'a {
        attrs0.attrs.iter().map(move |(attr, ty0)| {
            let ty1 = attrs1.attrs.get(attr).ok_or(LubHelp::RecordWidth)?;
            Ok((
                attr,
                AttributeType::least_upper_bound(schema, ty0, ty1, mode)?,
            ))
        })
    }

    pub(crate) fn strict_least_upper_bound(
        schema: &ValidatorSchema,
        attrs0: &Attributes,
        attrs1: &Attributes,
    ) -> Result<Attributes, LubHelp> {
        if attrs0.keys().collect::<HashSet<_>>() != attrs1.keys().collect::<HashSet<_>>() {
            return Err(LubHelp::RecordWidth);
        }
        Self::attributes_lub_iter(schema, attrs0, attrs1, ValidationMode::Strict)
            .map(|r| r.map(|(k, v)| (k.clone(), v)))
            .collect::<Result<Vec<_>, _>>()
            .map(Attributes::with_attributes)
    }

    pub(crate) fn permissive_least_upper_bound(
        schema: &ValidatorSchema,
        attrs0: &Attributes,
        attrs1: &Attributes,
    ) -> Attributes {
        Attributes::with_attributes(
            Self::attributes_lub_iter(schema, attrs0, attrs1, ValidationMode::Permissive)
                .flat_map(|r| r.map(|(k, v)| (k.clone(), v))),
        )
    }
}

impl IntoIterator for Attributes {
    type Item = (SmolStr, AttributeType);

    type IntoIter = <BTreeMap<SmolStr, AttributeType> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.attrs.into_iter()
    }
}

/// Used to tag record types to indicate if their attributes record is open or
/// closed.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Copy, Clone, Serialize, Default)]
pub enum OpenTag {
    /// The attributes are open. A value of this type may have attributes other
    /// than those listed.
    OpenAttributes,
    /// The attributes are closed. The attributes for a value of this type must
    /// exactly match the attributes listed in the type.
    #[default]
    ClosedAttributes,
}

impl OpenTag {
    pub(crate) fn is_open(self) -> bool {
        match self {
            OpenTag::OpenAttributes => true,
            OpenTag::ClosedAttributes => false,
        }
    }
}

/// Represents whether a type is an entity type, record type, or could be either
///
/// The subtyping lattice for these types is that
/// `Entity` <: `AnyEntity`. `Record` does not subtype anything.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Serialize)]
pub enum EntityRecordKind {
    /// A record type
    Record {
        /// The attributes that we know must exist (or may exist in the case of
        /// optional attributes) for a record with this type along with the
        /// types the attributes must have if they do exist.
        attrs: Attributes,
        /// Encodes whether the attributes for this record are open or closed.
        open_attributes: OpenTag,
    },

    /// Any entity type
    AnyEntity,
    /// An entity reference type. An entity reference might be a reference to one
    /// of multiple possible entity types when the entity references is the
    /// result of a least upper bound. An arbitrary entity without a name is
    /// represented using the `AnyEntity` record kind.
    ///
    /// Attributes in this case are not stored inline but must be looked up in
    /// the schema, based on the elements of the [`EntityLUB`].
    Entity(EntityLUB),

    /// We special case action entities, which store their attributes directly, like `Record`s do
    ActionEntity {
        /// Type name of the action entity
        name: EntityType,
        /// Attributes of the action entity
        attrs: Attributes,
    },
}

impl EntityRecordKind {
    pub(crate) fn as_entity_lub(&self) -> Option<EntityLUB> {
        match self {
            EntityRecordKind::Record { .. } => None,
            EntityRecordKind::AnyEntity => None,
            EntityRecordKind::Entity(lub) => Some(lub.clone()),
            EntityRecordKind::ActionEntity { name, .. } => {
                Some(EntityLUB::single_entity(name.clone()))
            }
        }
    }

    /// Return `true` if this entity or record may have additional undeclared
    /// attributes.
    pub(crate) fn has_open_attributes_record(&self, schema: &ValidatorSchema) -> bool {
        match self {
            // Records explicitly store this information.
            EntityRecordKind::Record {
                open_attributes, ..
            } => open_attributes.is_open(),
            // We know Actions never have additional attributes. This is true
            // because the upper bound for any two action entities is
            // `AnyEntity`, so if we have an ActionEntity here its attributes
            // are known precisely.
            EntityRecordKind::ActionEntity { .. } => false,
            // The `AnyEntity` type has no declared attributes, but it is a
            // super type of all other entity types which may have attributes,
            // so it clearly may have additional attributes.
            EntityRecordKind::AnyEntity => true,
            // An entity LUB may have additional attributes if any of the
            // elements may have additional attributes.
            EntityRecordKind::Entity(lub) => lub.iter().any(|e_name| {
                schema
                    .get_entity_type(e_name)
                    .map(|e_type| e_type.open_attributes())
                    // The entity type was not found in the schema, so we know
                    // nothing about it and must assume that it may have
                    // additional attributes.
                    .unwrap_or(OpenTag::OpenAttributes)
                    .is_open()
            }),
        }
    }

    /// Get the type of the given attribute in this entity or record.
    ///
    /// - If the attribute is known to not exist on this entity or record, returns
    ///   `None`.
    /// - If the attribute is known to be optional on tihs entity or record,
    ///   returns `Some` with the type.
    ///   (Note that [`AttributeType`] contains an `is_required` flag, so you can
    ///   distinguish this case.)
    /// - If the attribute may exist, but multiple types are possible for the
    ///   attribute (e.g., `AnyEntity`), returns `None`.
    pub(crate) fn get_attr(&self, schema: &ValidatorSchema, attr: &str) -> Option<AttributeType> {
        match self {
            EntityRecordKind::Record { attrs, .. } => attrs.get_attr(attr).cloned(),
            EntityRecordKind::Entity(lub) => {
                lub.get_attribute_types(schema).get_attr(attr).cloned()
            }
            EntityRecordKind::ActionEntity { attrs, .. } => attrs.get_attr(attr).cloned(),
            EntityRecordKind::AnyEntity => {
                // the attribute may exist, but multiple types for it are possible
                None
            }
        }
    }

    /// Get all the attribute names _known to exist_ for this entity or record
    ///
    /// For `AnyEntity`, this will return an empty vec, as there are no
    /// attribute names we _know_ must exist (even though `AnyEntity` types may
    /// clearly have attributes).
    /// For LUB types, this will return only the attribute names known to exist
    /// in the LUB.
    pub fn all_known_attrs(&self, schema: &ValidatorSchema) -> Vec<SmolStr> {
        // Wish the clone here could be avoided, but `get_attribute_types` returns an owned `Attributes`.
        match self {
            EntityRecordKind::Record { attrs, .. } => attrs.attrs.keys().cloned().collect(),
            EntityRecordKind::ActionEntity { attrs, .. } => attrs.attrs.keys().cloned().collect(),
            EntityRecordKind::AnyEntity => vec![],
            EntityRecordKind::Entity(lub) => {
                lub.get_attribute_types(schema).attrs.into_keys().collect()
            }
        }
    }

    pub(crate) fn least_upper_bound(
        schema: &ValidatorSchema,
        rk0: &EntityRecordKind,
        rk1: &EntityRecordKind,
        mode: ValidationMode,
    ) -> Result<EntityRecordKind, LubHelp> {
        use EntityRecordKind::*;
        match (rk0, rk1) {
            (
                Record {
                    attrs: attrs0,
                    open_attributes: open0,
                },
                Record {
                    attrs: attrs1,
                    open_attributes: open1,
                },
            ) => {
                let attrs = Attributes::least_upper_bound(schema, attrs0, attrs1, mode)?;

                // Even though this function will never be called when the
                // records are in a subtype relation, it is still possible that
                // the LUB attribute set is the same the attribute key sets for
                // `rk0` and `rk1`. This occurs when `rk0` and `rk1` have
                // identical attribute keys sets with all corresponding
                // attributes having a LUB while at least one pair of
                // corresponding attributes is not in a subtype relation.
                // E.g., Given `{a: true}` and `{a: false}`, the LUB is `{a: bool}`,
                // and we know that `a` is the only attribute for this (closed)
                // record even though neither is subtype of the other.
                let open_attributes = if open0.is_open()
                    || open1.is_open()
                    || (attrs.keys().collect::<BTreeSet<_>>()
                        != (attrs0.keys().chain(attrs1.keys()).collect::<BTreeSet<_>>()))
                {
                    OpenTag::OpenAttributes
                } else {
                    OpenTag::ClosedAttributes
                };
                Ok(Record {
                    attrs,
                    open_attributes,
                })
            }
            //We cannot, in general, have precise upper bounds between action
            //entities because `may_have_attr` assumes the list of attrs is
            //complete.
            (
                ActionEntity {
                    name: action_type1,
                    attrs: attrs1,
                },
                ActionEntity {
                    name: action_type2,
                    attrs: attrs2,
                },
            ) => {
                if action_type1 == action_type2 {
                    // Same action type. Ensure that the actions have the same
                    // attributes. Computing the LUB under strict mode disables
                    // means that the LUB does not exist if either record has as
                    // an attribute that does not exist in the other, so we know
                    // that list of attributes is complete, as is assumed by
                    // `may_have_attr`. As long as actions have empty an
                    // attribute records, the LUB no-ops, allowing for LUBs
                    // between actions with the same action entity type even in
                    // strict validation mode.
                    Attributes::least_upper_bound(schema, attrs1, attrs2, ValidationMode::Strict)
                        .map(|attrs| ActionEntity {
                            name: action_type1.clone(),
                            attrs,
                        })
                } else if mode.is_strict() {
                    Err(LubHelp::EntityType)
                } else {
                    Ok(AnyEntity)
                }
            }
            (Entity(lub0), Entity(lub1)) => {
                if mode.is_strict() && lub0 != lub1 {
                    Err(LubHelp::EntityType)
                } else {
                    Ok(Entity(lub0.least_upper_bound(lub1)))
                }
            }

            (AnyEntity, AnyEntity) => Ok(AnyEntity),

            (AnyEntity, Entity(_))
            | (Entity(_), AnyEntity)
            | (AnyEntity, ActionEntity { .. })
            | (ActionEntity { .. }, AnyEntity) => {
                if mode.is_strict() {
                    Err(LubHelp::EntityType)
                } else {
                    Ok(AnyEntity)
                }
            }

            // Entity and record types do not have a least upper bound to avoid
            // a non-terminating case.
            (AnyEntity, Record { .. }) | (Record { .. }, AnyEntity) => Err(LubHelp::EntityRecord),
            (Record { .. }, Entity(_)) | (Entity(_), Record { .. }) => Err(LubHelp::EntityRecord),

            //Likewise, we can't mix action entities and records
            (ActionEntity { .. }, Record { .. }) | (Record { .. }, ActionEntity { .. }) => {
                Err(LubHelp::EntityRecord)
            }
            //Action entities can be mixed with Entities. In this case, the LUB is AnyEntity
            (ActionEntity { .. }, Entity(_)) | (Entity(_), ActionEntity { .. }) => {
                if mode.is_strict() {
                    Err(LubHelp::EntityType)
                } else {
                    Ok(AnyEntity)
                }
            }
        }
    }

    /// Record/entity subtype is based on the lattice named entity <: arbitrary
    /// entity. We do not support subtyping between records and entities.
    pub(crate) fn is_subtype(
        schema: &ValidatorSchema,
        rk0: &EntityRecordKind,
        rk1: &EntityRecordKind,
        mode: ValidationMode,
    ) -> bool {
        use EntityRecordKind::*;
        match (rk0, rk1) {
            (
                Record {
                    attrs: attrs0,
                    open_attributes: open0,
                },
                Record {
                    attrs: attrs1,
                    open_attributes: open1,
                },
            ) => {
                // Closed attributes subtype open attributes. A record type with
                // open attributes may contain a value that is not in a record
                // type with closed attributes, so open attribute record types
                // can never subtype closed attribute record types.
                (!open0.is_open() || open1.is_open())
                // When `rk1` has open attributes, width subtyping applies since
                // there may be attributes in `rk0` that are not listed in
                // `rk1`.  When `rk1` is closed, a subtype of `rk1` may not have
                // any attributes that are not listed in `rk1`, so we apply
                // depth subtyping only. We apply this same restriction in
                // strict mode, i.e., strict mode applies depth subtyping but
                // not width subtyping.
                    && ((open1.is_open() && !mode.is_strict() && attrs0.is_subtype(schema, attrs1, mode))
                        || attrs0.is_subtype_depth_only(schema, attrs1, mode))
            }
            (ActionEntity { .. }, ActionEntity { .. }) => rk0 == rk1,
            (Entity(lub0), Entity(lub1)) => {
                if mode.is_strict() {
                    lub0 == lub1
                } else {
                    lub0.is_subtype(lub1)
                }
            }

            (AnyEntity, AnyEntity) => true,
            (Entity(_) | ActionEntity { .. }, AnyEntity) => !mode.is_strict(),

            // Entities cannot subtype records or vice-versa because their LUB
            // is undefined to avoid a non-terminating case.
            (Entity(_) | AnyEntity | ActionEntity { .. }, Record { .. }) => false,
            (Record { .. }, Entity(_) | AnyEntity | ActionEntity { .. }) => false,

            (ActionEntity { .. }, Entity(_)) => false,
            (AnyEntity, Entity(_)) => false,
            (Entity(_) | AnyEntity, ActionEntity { .. }) => false,
        }
    }
}

/// Contains the type of a record attribute and if the attribute is required.
#[derive(Ord, PartialOrd, Educe, Debug, Clone, Serialize)]
#[educe(Eq, PartialEq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct AttributeType {
    /// The type of the attribute.
    pub attr_type: Type,

    /// True when the attribute must be present. False if it is optional, and so
    /// may not be present in a record or entity.
    pub is_required: bool,
    ///  Source location - if available
    #[cfg(feature = "extended-schema")]
    #[serde(skip)]
    #[educe(Eq(ignore))]
    pub loc: Option<Loc>,
}

impl AttributeType {
    /// Construct an [`AttributeType`] with some type that may be required or
    /// optional as specified by the `is_required` parameter.
    pub fn new(attr_type: Type, is_required: bool) -> Self {
        Self {
            attr_type,
            is_required,
            #[cfg(feature = "extended-schema")]
            loc: None,
        }
    }

    #[cfg(feature = "extended-schema")]
    /// Construct an [`AttributeType`] with some type that may be required or
    /// optional as specified by the `is_required` parameter - includes source location
    pub fn new_with_loc(attr_type: Type, is_required: bool, loc: Option<Loc>) -> Self {
        Self {
            attr_type,
            is_required,
            loc,
        }
    }

    /// Construct an [`AttributeType`] for an attribute that is required.
    pub fn required_attribute(attr_type: Type) -> Self {
        Self::new(attr_type, true)
    }

    /// Construct an [`AttributeType`] for an attribute that is optional.
    pub fn optional_attribute(attr_type: Type) -> Self {
        Self::new(attr_type, false)
    }

    /// Is the attribute required?
    pub fn is_required(&self) -> bool {
        self.is_required
    }

    /// Display just the type portion of the [`AttributeType`], ignoring the
    /// `is_required` flag
    fn display_type(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.attr_type.fmt(f)
    }

    /// Get the least upper bound of two [`AttributeType`]s
    fn least_upper_bound(
        schema: &ValidatorSchema,
        ty0: &AttributeType,
        ty1: &AttributeType,
        mode: ValidationMode,
    ) -> Result<AttributeType, LubHelp> {
        Type::least_upper_bound(schema, &ty0.attr_type, &ty1.attr_type, mode).and_then(|lub| {
            let is_lub_required = ty0.is_required() && ty1.is_required();
            if mode.is_strict() && ty0.is_required() != ty1.is_required() {
                Err(LubHelp::AttributeQualifier)
            } else {
                Ok(AttributeType::new(lub, is_lub_required))
            }
        })
    }

    /// Is `ty0` a subtype of `ty1`?
    fn is_subtype(
        schema: &ValidatorSchema,
        ty0: &AttributeType,
        ty1: &AttributeType,
        mode: ValidationMode,
    ) -> bool {
        let qualifier_subtype = if mode.is_strict() {
            ty0.is_required() == ty1.is_required()
        } else {
            ty0.is_required() || !ty1.is_required()
        };
        qualifier_subtype && Type::is_subtype(schema, &ty0.attr_type, &ty1.attr_type, mode)
    }
}

/// Represent the possible primitive types.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Serialize)]
pub enum Primitive {
    /// Primitive boolean type.
    Bool,
    /// Primitive long type.
    Long,
    /// Primitive string type.
    String,
}

impl Primitive {
    /// Check if a string is a primitive
    #[cfg(feature = "extended-schema")]
    pub(crate) fn is_primitive(s: &str) -> bool {
        matches!(s, "Bool" | "Long" | "String")
    }
}

// PANIC SAFETY unit tests
#[allow(clippy::panic)]
// PANIC SAFETY unit tests
#[allow(clippy::indexing_slicing)]
#[cfg(test)]
mod test {
    use super::*;
    use crate::validator::{json_schema, ActionBehavior};
    use cool_asserts::assert_matches;

    impl Type {
        pub(crate) fn entity_lub<'a>(es: impl IntoIterator<Item = &'a str>) -> Type {
            let lub = EntityLUB {
                lub_elements: es.into_iter().map(|e| e.parse().unwrap()).collect(),
            };
            assert!(!lub.lub_elements.is_empty());
            Type::EntityOrRecord(EntityRecordKind::Entity(lub))
        }

        pub(crate) fn open_record_with_required_attributes(
            required_attrs: impl IntoIterator<Item = (SmolStr, Type)>,
        ) -> Type {
            Type::EntityOrRecord(EntityRecordKind::Record {
                attrs: Attributes::with_required_attributes(required_attrs),
                open_attributes: OpenTag::OpenAttributes,
            })
        }

        pub(crate) fn closed_record_with_required_attributes(
            required_attrs: impl IntoIterator<Item = (SmolStr, Type)>,
        ) -> Type {
            Type::record_with_required_attributes(required_attrs, OpenTag::ClosedAttributes)
        }

        pub(crate) fn open_record_with_attributes(
            attrs: impl IntoIterator<Item = (SmolStr, AttributeType)>,
        ) -> Type {
            Self::record_with_attributes(attrs, OpenTag::OpenAttributes)
        }

        pub(crate) fn closed_record_with_attributes(
            attrs: impl IntoIterator<Item = (SmolStr, AttributeType)>,
        ) -> Type {
            Self::record_with_attributes(attrs, OpenTag::ClosedAttributes)
        }
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_least_upper_bound(
        schema: ValidatorSchema,
        mode: ValidationMode,
        lhs: Type,
        rhs: Type,
        lub: Result<Type, LubHelp>,
    ) {
        assert_eq!(
            Type::least_upper_bound(&schema, &lhs, &rhs, mode),
            lub,
            "assert_least_upper_bound({lhs:?}, {rhs:?}, {lub:?}, {mode:?})",
        );

        if let Ok(lub_ty) = &lub {
            // Also assert that types are subtypes of the LUB
            assert!(
                Type::is_subtype(&schema, &lhs, lub_ty, mode),
                "{lhs:?} </: ({mode:?}) {lub_ty:?}"
            );
            assert!(
                Type::is_subtype(&schema, &rhs, lub_ty, mode),
                "{rhs:?} </: ({mode:?}) {lub_ty:?}"
            );

            // Permissive LUB should be the same as strict when the strict LUB is defined.
            if mode == ValidationMode::Strict {
                assert_least_upper_bound(schema, ValidationMode::Permissive, lhs, rhs, lub);
            }
        } else if mode == ValidationMode::Permissive {
            // Lub is `Err` for permissive, so it should also be `Err` for strict.
            assert_least_upper_bound(schema, ValidationMode::Strict, lhs, rhs, lub);
        }
    }
    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_entity_lub(
        schema: ValidatorSchema,
        mode: ValidationMode,
        lhs: Type,
        rhs: Type,
        lub_names: &[&str],
        lub_attrs: &[(&str, Type)],
    ) {
        let lub = Type::least_upper_bound(&schema, &lhs, &rhs, mode);
        assert_matches!(&lub, Ok(Type::EntityOrRecord(EntityRecordKind::Entity(entity_lub))) => {
            assert_eq!(
                lub_names
                    .iter()
                    .map(|s| s.parse().expect("Expected valid entity type name."))
                    .collect::<BTreeSet<_>>(),
                entity_lub.lub_elements,
                "Incorrect entity types composing LUB for {mode:?}."
            );
            assert_eq!(
                Attributes::with_attributes(
                    lub_attrs
                        .iter()
                        .map(|(s, t)| (
                            AsRef::<str>::as_ref(s).into(),
                            AttributeType::required_attribute(t.clone())
                        ))
                ),
                entity_lub.get_attribute_types(&schema),
                "Incorrect computed record type for LUB for {mode:?}."
            );
        });

        // Also assert that types are subtypes of the LUB
        assert!(
            Type::is_subtype(&schema, &lhs, lub.as_ref().unwrap(), mode),
            "{lhs:?} </: ({mode:?}) {lub:?}"
        );
        assert!(
            Type::is_subtype(&schema, &rhs, lub.as_ref().unwrap(), mode),
            "{rhs:?} </: ({mode:?}) {lub:?}"
        );

        // Permissive LUB should be the same as strict when the strict LUB is defined.
        if mode == ValidationMode::Strict {
            assert_entity_lub(
                schema,
                ValidationMode::Permissive,
                lhs,
                rhs,
                lub_names,
                lub_attrs,
            );
        }
    }

    #[test]
    fn test_primitive_lub() {
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::False,
            Type::True,
            Ok(Type::primitive_boolean()),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::False,
            Type::False,
            Ok(Type::False),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::False,
            Type::primitive_boolean(),
            Ok(Type::primitive_boolean()),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::True,
            Type::True,
            Ok(Type::True),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::True,
            Type::False,
            Ok(Type::primitive_boolean()),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::True,
            Type::primitive_boolean(),
            Ok(Type::primitive_boolean()),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::primitive_boolean(),
            Type::False,
            Ok(Type::primitive_boolean()),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::primitive_boolean(),
            Type::True,
            Ok(Type::primitive_boolean()),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::primitive_boolean(),
            Type::primitive_boolean(),
            Ok(Type::primitive_boolean()),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::primitive_string(),
            Type::primitive_string(),
            Ok(Type::primitive_string()),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::primitive_long(),
            Type::primitive_long(),
            Ok(Type::primitive_long()),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::False,
            Type::primitive_string(),
            Err(LubHelp::None),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::False,
            Type::primitive_long(),
            Err(LubHelp::None),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::True,
            Type::primitive_string(),
            Err(LubHelp::None),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::True,
            Type::primitive_long(),
            Err(LubHelp::None),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::primitive_boolean(),
            Type::primitive_string(),
            Err(LubHelp::None),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::primitive_boolean(),
            Type::primitive_long(),
            Err(LubHelp::None),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::primitive_string(),
            Type::primitive_long(),
            Err(LubHelp::None),
        );
    }

    #[test]
    fn test_extension_lub() {
        let ipaddr: Name = "ipaddr".parse().expect("should be a valid identifier");
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::extension(ipaddr.clone()),
            Type::extension(ipaddr.clone()),
            Ok(Type::extension(ipaddr.clone())),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::extension(ipaddr.clone()),
            Type::extension("test".parse().expect("should be a valid identifier")),
            Err(LubHelp::None),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::extension(ipaddr.clone()),
            Type::False,
            Err(LubHelp::None),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::extension(ipaddr.clone()),
            Type::primitive_string(),
            Err(LubHelp::None),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::extension(ipaddr),
            Type::any_entity_reference(),
            Err(LubHelp::None),
        );
    }

    #[test]
    fn test_set_lub() {
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::set(Type::True),
            Type::set(Type::True),
            Ok(Type::set(Type::True)),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::set(Type::False),
            Type::set(Type::True),
            Ok(Type::set(Type::primitive_boolean())),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::set(Type::primitive_boolean()),
            Type::set(Type::primitive_long()),
            Err(LubHelp::None),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::set(Type::primitive_boolean()),
            Type::primitive_boolean(),
            Err(LubHelp::None),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::any_set(),
            Type::any_set(),
            Ok(Type::any_set()),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::any_set(),
            Type::set(Type::primitive_long()),
            Ok(Type::any_set()),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::set(Type::primitive_long()),
            Type::any_set(),
            Ok(Type::any_set()),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::any_set(),
            Type::primitive_boolean(),
            Err(LubHelp::None),
        );
    }

    #[test]
    fn test_record_undef_lub() {
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::open_record_with_attributes(None),
            Type::primitive_string(),
            Err(LubHelp::None),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::closed_record_with_attributes(None),
            Type::primitive_string(),
            Err(LubHelp::None),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::closed_record_with_attributes(None),
            Type::set(Type::primitive_boolean()),
            Err(LubHelp::None),
        );
    }

    #[test]
    fn test_record_lub() {
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::closed_record_with_attributes(None),
            Type::closed_record_with_attributes(None),
            Ok(Type::closed_record_with_attributes(None)),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::closed_record_with_attributes(None),
            Type::open_record_with_attributes(None),
            Ok(Type::open_record_with_attributes(None)),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::open_record_with_attributes(None),
            Type::closed_record_with_attributes(None),
            Ok(Type::open_record_with_attributes(None)),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::open_record_with_attributes(None),
            Type::open_record_with_attributes(None),
            Ok(Type::open_record_with_attributes(None)),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::False),
                ("bar".into(), Type::primitive_long()),
            ]),
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::primitive_string()),
                ("bar".into(), Type::primitive_long()),
            ]),
            Ok(Type::open_record_with_required_attributes([(
                "bar".into(),
                Type::primitive_long(),
            )])),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::False),
                ("bar".into(), Type::primitive_long()),
            ]),
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::primitive_string()),
                ("bar".into(), Type::primitive_long()),
            ]),
            Err(LubHelp::None),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::closed_record_with_required_attributes([("bar".into(), Type::primitive_long())]),
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::primitive_string()),
                ("bar".into(), Type::primitive_long()),
            ]),
            Ok(Type::open_record_with_required_attributes([(
                "bar".into(),
                Type::primitive_long(),
            )])),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::closed_record_with_required_attributes([("bar".into(), Type::primitive_long())]),
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::primitive_string()),
                ("bar".into(), Type::primitive_long()),
            ]),
            Err(LubHelp::RecordWidth),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::closed_record_with_required_attributes([("a".into(), Type::True)]),
            Type::closed_record_with_required_attributes([("a".into(), Type::False)]),
            Ok(Type::closed_record_with_required_attributes([(
                "a".into(),
                Type::primitive_boolean(),
            )])),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::False),
                ("bar".into(), Type::primitive_long()),
            ]),
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::True),
                ("baz".into(), Type::primitive_long()),
            ]),
            Ok(Type::open_record_with_required_attributes([(
                "foo".into(),
                Type::primitive_boolean(),
            )])),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::False),
                ("bar".into(), Type::primitive_long()),
            ]),
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::True),
                ("baz".into(), Type::primitive_long()),
            ]),
            Err(LubHelp::RecordWidth),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::closed_record_with_required_attributes([("foo".into(), Type::False)]),
            Type::closed_record_with_required_attributes([("foo".into(), Type::True)]),
            Ok(Type::closed_record_with_required_attributes([(
                "foo".into(),
                Type::primitive_boolean(),
            )])),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::closed_record_with_attributes([
                (
                    "foo".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
                (
                    "bar".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
            ]),
            Type::closed_record_with_attributes([
                (
                    "foo".into(),
                    AttributeType::new(Type::primitive_long(), true),
                ),
                (
                    "bar".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
            ]),
            Ok(Type::closed_record_with_attributes([
                (
                    "foo".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
                (
                    "bar".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
            ])),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::closed_record_with_attributes([
                (
                    "foo".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
                (
                    "bar".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
            ]),
            Type::closed_record_with_attributes([
                (
                    "foo".into(),
                    AttributeType::new(Type::primitive_long(), true),
                ),
                (
                    "bar".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
            ]),
            Err(LubHelp::AttributeQualifier),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::closed_record_with_attributes([
                (
                    "foo".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
                (
                    "bar".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
            ]),
            Type::closed_record_with_attributes([
                (
                    "foo".into(),
                    AttributeType::new(Type::primitive_long(), true),
                ),
                (
                    "baz".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
            ]),
            Ok(Type::open_record_with_attributes([(
                "foo".into(),
                AttributeType::new(Type::primitive_long(), false),
            )])),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::closed_record_with_attributes([
                (
                    "foo".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
                (
                    "bar".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
            ]),
            Type::closed_record_with_attributes([
                (
                    "foo".into(),
                    AttributeType::new(Type::primitive_long(), true),
                ),
                (
                    "baz".into(),
                    AttributeType::new(Type::primitive_long(), false),
                ),
            ]),
            Err(LubHelp::RecordWidth),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::open_record_with_attributes([(
                "foo".into(),
                AttributeType::new(Type::False, true),
            )]),
            Type::closed_record_with_attributes([(
                "foo".into(),
                AttributeType::new(Type::True, true),
            )]),
            Ok(Type::open_record_with_attributes([(
                "foo".into(),
                AttributeType::new(Type::primitive_boolean(), true),
            )])),
        );

        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::closed_record_with_required_attributes([("a".into(), Type::primitive_long())]),
            Type::closed_record_with_attributes([]),
            Ok(Type::open_record_with_attributes([])),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Strict,
            Type::closed_record_with_required_attributes([("a".into(), Type::primitive_long())]),
            Type::closed_record_with_attributes([]),
            Err(LubHelp::RecordWidth),
        );
    }

    fn simple_schema() -> ValidatorSchema {
        ValidatorSchema::from_schema_frag(
            json_schema::Fragment::from_json_value(serde_json::json!({ "":
            {
                "entityTypes": {
                    "foo": {},
                    "bar": {}
                },
                "actions": {}
            }}))
            .expect("Expected valid schema"),
            ActionBehavior::PermitAttributes,
            Extensions::all_available(),
        )
        .expect("Expected valid schema")
    }

    #[test]
    fn test_entity_lub() {
        assert_least_upper_bound(
            simple_schema(),
            ValidationMode::Strict,
            Type::any_entity_reference(),
            Type::any_entity_reference(),
            Ok(Type::any_entity_reference()),
        );
        assert_entity_lub(
            simple_schema(),
            ValidationMode::Permissive,
            Type::named_entity_reference_from_str("foo"),
            Type::named_entity_reference_from_str("bar"),
            &["foo", "bar"],
            &[],
        );
        assert_least_upper_bound(
            simple_schema(),
            ValidationMode::Strict,
            Type::named_entity_reference_from_str("foo"),
            Type::named_entity_reference_from_str("bar"),
            Err(LubHelp::EntityType),
        );
        assert_entity_lub(
            simple_schema(),
            ValidationMode::Strict,
            Type::named_entity_reference_from_str("foo"),
            Type::named_entity_reference_from_str("foo"),
            &["foo"],
            &[],
        );
        assert_least_upper_bound(
            simple_schema(),
            ValidationMode::Permissive,
            Type::any_entity_reference(),
            Type::named_entity_reference_from_str("foo"),
            Ok(Type::any_entity_reference()),
        );
        assert_least_upper_bound(
            simple_schema(),
            ValidationMode::Strict,
            Type::any_entity_reference(),
            Type::named_entity_reference_from_str("foo"),
            Err(LubHelp::EntityType),
        );
        assert_least_upper_bound(
            simple_schema(),
            ValidationMode::Permissive,
            Type::named_entity_reference_from_str("foo"),
            Type::primitive_boolean(),
            Err(LubHelp::None),
        );
        assert_least_upper_bound(
            simple_schema(),
            ValidationMode::Permissive,
            Type::named_entity_reference_from_str("foo"),
            Type::set(Type::any_entity_reference()),
            Err(LubHelp::None),
        );
    }

    fn action_schema() -> ValidatorSchema {
        ValidatorSchema::from_schema_frag(
            json_schema::Fragment::from_json_value(serde_json::json!({
            "": {
                "entityTypes": { "foo": {}},
                "actions": {
                    "view": { "appliesTo": {"principalTypes": [], "resourceTypes": []} },
                    "edit": { "appliesTo": {"principalTypes": [], "resourceTypes": []} },
                }
            },
            "ns": {
                "entityTypes": {},
                "actions": {
                    "move": { "appliesTo": {"principalTypes": [], "resourceTypes": []} },
                }
            }}))
            .expect("Expected valid schema"),
            ActionBehavior::PermitAttributes,
            Extensions::all_available(),
        )
        .expect("Expected valid schema")
    }

    /// Test cases with entity type Action are interesting because Action
    /// does not need to be declared in the entity type list.
    #[test]
    fn test_action_entity_lub() {
        let action_view_ty =
            Type::euid_literal(&r#"Action::"view""#.parse().unwrap(), &action_schema()).unwrap();

        assert_least_upper_bound(
            action_schema(),
            ValidationMode::Strict,
            action_view_ty.clone(),
            action_view_ty.clone(),
            Ok(action_view_ty.clone()),
        );

        // This test case seems a little odd, but the types actually only track
        // the entity type, not the id, so the `Action::"edit"` type is
        // identical to `Action::"view"`.
        assert_least_upper_bound(
            action_schema(),
            ValidationMode::Strict,
            action_view_ty.clone(),
            Type::euid_literal(&r#"Action::"edit""#.parse().unwrap(), &action_schema()).unwrap(),
            Ok(action_view_ty.clone()),
        );

        // These actions have different entity types, so we give `AnyEntity` as
        // the permissive LUB, and error in strict mode.
        assert_least_upper_bound(
            action_schema(),
            ValidationMode::Permissive,
            action_view_ty.clone(),
            Type::euid_literal(&r#"ns::Action::"move""#.parse().unwrap(), &action_schema())
                .unwrap(),
            Ok(Type::any_entity_reference()),
        );
        assert_least_upper_bound(
            action_schema(),
            ValidationMode::Strict,
            action_view_ty.clone(),
            Type::euid_literal(&r#"ns::Action::"move""#.parse().unwrap(), &action_schema())
                .unwrap(),
            Err(LubHelp::EntityType),
        );

        assert_least_upper_bound(
            action_schema(),
            ValidationMode::Permissive,
            action_view_ty.clone(),
            Type::named_entity_reference_from_str("foo"),
            Ok(Type::any_entity_reference()),
        );
        assert_least_upper_bound(
            action_schema(),
            ValidationMode::Strict,
            action_view_ty.clone(),
            Type::named_entity_reference_from_str("foo"),
            Err(LubHelp::EntityType),
        );

        assert_least_upper_bound(
            action_schema(),
            ValidationMode::Permissive,
            action_view_ty.clone(),
            Type::any_entity_reference(),
            Ok(Type::any_entity_reference()),
        );
        assert_least_upper_bound(
            action_schema(),
            ValidationMode::Strict,
            action_view_ty.clone(),
            Type::any_entity_reference(),
            Err(LubHelp::EntityType),
        );

        assert_least_upper_bound(
            action_schema(),
            ValidationMode::Permissive,
            action_view_ty.clone(),
            Type::primitive_long(),
            Err(LubHelp::None),
        );
        assert_least_upper_bound(
            action_schema(),
            ValidationMode::Permissive,
            action_view_ty,
            Type::any_record(),
            Err(LubHelp::EntityRecord),
        );
    }

    fn attr_schema() -> ValidatorSchema {
        ValidatorSchema::from_schema_frag(
            json_schema::Fragment::from_json_value(serde_json::json!(
            {"": {
                "entityTypes": {
                    "foo": {},
                    "bar": {},
                    "baz": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": {"type": "Long"},
                                "b": {"type": "String"},
                                "c": {"type": "Entity", "name": "foo"}
                            }
                        }
                    },
                    "buz": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": {"type": "Long"},
                                "b": {"type": "Long"},
                                "c": {"type": "Entity", "name": "bar"}
                            }
                        }
                    }
                },
                "actions": {}
            }}))
            .expect("Expected valid schema"),
            ActionBehavior::PermitAttributes,
            Extensions::all_available(),
        )
        .expect("Expected valid schema")
    }

    #[test]
    fn test_entity_lub_with_attributes() {
        assert_entity_lub(
            attr_schema(),
            ValidationMode::Strict,
            Type::named_entity_reference_from_str("baz"),
            Type::named_entity_reference_from_str("baz"),
            &["baz"],
            &[
                ("a", Type::primitive_long()),
                ("b", Type::primitive_string()),
                ("c", Type::named_entity_reference_from_str("foo")),
            ],
        );
        assert_entity_lub(
            attr_schema(),
            ValidationMode::Permissive,
            Type::named_entity_reference_from_str("baz"),
            Type::named_entity_reference_from_str("foo"),
            &["baz", "foo"],
            &[],
        );
        assert_least_upper_bound(
            attr_schema(),
            ValidationMode::Strict,
            Type::named_entity_reference_from_str("baz"),
            Type::named_entity_reference_from_str("foo"),
            Err(LubHelp::EntityType),
        );
        assert_entity_lub(
            attr_schema(),
            ValidationMode::Permissive,
            Type::named_entity_reference_from_str("baz"),
            Type::named_entity_reference_from_str("buz"),
            &["baz", "buz"],
            &[
                ("a", Type::primitive_long()),
                (
                    "c",
                    Type::EntityOrRecord(EntityRecordKind::Entity(EntityLUB {
                        lub_elements: ["foo".to_string(), "bar".to_string()]
                            .into_iter()
                            .map(|n| n.parse().expect("Expected valid entity type name."))
                            .collect::<BTreeSet<_>>(),
                    })),
                ),
            ],
        );
        assert_least_upper_bound(
            attr_schema(),
            ValidationMode::Strict,
            Type::named_entity_reference_from_str("baz"),
            Type::named_entity_reference_from_str("buz"),
            Err(LubHelp::EntityType),
        );
    }

    #[test]
    fn test_record_entity_lub() {
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::any_entity_reference(),
            Type::any_record(),
            Err(LubHelp::EntityRecord),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::closed_record_with_attributes(None),
            Type::any_entity_reference(),
            Err(LubHelp::EntityRecord),
        );
        assert_least_upper_bound(
            ValidatorSchema::empty(),
            ValidationMode::Permissive,
            Type::closed_record_with_required_attributes([
                ("foo".into(), Type::False),
                ("bar".into(), Type::primitive_long()),
            ]),
            Type::any_entity_reference(),
            Err(LubHelp::EntityRecord),
        );
        assert_least_upper_bound(
            attr_schema(),
            ValidationMode::Permissive,
            Type::named_entity_reference_from_str("foo"),
            Type::any_record(),
            Err(LubHelp::EntityRecord),
        );
        assert_least_upper_bound(
            attr_schema(),
            ValidationMode::Permissive,
            Type::named_entity_reference_from_str("baz"),
            Type::any_record(),
            Err(LubHelp::EntityRecord),
        );
        assert_least_upper_bound(
            attr_schema(),
            ValidationMode::Permissive,
            Type::named_entity_reference_from_str("buz"),
            Type::closed_record_with_required_attributes(vec![
                ("a".into(), Type::primitive_long()),
                ("b".into(), Type::primitive_long()),
                ("c".into(), Type::named_entity_reference_from_str("bar")),
            ]),
            Err(LubHelp::EntityRecord),
        );
    }

    // Direct test of LUB computation which causes a non-termination bug.
    #[test]
    fn record_entity_lub_non_term() {
        let schema = ValidatorSchema::from_schema_frag(
            json_schema::Fragment::from_json_value(serde_json::json!(
            {"": {
                "entityTypes": {
                    "U": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "foo": {
                                    "type": "Record",
                                    "attributes": {
                                        "foo": {
                                            "type": "Entity",
                                            "name": "U"
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "actions": {}
            }}))
            .expect("Expected valid schema"),
            ActionBehavior::PermitAttributes,
            Extensions::all_available(),
        )
        .expect("Expected valid schema");

        assert_least_upper_bound(
            schema,
            ValidationMode::Permissive,
            Type::named_entity_reference_from_str("U"),
            Type::closed_record_with_required_attributes([(
                "foo".into(),
                Type::named_entity_reference_from_str("U"),
            )]),
            Err(LubHelp::EntityRecord),
        );
    }

    fn rec_schema() -> ValidatorSchema {
        ValidatorSchema::from_schema_frag(
            json_schema::Fragment::from_json_value(serde_json::json!(
                {"": {
                    "entityTypes": {
                        "biz": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "c": {"type": "Entity", "name": "biz"}
                                }
                            }
                        },
                        "fiz": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "c": {"type": "Entity", "name": "fiz"}
                                }
                            }
                        }
                    },
                    "actions": {}
                }}
            ))
            .expect("Expected valid schema"),
            ActionBehavior::PermitAttributes,
            Extensions::all_available(),
        )
        .expect("Expected valid schema")
    }

    #[test]
    fn test_with_recursive_types() {
        assert_entity_lub(
            rec_schema(),
            ValidationMode::Strict,
            Type::named_entity_reference_from_str("biz"),
            Type::named_entity_reference_from_str("biz"),
            &["biz"],
            &[("c", Type::named_entity_reference_from_str("biz"))],
        );
        assert_entity_lub(
            rec_schema(),
            ValidationMode::Permissive,
            Type::named_entity_reference_from_str("biz"),
            Type::named_entity_reference_from_str("fiz"),
            &["biz", "fiz"],
            &[(
                "c",
                Type::EntityOrRecord(EntityRecordKind::Entity(EntityLUB {
                    lub_elements: ["biz".to_string(), "fiz".to_string()]
                        .into_iter()
                        .map(|n| n.parse().expect("Expected valid entity type name."))
                        .collect::<BTreeSet<_>>(),
                })),
            )],
        );
        assert_least_upper_bound(
            rec_schema(),
            ValidationMode::Strict,
            Type::named_entity_reference_from_str("biz"),
            Type::named_entity_reference_from_str("fiz"),
            Err(LubHelp::EntityType),
        );
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_type_display_roundtrip(ty: &Type) {
        // test that a common type declaration using this type roundtrips properly
        let type_str = format!("type T = {ty}; entity E {{ foo: T }};");
        println!("{type_str}");
        let (schema, _) =
            ValidatorSchema::from_cedarschema_str(&type_str, Extensions::all_available()).unwrap();
        assert_eq!(
            &schema
                .get_entity_type(&EntityType::from_normalized_str("E").unwrap())
                .unwrap()
                .attr("foo")
                .unwrap()
                .attr_type,
            ty,
        );
    }

    #[test]
    fn type_display_roundtrip() {
        assert_type_display_roundtrip(&Type::primitive_boolean());
        assert_type_display_roundtrip(&Type::primitive_long());
        assert_type_display_roundtrip(&Type::primitive_string());
        assert_type_display_roundtrip(&Type::set(Type::primitive_boolean()));
        assert_type_display_roundtrip(&Type::set(Type::primitive_string()));
        assert_type_display_roundtrip(&Type::set(Type::primitive_long()));
        assert_type_display_roundtrip(&Type::closed_record_with_attributes(None));
        assert_type_display_roundtrip(&Type::closed_record_with_attributes([(
            "a".into(),
            AttributeType::required_attribute(Type::primitive_boolean()),
        )]));
        assert_type_display_roundtrip(&Type::closed_record_with_attributes([
            (
                "a".into(),
                AttributeType::required_attribute(Type::primitive_boolean()),
            ),
            (
                "b".into(),
                AttributeType::new(Type::primitive_long(), false),
            ),
        ]));
    }

    #[track_caller] // report the caller's location as the location of the panic, not the location in this function
    fn assert_displays_as(ty: &Type, repr: &str) {
        assert_eq!(
            ty.to_string(),
            repr,
            "Unexpected Display output for type {:?}",
            ty
        );
    }

    // Test display for types that don't roundtrip.
    #[test]
    fn test_type_display() {
        // Entity types don't roundtrip because the Cedar format type parser
        // checks that they are defined already, so we'd need to provide a
        // complete schema. TODO: the final stage of schema parsing already does
        // this. Can we remove duplicated checks from Cedar schema parsing?
        assert_displays_as(&Type::named_entity_reference_from_str("Foo"), "Foo");
        assert_displays_as(
            &Type::named_entity_reference_from_str("Foo::Bar"),
            "Foo::Bar",
        );
        assert_displays_as(
            &Type::named_entity_reference_from_str("Foo::Bar::Baz"),
            "Foo::Bar::Baz",
        );

        // These type aren't representable in a schema.
        assert_displays_as(&Type::Never, "__cedar::internal::Never");
        assert_displays_as(&Type::True, "__cedar::internal::True");
        assert_displays_as(&Type::False, "__cedar::internal::False");
        assert_displays_as(&Type::any_set(), "Set<__cedar::internal::Any>");
        assert_displays_as(
            &Type::any_entity_reference(),
            "__cedar::internal::AnyEntity",
        );
        assert_displays_as(
            &Type::least_upper_bound(
                &ValidatorSchema::empty(),
                &Type::named_entity_reference_from_str("Foo"),
                &Type::named_entity_reference_from_str("Bar"),
                ValidationMode::Permissive,
            )
            .expect("Expected a least upper bound to exist."),
            "__cedar::internal::Union<Bar, Foo>",
        );
    }

    #[test]
    #[cfg(feature = "ipaddr")]
    fn test_extension_type_display() {
        let ipaddr = Name::parse_unqualified_name("ipaddr").expect("should be a valid identifier");
        assert_type_display_roundtrip(&Type::extension(ipaddr));
    }

    #[test]
    #[cfg(feature = "extended-schema")]
    fn test_matches_name() {
        assert!(Primitive::is_primitive("Long"))
    }
}
