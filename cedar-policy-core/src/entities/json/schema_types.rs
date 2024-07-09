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

use crate::ast::{
    BorrowedRestrictedExpr, EntityType, Expr, ExprKind, Literal, Name, PartialValue, Type, Unknown,
    Value, ValueKind,
};
use crate::extensions::{
    extension_function_lookup_errors, ExtensionFunctionLookupError, Extensions,
};
use itertools::Itertools;
use miette::Diagnostic;
use smol_str::SmolStr;
use std::collections::HashMap;
use thiserror::Error;

/// Possible types that schema-based parsing can expect for Cedar values.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SchemaType {
    /// Boolean
    Bool,
    /// Signed integer
    Long,
    /// String
    String,
    /// Set, with homogeneous elements of the specified type
    Set {
        /// Element type
        element_ty: Box<SchemaType>,
    },
    /// Type of the empty set.  (Compatible with all `Set` types)
    EmptySet,
    /// Record, with the specified attributes having the specified types
    Record {
        /// Attributes and their types
        attrs: HashMap<SmolStr, AttributeType>,
        /// Can a record with this type have attributes other than those specified in `attrs`
        open_attrs: bool,
    },
    /// Entity
    Entity {
        /// Entity type
        ty: EntityType,
    },
    /// Extension types
    Extension {
        /// Name of the extension type.
        ///
        /// Cedar has nominal typing, so two values have the same type iff
        /// they have the same typename here.
        name: Name,
    },
}

/// Attribute type structure used in [`SchemaType`]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AttributeType {
    /// Type of the attribute
    attr_type: SchemaType,
    /// Is the attribute required
    required: bool,
}

impl SchemaType {
    /// Return the `SchemaType` corresponding to the given `Type`, if possible.
    ///
    /// Some `Type`s do not contain enough information to construct a full
    /// `SchemaType`.  In those cases, this function returns `None`.
    pub fn from_ty(ty: Type) -> Option<Self> {
        match ty {
            Type::Bool => Some(SchemaType::Bool),
            Type::Long => Some(SchemaType::Long),
            Type::String => Some(SchemaType::String),
            Type::Entity { ty } => Some(SchemaType::Entity { ty }),
            Type::Set => None,
            Type::Record => None,
            Type::Extension { name } => Some(SchemaType::Extension { name }),
        }
    }

    /// Does this SchemaType match the given Type.
    /// I.e., are they compatible, in the sense that there exist some concrete
    /// values that have the given SchemaType and the given Type.
    pub fn matches(&self, ty: &Type) -> bool {
        match (self, ty) {
            (SchemaType::Bool, Type::Bool) => true,
            (SchemaType::Long, Type::Long) => true,
            (SchemaType::String, Type::String) => true,
            (SchemaType::Set { .. }, Type::Set) => true,
            (SchemaType::EmptySet, Type::Set) => true,
            (SchemaType::Record { .. }, Type::Record) => true,
            (SchemaType::Entity { ty: ty1 }, Type::Entity { ty: ty2 }) => ty1 == ty2,
            (SchemaType::Extension { name: name1 }, Type::Extension { name: name2 }) => {
                name1 == name2
            }
            _ => false,
        }
    }

    /// Does this SchemaType match the given SchemaType.
    /// I.e., are they compatible, in the sense that there exist some concrete
    /// values that have both types.
    pub fn is_consistent_with(&self, other: &SchemaType) -> bool {
        if self == other {
            true
        } else {
            use SchemaType::*;
            match (self, other) {
                (Set { .. }, EmptySet) => true,
                (EmptySet, Set { .. }) => true,
                (Set { element_ty: elty1 }, Set { element_ty: elty2 }) => {
                    elty1.is_consistent_with(elty2)
                }
                (
                    Record {
                        attrs: attrs1,
                        open_attrs: open1,
                    },
                    Record {
                        attrs: attrs2,
                        open_attrs: open2,
                    },
                ) => {
                    attrs1.iter().all(|(k, v)| {
                        match attrs2.get(k) {
                            Some(ty) => {
                                // both have the attribute, doesn't matter if
                                // one or both consider it required or optional
                                ty.attr_type.is_consistent_with(&v.attr_type)
                            }
                            None => {
                                // attrs1 has the attribute, attrs2 does not.
                                // if required in attrs1 and attrs2 is
                                // closed, incompatible.  otherwise fine
                                !v.required || *open2
                            }
                        }
                    }) && attrs2.iter().all(|(k, v)| {
                        match attrs1.get(k) {
                            Some(ty) => {
                                // both have the attribute, doesn't matter if
                                // one or both consider it required or optional
                                ty.attr_type.is_consistent_with(&v.attr_type)
                            }
                            None => {
                                // attrs2 has the attribute, attrs1 does not.
                                // if required in attrs2 and attrs1 is closed,
                                // incompatible.  otherwise fine
                                !v.required || *open1
                            }
                        }
                    })
                }
                _ => false,
            }
        }
    }

    /// Iterate over all extension function types contained in this SchemaType
    pub fn contained_ext_types(&self) -> Box<dyn Iterator<Item = &Name> + '_> {
        match self {
            Self::Extension { name } => Box::new(std::iter::once(name)),
            Self::Set { element_ty } => element_ty.contained_ext_types(),
            Self::Record { attrs, .. } => Box::new(
                attrs
                    .values()
                    .flat_map(|ty| ty.attr_type.contained_ext_types()),
            ),
            Self::Bool | Self::Long | Self::String | Self::EmptySet | Self::Entity { .. } => {
                Box::new(std::iter::empty())
            }
        }
    }
}

impl AttributeType {
    /// Constuct a new required attribute type
    pub fn required(attr_type: SchemaType) -> Self {
        Self {
            attr_type,
            required: true,
        }
    }

    /// Construct a new optional attribute type
    pub fn optional(attr_type: SchemaType) -> Self {
        Self {
            attr_type,
            required: false,
        }
    }

    /// Is the attribute required
    pub fn is_required(&self) -> bool {
        self.required
    }

    /// Get the `SchemaType` of the attribute
    pub fn schema_type(&self) -> &SchemaType {
        &self.attr_type
    }
}

impl std::fmt::Display for SchemaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool => write!(f, "bool"),
            Self::Long => write!(f, "long"),
            Self::String => write!(f, "string"),
            Self::Set { element_ty } => write!(f, "(set of {})", &element_ty),
            Self::EmptySet => write!(f, "empty-set"),
            Self::Record { attrs, open_attrs } => {
                if attrs.is_empty() && *open_attrs {
                    write!(f, "any record")
                } else if attrs.is_empty() {
                    write!(f, "empty record")
                } else {
                    if *open_attrs {
                        write!(f, "record with at least attributes: {{")?;
                    } else {
                        write!(f, "record with attributes: {{")?;
                    }
                    // sorting attributes ensures that there is a single, deterministic
                    // Display output for each `SchemaType`, which is important for
                    // tests that check equality of error messages
                    for (i, (k, v)) in attrs
                        .iter()
                        .sorted_unstable_by_key(|(k, _)| SmolStr::clone(k))
                        .enumerate()
                    {
                        write!(f, "{k:?} => {v}")?;
                        if i < (attrs.len() - 1) {
                            write!(f, ", ")?;
                        }
                    }
                    write!(f, "}}")?;
                    Ok(())
                }
            }
            Self::Entity { ty } => write!(f, "`{ty}`"),
            Self::Extension { name } => write!(f, "{}", name),
        }
    }
}

impl std::fmt::Display for AttributeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "({}) {}",
            if self.required {
                "required"
            } else {
                "optional"
            },
            &self.attr_type
        )
    }
}

/// Errors encountered when trying to compute the [`SchemaType`] of something
#[derive(Debug, Diagnostic, Error)]
pub enum GetSchemaTypeError {
    /// Encountered a heterogeneous set. Heterogeneous sets do not have a valid
    /// [`SchemaType`].
    #[error(transparent)]
    #[diagnostic(transparent)]
    HeterogeneousSet(#[from] HeterogeneousSetError),
    /// Error looking up an extension function, which may be necessary to
    /// compute the [`SchemaType`] of expressions that contain extension
    /// function calls -- not to actually call the extension function, but to
    /// get metadata about it
    #[error(transparent)]
    #[diagnostic(transparent)]
    ExtensionFunctionLookup(#[from] ExtensionFunctionLookupError),
    /// Trying to compute the [`SchemaType`], but the value or expression
    /// contains an [`Unknown`] that has insufficient type information
    /// associated in order to compute the `SchemaType`
    #[error("cannot compute type because of insufficient type information for `{unknown}`")]
    UnknownInsufficientTypeInfo {
        /// `Unknown` which has insufficient type information
        unknown: Unknown,
    },
    /// Trying to compute the [`SchemaType`] of a nontrivial residual (i.e., a
    /// residual which is not just a single `Unknown`). For now, we do not
    /// attempt to compute the [`SchemaType`] in these cases, and just return
    /// this error.
    #[error("cannot compute type of nontrivial residual `{residual}`")]
    NontrivialResidual {
        /// Nontrivial residual which we were trying to compute the
        /// [`SchemaType`] of
        residual: Box<Expr>,
    },
}

/// Found a set whose elements don't all have the same type.  This doesn't match
/// any possible schema.
#[derive(Debug, Diagnostic, Error)]
#[error("set elements have different types: {ty1} and {ty2}")]
#[diagnostic(help("for sets declared in a schema, set elements must all have the same type"))]
pub struct HeterogeneousSetError {
    /// First element type which was found
    ty1: Box<SchemaType>,
    /// Second element type which was found
    ty2: Box<SchemaType>,
}

/// Get the [`SchemaType`] of a restricted expression.
///
/// This isn't possible for general `Expr`s (without a request, full schema,
/// etc), but is possible for (concrete) restricted expressions, given the
/// information in `Extensions`.
///
/// For records, we can't know whether the attributes in the given record are
/// required or optional.
/// This function, when given a record that has keys A, B, and C, will return a
/// `SchemaType` where A, B, and C are all marked as optional attributes, but no
/// other attributes are possible.
/// That is, this assumes that all existing attributes are optional, but that no
/// other optional attributes are possible.
/// Compared to marking A, B, and C as required, this allows the returned
/// `SchemaType` to `is_consistent_with()` more types.
///
/// This function may return `GetSchemaTypeError`, but should never return
/// `NontrivialResidual`, because `RestrictedExpr`s can't contain nontrivial
/// residuals, only simple unknowns.
pub fn schematype_of_restricted_expr(
    rexpr: BorrowedRestrictedExpr<'_>,
    extensions: Extensions<'_>,
) -> Result<SchemaType, GetSchemaTypeError> {
    match rexpr.expr_kind() {
        ExprKind::Lit(lit) => Ok(schematype_of_lit(lit)),
        ExprKind::Set(elements) => {
            let element_types = elements.iter().map(|el| {
                schematype_of_restricted_expr(BorrowedRestrictedExpr::new_unchecked(el), extensions) // assuming the invariant holds for the set as a whole, it will also hold for each element
            });
            schematype_of_set_elements(element_types)
        }
        ExprKind::Record(map) => {
            Ok(SchemaType::Record {
                attrs: map.iter().map(|(k, v)| {
                    let attr_type = schematype_of_restricted_expr(
                        BorrowedRestrictedExpr::new_unchecked(v), // assuming the invariant holds for the record as a whole, it will also hold for each attribute value
                        extensions,
                    )?;
                    // we can't know if the attribute is required or optional,
                    // but marking it optional is more flexible -- allows the
                    // attribute type to `is_consistent_with()` more types
                    Ok((k.clone(), AttributeType::optional(attr_type)))
                }).collect::<Result<HashMap<_,_>, GetSchemaTypeError>>()?,
                open_attrs: false,
            })
        }
        ExprKind::ExtensionFunctionApp { fn_name, .. } => {
            let efunc = extensions.func(fn_name)?;
            Ok(efunc.return_type().cloned().ok_or_else(|| ExtensionFunctionLookupError::HasNoType(extension_function_lookup_errors::HasNoTypeError {
                name: efunc.name().clone(),
                source_loc: rexpr.source_loc().cloned(),
            }))?)
        }
        ExprKind::Unknown(u @ Unknown { type_annotation, .. }) => match type_annotation {
            None => Err(GetSchemaTypeError::UnknownInsufficientTypeInfo { unknown: u.clone() }),
            Some(ty) => match SchemaType::from_ty(ty.clone()) {
                Some(ty) => Ok(ty),
                None => Err(GetSchemaTypeError::UnknownInsufficientTypeInfo { unknown: u.clone() }),
            }
        }
        // PANIC SAFETY. Unreachable by invariant on restricted expressions
        #[allow(clippy::unreachable)]
        expr => unreachable!("internal invariant violation: BorrowedRestrictedExpr somehow contained this expr case: {expr:?}"),
    }
}

/// Get the [`SchemaType`] of a [`Value`].
///
/// Note that while getting the [`Type`] of a [`Value`] (with `value.type_of()`)
/// is O(1), getting the [`SchemaType`] requires recursively traversing the
/// whole `Value` and is thus O(n).
///
/// If the `Value` is a record, we can't know whether the attributes in the
/// given record are required or optional.
/// This function will return the `SchemaType` where all attributes that appear
/// in the `Value` are required, and no other attributes exist.
/// That is, this assumes that all existing attributes are required, and that no
/// other optional attributes are possible.
pub fn schematype_of_value(value: &Value) -> Result<SchemaType, HeterogeneousSetError> {
    schematype_of_valuekind(&value.value)
}

/// Get the [`SchemaType`] of a [`ValueKind`].
///
/// Note that while getting the [`Type`] of a [`ValueKind`] (with `value.type_of()`)
/// is O(1), getting the [`SchemaType`] requires recursively traversing the
/// whole value and is thus O(n).
///
/// If the `ValueKind` is a record, we can't know whether the attributes in the
/// given record are required or optional.
/// This function will return the `SchemaType` where all attributes that appear
/// in the `ValueKind` are required, and no other attributes exist.
/// That is, this assumes that all existing attributes are required, and that no
/// other optional attributes are possible.
pub fn schematype_of_valuekind(value: &ValueKind) -> Result<SchemaType, HeterogeneousSetError> {
    match value {
        ValueKind::Lit(lit) => Ok(schematype_of_lit(lit)),
        ValueKind::Set(set) => {
            let element_types = set.iter().map(schematype_of_value);
            schematype_of_set_elements(element_types)
        }
        ValueKind::Record(record) => Ok(SchemaType::Record {
            attrs: record
                .iter()
                .map(|(k, v)| Ok((k.clone(), AttributeType::required(schematype_of_value(v)?))))
                .collect::<Result<_, HeterogeneousSetError>>()?,
            open_attrs: false,
        }),
        ValueKind::ExtensionValue(ev) => Ok(SchemaType::Extension {
            name: ev.typename(),
        }),
    }
}

/// Get the [`SchemaType`] of a [`Literal`].
pub fn schematype_of_lit(lit: &Literal) -> SchemaType {
    match lit {
        Literal::Bool(_) => SchemaType::Bool,
        Literal::Long(_) => SchemaType::Long,
        Literal::String(_) => SchemaType::String,
        Literal::EntityUID(euid) => SchemaType::Entity {
            ty: euid.entity_type().clone(),
        },
    }
}

/// Get the [`SchemaType`] for a set whose elements have the types given by this
/// iterator.
///
/// Always returns some kind of `SchemaType::Set { .. }`, or an error.
fn schematype_of_set_elements<E: From<HeterogeneousSetError>>(
    mut element_types: impl Iterator<Item = Result<SchemaType, E>>,
) -> Result<SchemaType, E> {
    match element_types.next() {
        None => Ok(SchemaType::EmptySet),
        Some(Err(e)) => Err(e),
        Some(Ok(element_ty)) => {
            let matches_element_ty = |ty: &Result<SchemaType, E>| matches!(ty, Ok(ty) if ty.is_consistent_with(&element_ty));
            let conflicting_ty = element_types.find(|ty| !matches_element_ty(ty));
            match conflicting_ty {
                None => Ok(SchemaType::Set {
                    element_ty: Box::new(element_ty),
                }),
                Some(Ok(conflicting_ty)) => Err(HeterogeneousSetError {
                    ty1: Box::new(element_ty),
                    ty2: Box::new(conflicting_ty),
                }
                .into()),
                Some(Err(e)) => Err(e),
            }
        }
    }
}

/// Get the [`SchemaType`] of a [`PartialValue`].
///
/// For some residuals, the `SchemaType` cannot be determined without evaluating
/// (or knowing more type information about the unknowns). In those cases, this
/// function returns an appropriate `GetSchemaTypeError`.
///
/// See notes on [`schematype_of_value()`].
pub fn schematype_of_partialvalue(
    pvalue: &PartialValue,
    extensions: Extensions<'_>,
) -> Result<SchemaType, GetSchemaTypeError> {
    match pvalue {
        PartialValue::Value(v) => schematype_of_value(v).map_err(Into::into),
        PartialValue::Residual(expr) => match BorrowedRestrictedExpr::new(expr) {
            Ok(expr) => schematype_of_restricted_expr(expr, extensions),
            Err(_) => {
                // the PartialValue is a residual that isn't a valid restricted expression.
                // For now we don't try to determine the type in this case.
                Err(GetSchemaTypeError::NontrivialResidual {
                    residual: Box::new(expr.clone()),
                })
            }
        },
    }
}
