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

//! Defines structures for entity type and action id information used by the
//! validator. The contents of these structures should be populated from and schema
//! with a few transformations applied to the data. Specifically, the
//! `member_of` relation from the schema is reversed and the transitive closure is
//! computed to obtain a `descendants` relation.

use crate::{
    ast::{Entity, EntityType, EntityUID, InternalName, Name, UnreservedId},
    entities::{err::EntitiesError, Entities, TCComputation},
    extensions::Extensions,
    parser::Loc,
    transitive_closure::compute_tc,
};
use educe::Educe;
use namespace_def::EntityTypeFragment;
use nonempty::NonEmpty;
use serde::Deserialize;
#[cfg(feature = "extended-schema")]
use smol_str::SmolStr;
use smol_str::ToSmolStr;
use std::collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

#[cfg(feature = "extended-schema")]
use crate::validator::types::Primitive;

use crate::validator::{
    cedar_schema::SchemaWarning,
    json_schema,
    partition_nonempty::PartitionNonEmpty,
    types::{Attributes, EntityRecordKind, OpenTag, RequestEnv, Type},
    ValidationMode,
};

mod action;
pub use action::ValidatorActionId;
pub(crate) use action::ValidatorApplySpec;
mod entity_type;
pub use entity_type::{ValidatorEntityType, ValidatorEntityTypeKind};
mod namespace_def;
pub(crate) use namespace_def::try_jsonschema_type_into_validator_type;
pub use namespace_def::ValidatorNamespaceDef;
mod raw_name;
pub use raw_name::{ConditionalName, RawName, ReferenceType};
pub(crate) mod err;
use err::{schema_errors::*, *};

/// Configurable validator behaviors regarding actions
#[derive(Debug, Eq, PartialEq, Copy, Clone, Default)]
pub enum ActionBehavior {
    /// Action entities cannot have attributes. Attempting to declare attributes
    /// will result in a error when constructing the schema.
    ///
    /// Since we do not have a formal model for action attributes, this behavior
    /// (disabling/prohibiting them) is the default.
    #[default]
    ProhibitAttributes,
    /// Action entities may have attributes.
    PermitAttributes,
}

/// A `ValidatorSchemaFragment` consists of any number (even 0) of
/// `ValidatorNamespaceDef`s.
#[derive(Debug, Clone)]
pub struct ValidatorSchemaFragment<N, A>(Vec<ValidatorNamespaceDef<N, A>>);

impl TryInto<ValidatorSchemaFragment<ConditionalName, ConditionalName>>
    for json_schema::Fragment<RawName>
{
    type Error = SchemaError;

    fn try_into(self) -> Result<ValidatorSchemaFragment<ConditionalName, ConditionalName>> {
        ValidatorSchemaFragment::from_schema_fragment(
            self,
            ActionBehavior::default(),
            Extensions::all_available(),
        )
    }
}

impl<N, A> ValidatorSchemaFragment<N, A> {
    /// Construct a [`ValidatorSchemaFragment`] from multiple [`ValidatorNamespaceDef`]s
    pub fn from_namespaces(
        namespaces: impl IntoIterator<Item = ValidatorNamespaceDef<N, A>>,
    ) -> Self {
        Self(namespaces.into_iter().collect())
    }

    /// Get the fully-qualified [`InternalName`]s for the namespaces in this
    /// fragment.
    /// `None` indicates the empty namespace.
    pub fn namespaces(&self) -> impl Iterator<Item = Option<&InternalName>> {
        self.0.iter().map(|d| d.namespace())
    }
}

impl ValidatorSchemaFragment<ConditionalName, ConditionalName> {
    /// Construct a [`ValidatorSchemaFragment`] from a [`json_schema::Fragment`]
    pub fn from_schema_fragment(
        fragment: json_schema::Fragment<RawName>,
        action_behavior: ActionBehavior,
        extensions: &Extensions<'_>,
    ) -> Result<Self> {
        Ok(Self(
            fragment
                .0
                .into_iter()
                .map(|(fragment_ns, ns_def)| {
                    ValidatorNamespaceDef::from_namespace_definition(
                        fragment_ns.map(Into::into),
                        ns_def,
                        action_behavior,
                        extensions,
                    )
                })
                .partition_nonempty()?,
        ))
    }

    /// Convert this [`ValidatorSchemaFragment<ConditionalName, A>`] into a
    /// [`ValidatorSchemaFragment<Name, A>`] by fully-qualifying all typenames that
    /// appear anywhere in any definitions.
    ///
    /// `all_defs` needs to contain the full set of all fully-qualified typenames
    /// and actions that are defined in the schema (in all schema fragments).
    pub fn fully_qualify_type_references(
        self,
        all_defs: &AllDefs,
    ) -> Result<ValidatorSchemaFragment<InternalName, EntityType>> {
        self.0
            .into_iter()
            .map(|ns_def| ns_def.fully_qualify_type_references(all_defs))
            .partition_nonempty()
            .map(ValidatorSchemaFragment)
            .map_err(SchemaError::join_nonempty)
    }
}

/// Main Type struct that includes source location if available in the `extended-schema`
#[derive(Clone, Debug, Educe)]
#[educe(Eq, PartialEq)]
pub struct ValidatorType {
    ty: Type,
    #[cfg(feature = "extended-schema")]
    loc: Option<Loc>,
}

impl ValidatorType {
    /// New validator type
    pub fn new(ty: Type) -> Self {
        Self {
            ty,
            #[cfg(feature = "extended-schema")]
            loc: None,
        }
    }
    /// New validator type with source location
    #[cfg(feature = "extended-schema")]
    pub fn new_with_loc(ty: Type, loc: Option<Loc>) -> Self {
        Self { ty, loc }
    }
}

/// Represents common types - in extended-schema we maintain the set of common type names as well as source location data
#[cfg(feature = "extended-schema")]
#[derive(Clone, Debug, Educe)]
#[educe(Eq, PartialEq, Hash)]
pub struct ValidatorCommonType {
    /// Common type name
    pub name: SmolStr,

    /// Common type name source location if available
    #[educe(Eq(ignore))]
    pub name_loc: Option<Loc>,

    /// Common type definition source location if available
    #[educe(Eq(ignore))]
    pub type_loc: Option<Loc>,
}

#[cfg(feature = "extended-schema")]
impl ValidatorCommonType {
    /// Create new `ValidatorCommonType` based on `InternalName` and `ValidatorType`
    pub fn new(name: &InternalName, ty: ValidatorType) -> Self {
        Self {
            name: name.basename().clone().into_smolstr(),
            name_loc: name.loc().cloned(),
            type_loc: ty.loc,
        }
    }
}

/// Represents namespace - in extended-schema we maintain the set of namespace names as well as source location data
#[cfg(feature = "extended-schema")]
#[derive(Clone, Debug, Educe)]
#[educe(Eq, PartialEq, Hash)]
pub struct ValidatorNamespace {
    /// Name of namespace
    pub name: SmolStr,
    /// Namespace name source location if available
    #[educe(Eq(ignore))]
    pub name_loc: Option<Loc>,

    /// Namespace definition source location if available
    #[educe(Eq(ignore))]
    pub def_loc: Option<Loc>,
}

/// Internal representation of the schema for use by the validator.
///
/// In this representation, all common types are fully expanded, and all entity
/// type names are fully disambiguated (fully qualified).
#[derive(Clone, Debug)]
pub struct ValidatorSchema {
    /// Map from entity type names to the [`ValidatorEntityType`] object.
    entity_types: HashMap<EntityType, ValidatorEntityType>,

    /// Map from action id names to the [`ValidatorActionId`] object.
    action_ids: HashMap<EntityUID, ValidatorActionId>,

    /// For easy lookup, this is a map from action name to `Entity` object
    /// for each action in the schema. This information is contained elsewhere
    /// in the `ValidatorSchema`, but not efficient to extract -- getting the
    /// `Entity` from the `ValidatorSchema` is O(N) as of this writing, but with
    /// this cache it's O(1).
    pub(crate) actions: HashMap<EntityUID, Arc<Entity>>,

    #[cfg(feature = "extended-schema")]
    common_types: HashSet<ValidatorCommonType>,
    #[cfg(feature = "extended-schema")]
    namespaces: HashSet<ValidatorNamespace>,
}

/// Construct [`ValidatorSchema`] from a string containing a schema formatted
/// in the Cedar schema format.
impl std::str::FromStr for ValidatorSchema {
    type Err = CedarSchemaError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_cedarschema_str(s, Extensions::all_available()).map(|(schema, _)| schema)
    }
}

impl TryFrom<json_schema::NamespaceDefinition<RawName>> for ValidatorSchema {
    type Error = SchemaError;

    fn try_from(nsd: json_schema::NamespaceDefinition<RawName>) -> Result<ValidatorSchema> {
        ValidatorSchema::from_schema_fragments(
            [ValidatorSchemaFragment::from_namespaces([nsd.try_into()?])],
            Extensions::all_available(),
        )
    }
}

impl TryFrom<json_schema::Fragment<RawName>> for ValidatorSchema {
    type Error = SchemaError;

    fn try_from(frag: json_schema::Fragment<RawName>) -> Result<ValidatorSchema> {
        ValidatorSchema::from_schema_fragments([frag.try_into()?], Extensions::all_available())
    }
}

impl ValidatorSchema {
    /// Construct a new `ValidatorSchema` from a set of `ValidatorEntityType`s and `ValidatorActionId`s
    pub fn new(
        entity_types: impl IntoIterator<Item = ValidatorEntityType>,
        action_ids: impl IntoIterator<Item = ValidatorActionId>,
    ) -> Self {
        let entity_types = entity_types
            .into_iter()
            .map(|ety| (ety.name().clone(), ety))
            .collect();
        let action_ids = action_ids
            .into_iter()
            .map(|id| (id.name().clone(), id))
            .collect();
        Self::new_from_maps(
            entity_types,
            action_ids,
            #[cfg(feature = "extended-schema")]
            HashSet::new(),
            #[cfg(feature = "extended-schema")]
            HashSet::new(),
        )
    }

    /// for internal use: version of `new()` which takes the maps directly, rather than constructing them.
    ///
    /// This function constructs the `actions` cache.
    fn new_from_maps(
        entity_types: HashMap<EntityType, ValidatorEntityType>,
        action_ids: HashMap<EntityUID, ValidatorActionId>,
        #[cfg(feature = "extended-schema")] common_types: HashSet<ValidatorCommonType>,
        #[cfg(feature = "extended-schema")] namespaces: HashSet<ValidatorNamespace>,
    ) -> Self {
        let actions = Self::action_entities_iter(&action_ids)
            .map(|e| (e.uid().clone(), Arc::new(e)))
            .collect();
        Self {
            entity_types,
            action_ids,
            actions,
            #[cfg(feature = "extended-schema")]
            common_types,
            #[cfg(feature = "extended-schema")]
            namespaces,
        }
    }

    /// Returns an iter of common types in the schema
    #[cfg(feature = "extended-schema")]
    pub fn common_types(&self) -> impl Iterator<Item = &ValidatorCommonType> {
        self.common_types.iter()
    }

    /// Returns an iter of validator namespaces in the schema
    #[cfg(feature = "extended-schema")]
    pub fn namespaces(&self) -> impl Iterator<Item = &ValidatorNamespace> {
        self.namespaces.iter()
    }

    /// Returns an iterator over every entity type that can be a principal for any action in this schema
    pub fn principals(&self) -> impl Iterator<Item = &EntityType> {
        self.action_ids
            .values()
            .flat_map(ValidatorActionId::principals)
    }

    /// Returns an iterator over every entity type that can be a resource for any action in this schema
    pub fn resources(&self) -> impl Iterator<Item = &EntityType> {
        self.action_ids
            .values()
            .flat_map(ValidatorActionId::resources)
    }

    /// Returns an iterator over every entity type that can be a principal for `action` in this schema
    ///
    /// # Errors
    ///
    /// Returns [`None`] if `action` is not found in the schema
    pub fn principals_for_action(
        &self,
        action: &EntityUID,
    ) -> Option<impl Iterator<Item = &EntityType>> {
        self.action_ids
            .get(action)
            .map(ValidatorActionId::principals)
    }

    /// Returns an iterator over every entity type that can be a resource for `action` in this schema
    ///
    /// # Errors
    ///
    /// Returns [`None`] if `action` is not found in the schema
    pub fn resources_for_action(
        &self,
        action: &EntityUID,
    ) -> Option<impl Iterator<Item = &EntityType>> {
        self.action_ids
            .get(action)
            .map(ValidatorActionId::resources)
    }

    /// Returns an iterator over every valid `RequestEnv` in the schema
    pub fn unlinked_request_envs(
        &self,
        mode: ValidationMode,
    ) -> impl Iterator<Item = RequestEnv<'_>> + '_ {
        // For every action compute the cross product of the principal and
        // resource applies_to sets.
        self.action_ids()
            .flat_map(|action| {
                action.applies_to_principals().flat_map(|principal| {
                    action
                        .applies_to_resources()
                        .map(|resource| RequestEnv::DeclaredAction {
                            principal,
                            action: &action.name,
                            resource,
                            context: &action.context,
                            principal_slot: None,
                            resource_slot: None,
                        })
                })
            })
            .chain(if mode.is_partial() {
                // A partial schema might not list all actions, and may not
                // include all principal and resource types for the listed ones.
                // So we typecheck with a fully unknown request to handle these
                // missing cases.
                Some(RequestEnv::UndeclaredAction)
            } else {
                None
            })
    }

    /// Returns an iterator over all the entity types that can be a parent of `ty`
    ///
    /// # Errors
    ///
    /// Returns [`None`] if the `ty` is not found in the schema
    pub fn ancestors<'a>(
        &'a self,
        ty: &'a EntityType,
    ) -> Option<impl Iterator<Item = &'a EntityType> + 'a> {
        if self.entity_types.contains_key(ty) {
            Some(self.entity_types.values().filter_map(|ety| {
                if ety.descendants.contains(ty) {
                    Some(&ety.name)
                } else {
                    None
                }
            }))
        } else {
            None
        }
    }

    /// Returns an iterator over all the action groups defined in this schema
    pub fn action_groups(&self) -> impl Iterator<Item = &EntityUID> {
        self.action_ids.values().filter_map(|action| {
            if action.descendants.is_empty() {
                None
            } else {
                Some(&action.name)
            }
        })
    }

    /// Returns an iterator over all actions defined in this schema
    pub fn actions(&self) -> impl Iterator<Item = &EntityUID> {
        self.action_ids.keys()
    }

    /// Create a [`ValidatorSchema`] without any definitions (of entity types,
    /// common types, or actions).
    pub fn empty() -> ValidatorSchema {
        Self {
            entity_types: HashMap::new(),
            action_ids: HashMap::new(),
            actions: HashMap::new(),
            #[cfg(feature = "extended-schema")]
            common_types: HashSet::new(),
            #[cfg(feature = "extended-schema")]
            namespaces: HashSet::new(),
        }
    }

    /// Construct a [`ValidatorSchema`] from a JSON value in the appropriate
    /// shape.
    pub fn from_json_value(json: serde_json::Value, extensions: &Extensions<'_>) -> Result<Self> {
        Self::from_schema_frag(
            json_schema::Fragment::<RawName>::from_json_value(json)?,
            ActionBehavior::default(),
            extensions,
        )
    }

    /// Construct a [`ValidatorSchema`] from a string containing JSON in the
    /// appropriate shape.
    pub fn from_json_str(json: &str, extensions: &Extensions<'_>) -> Result<Self> {
        Self::from_schema_frag(
            json_schema::Fragment::<RawName>::from_json_str(json)?,
            ActionBehavior::default(),
            extensions,
        )
    }

    /// Construct a [`ValidatorSchema`] directly from a file containing JSON
    /// in the appropriate shape.
    pub fn from_json_file(file: impl std::io::Read, extensions: &Extensions<'_>) -> Result<Self> {
        Self::from_schema_frag(
            json_schema::Fragment::<RawName>::from_json_file(file)?,
            ActionBehavior::default(),
            extensions,
        )
    }

    /// Construct a [`ValidatorSchema`] directly from a file containing the
    /// Cedar schema syntax.
    pub fn from_cedarschema_file<'a>(
        r: impl std::io::Read,
        extensions: &'a Extensions<'a>,
    ) -> std::result::Result<(Self, impl Iterator<Item = SchemaWarning> + 'a), CedarSchemaError>
    {
        let (fragment, warnings) = json_schema::Fragment::from_cedarschema_file(r, extensions)?;
        let schema_and_warnings =
            Self::from_schema_frag(fragment, ActionBehavior::default(), extensions)
                .map(|schema| (schema, warnings))?;
        Ok(schema_and_warnings)
    }

    /// Construct a [`ValidatorSchema`] from a string containing the Cedar
    /// schema syntax.
    pub fn from_cedarschema_str<'a>(
        src: &str,
        extensions: &Extensions<'a>,
    ) -> std::result::Result<(Self, impl Iterator<Item = SchemaWarning> + 'a), CedarSchemaError>
    {
        let (fragment, warnings) = json_schema::Fragment::from_cedarschema_str(src, extensions)?;
        let schema_and_warnings =
            Self::from_schema_frag(fragment, ActionBehavior::default(), extensions)
                .map(|schema| (schema, warnings))?;
        Ok(schema_and_warnings)
    }

    /// Helper function to construct a [`ValidatorSchema`] from a single [`json_schema::Fragment`].
    pub(crate) fn from_schema_frag(
        schema_file: json_schema::Fragment<RawName>,
        action_behavior: ActionBehavior,
        extensions: &Extensions<'_>,
    ) -> Result<ValidatorSchema> {
        Self::from_schema_fragments(
            [ValidatorSchemaFragment::from_schema_fragment(
                schema_file,
                action_behavior,
                extensions,
            )?],
            extensions,
        )
    }

    /// Construct a [`ValidatorSchema`] from some number of [`ValidatorSchemaFragment`]s.
    pub fn from_schema_fragments(
        fragments: impl IntoIterator<Item = ValidatorSchemaFragment<ConditionalName, ConditionalName>>,
        extensions: &Extensions<'_>,
    ) -> Result<ValidatorSchema> {
        let mut fragments = fragments
            .into_iter()
            // All schemas implicitly include the following fragment as well,
            // defining the items in the `__cedar` namespace.
            .chain(std::iter::once(cedar_fragment(extensions)))
            .collect::<Vec<_>>();

        // Collect source location data for all the namespaces
        #[cfg(feature = "extended-schema")]
        let validator_namespaces = fragments
            .clone()
            .into_iter()
            .flat_map(|f| f.0.into_iter().map(|n| (n.namespace().cloned(), n.loc)))
            .filter_map(|n| match n {
                (Some(name), loc) => Some((name, loc)),
                (None, _) => None,
            })
            .map(|n| ValidatorNamespace {
                name: n.0.basename().clone().into_smolstr(),
                name_loc: n.0.loc().cloned(),
                def_loc: n.1,
            })
            .collect::<HashSet<_>>();

        // Build the sets of all entity type, common type, and action definitions
        // (fully-qualified names) in all fragments.
        let mut all_defs = AllDefs::new(|| fragments.iter());

        // Now we have enough information to do the checks required by RFC 70.
        // We do not need all _references_ to types/actions to be fully resolved yet,
        // because RFC 70 does not actually say anything about references, and can be
        // enforced knowing only about the _definitions_.
        // Furthermore, doing these checks before adding the builtin common-type aliases
        // in the empty namespace is convenient, because at this point the only
        // definitions in the empty namespace are the ones the user has put there, which
        // are thus subject to RFC 70 shadowing rules.
        all_defs.rfc_70_shadowing_checks()?;

        // Add aliases for primitive and extension typenames in the empty namespace,
        // so that they can be accessed without `__cedar`.
        // (Only add each alias if it doesn't conflict with a user declaration --
        // if it does conflict, we won't add the alias and the user needs to use
        // `__cedar` to refer to the primitive/extension type.)
        // In the future, if we support some kind of `use` keyword to make names
        // available in the empty namespace, we'd probably add that here.
        for tyname in primitive_types::<Name>()
            .map(|(id, _)| Name::unqualified_name(id))
            .chain(extensions.ext_types().cloned())
        {
            if !all_defs.is_defined_as_entity(tyname.as_ref())
                && !all_defs.is_defined_as_common(tyname.as_ref())
            {
                assert!(
                    tyname.is_unqualified(),
                    "expected all primitive and extension type names to be unqualified"
                );
                fragments.push(single_alias_in_empty_namespace(
                    tyname.basename().clone(),
                    tyname.as_ref().qualify_with(Some(&InternalName::__cedar())),
                    None, // there is no source loc associated with the builtin definitions of primitive and extension types
                ));
                all_defs.mark_as_defined_as_common_type(tyname.into());
            }
        }

        // Now use `all_defs` to resolve all [`ConditionalName`] type references
        // into fully-qualified [`InternalName`] references.
        // ("Resolve" here just means convert to fully-qualified
        // `InternalName`s; it does not mean inlining common types -- that will
        // come later.)
        // This produces an intermediate form of schema fragment,
        // `ValidatorSchemaFragment<InternalName, EntityType>`.
        let fragments: Vec<_> = fragments
            .into_iter()
            .map(|frag| frag.fully_qualify_type_references(&all_defs))
            .partition_nonempty()?;

        // Now that all references are fully-qualified, we can build the aggregate
        // maps for common types, entity types, and actions, checking that nothing
        // is defined twice. Since all of these names are already fully-qualified,
        // the same base type name may appear multiple times so long as the
        // namespaces are different.
        let mut common_types = HashMap::new();
        let mut entity_type_fragments: HashMap<EntityType, _> = HashMap::new();
        let mut action_fragments = HashMap::new();
        for ns_def in fragments.into_iter().flat_map(|f| f.0.into_iter()) {
            for (name, ty) in ns_def.common_types.defs {
                match common_types.entry(name) {
                    Entry::Vacant(v) => v.insert(ty),
                    Entry::Occupied(o) => {
                        return Err(DuplicateCommonTypeError {
                            ty: o.key().clone(),
                        }
                        .into());
                    }
                };
            }

            for (name, entity_type) in ns_def.entity_types.defs {
                match entity_type_fragments.entry(name) {
                    Entry::Vacant(v) => v.insert(entity_type),
                    Entry::Occupied(o) => {
                        return Err(DuplicateEntityTypeError {
                            ty: o.key().clone(),
                        }
                        .into())
                    }
                };
            }

            for (action_euid, action) in ns_def.actions.actions {
                match action_fragments.entry(action_euid) {
                    Entry::Vacant(v) => v.insert(action),
                    Entry::Occupied(o) => {
                        return Err(DuplicateActionError(o.key().to_smolstr()).into())
                    }
                };
            }
        }

        let resolver = CommonTypeResolver::new(&common_types);
        let common_types: HashMap<&InternalName, ValidatorType> = resolver.resolve(extensions)?;

        // Invert the `parents` relation defined by entities and action so far
        // to get a `children` relation.
        let mut entity_children: HashMap<EntityType, HashSet<EntityType>> = HashMap::new();
        for (name, entity_type) in entity_type_fragments.iter() {
            for parent in entity_type.parents() {
                entity_children
                    .entry(internal_name_to_entity_type(parent.clone())?)
                    .or_default()
                    .insert(name.clone());
            }
        }
        let mut entity_types = entity_type_fragments
            .into_iter()
            .map(|(name, entity_type)| -> Result<_> {
                // Keys of the `entity_children` map were values of an
                // `memberOfTypes` list, so they might not have been declared in
                // their fragment.  By removing entries from `entity_children`
                // where the key is a declared name, we will be left with a map
                // where the keys are undeclared. These keys are used to report
                // an error when undeclared entity types are referenced inside a
                // `memberOfTypes` list. The error is reported alongside the
                // error for any other undeclared entity types by
                // `check_for_undeclared`.
                let descendants = entity_children.remove(&name).unwrap_or_default();

                match entity_type {
                    EntityTypeFragment::Enum(choices) => Ok((
                        name.clone(),
                        ValidatorEntityType::new_enum(
                            name.clone(),
                            descendants,
                            choices,
                            name.loc().cloned(),
                        ),
                    )),
                    EntityTypeFragment::Standard {
                        attributes,
                        parents: _,
                        tags,
                    } => {
                        let (attributes, open_attributes) = {
                            let attr_loc = attributes.0.loc().cloned();
                            let unresolved = try_jsonschema_type_into_validator_type(
                                attributes.0,
                                extensions,
                                attr_loc,
                            )?;
                            Self::record_attributes_or_none(
                                unresolved.resolve_common_type_refs(&common_types)?,
                            )
                            .ok_or_else(|| {
                                ContextOrShapeNotRecordError {
                                    ctx_or_shape: ContextOrShape::EntityTypeShape(name.clone()),
                                }
                            })?
                        };
                        let tags = tags
                            .map(|tags| {
                                let tags_loc = tags.loc().cloned();
                                try_jsonschema_type_into_validator_type(tags, extensions, tags_loc)
                            })
                            .transpose()?
                            .map(|unresolved| unresolved.resolve_common_type_refs(&common_types))
                            .transpose()?;

                        Ok((
                            name.with_loc(name.loc()),
                            ValidatorEntityType::new_standard(
                                name.clone(),
                                descendants,
                                attributes,
                                open_attributes,
                                tags.map(|t| t.ty),
                                name.loc().cloned(),
                            ),
                        ))
                    }
                }
            })
            .partition_nonempty()?;

        let mut action_children = HashMap::new();
        for (euid, action) in action_fragments.iter() {
            for parent in action.parents.iter() {
                action_children
                    .entry(parent.clone().try_into()?)
                    .or_insert_with(HashSet::new)
                    .insert(euid.clone());
            }
        }
        let mut action_ids = action_fragments
            .into_iter()
            .map(|(name, action)| -> Result<_> {
                let descendants = action_children.remove(&name).unwrap_or_default();
                let (context, open_context_attributes) = {
                    let context_loc = action.context.loc().cloned();
                    let unresolved = try_jsonschema_type_into_validator_type(
                        action.context,
                        extensions,
                        context_loc,
                    )?;
                    Self::record_attributes_or_none(
                        unresolved.resolve_common_type_refs(&common_types)?,
                    )
                    .ok_or_else(|| ContextOrShapeNotRecordError {
                        ctx_or_shape: ContextOrShape::ActionContext(name.clone()),
                    })?
                };
                Ok((
                    name.clone(),
                    ValidatorActionId {
                        name,
                        applies_to: action.applies_to,
                        descendants,
                        context: Type::record_with_attributes(context, open_context_attributes),
                        attribute_types: action.attribute_types,
                        attributes: action.attributes,
                        loc: action.loc,
                    },
                ))
            })
            .partition_nonempty()?;

        // We constructed entity types and actions with child maps, but we need
        // transitively closed descendants.
        compute_tc(&mut entity_types, false)
            .map_err(|e| EntityTypeTransitiveClosureError::from(Box::new(e)))?;
        // Pass `true` here so that we also check that the action hierarchy does
        // not contain cycles.
        compute_tc(&mut action_ids, true)?;
        #[cfg(feature = "extended-schema")]
        let common_type_validators = common_types
            .clone()
            .into_iter()
            .filter(|ct| {
                // Only collect common types that are not primitives and have location data
                let ct_name = ct.0.clone();
                ct_name.loc().is_some() && !Primitive::is_primitive(ct_name.basename().as_ref())
            })
            .map(|ct| ValidatorCommonType::new(ct.0, ct.1))
            .collect();
        // Return with an error if there is an undeclared entity or action
        // referenced in any fragment. `{entity,action}_children` are provided
        // for the `undeclared_parent_{entities,actions}` arguments because
        // removed keys from these maps as we encountered declarations for the
        // entity types or actions. Any keys left in the map are therefore
        // undeclared.
        Self::check_for_undeclared(
            &entity_types,
            entity_children.into_keys(),
            &action_ids,
            action_children.into_keys(),
            common_types.into_values(),
        )?;
        #[cfg(not(feature = "extended-schema"))]
        let validator_schema = Ok(ValidatorSchema::new_from_maps(entity_types, action_ids));
        #[cfg(feature = "extended-schema")]
        let validator_schema = Ok(ValidatorSchema::new_from_maps(
            entity_types,
            action_ids,
            #[cfg(feature = "extended-schema")]
            common_type_validators,
            #[cfg(feature = "extended-schema")]
            validator_namespaces,
        ));
        validator_schema
    }

    /// Check that all entity types and actions referenced in the schema are in
    /// the set of declared entity type or action names.
    /// This function assumes that all entity types are fully qualified, which
    /// is indicated by the use of the [`EntityType`] and [`EntityUID`] types.
    fn check_for_undeclared(
        entity_types: &HashMap<EntityType, ValidatorEntityType>,
        undeclared_parent_entities: impl IntoIterator<Item = EntityType>,
        action_ids: &HashMap<EntityUID, ValidatorActionId>,
        undeclared_parent_actions: impl IntoIterator<Item = EntityUID>,
        common_types: impl IntoIterator<Item = ValidatorType>,
    ) -> Result<()> {
        // When we constructed `entity_types`, we removed entity types from  the
        // `entity_children` map as we encountered a declaration for that type.
        // Any entity types left in the map are therefore undeclared. These are
        // any undeclared entity types which appeared in a `memberOf` list.
        let mut undeclared_e = undeclared_parent_entities
            .into_iter()
            .collect::<BTreeSet<EntityType>>();
        // Looking at entity types, we need to check entity references in
        // attribute types. We already know that all elements of the
        // `descendants` list were declared because the list is a result of
        // inverting the `memberOf` relationship which mapped declared entity
        // types to their parent entity types.
        for entity_type in entity_types.values() {
            for (_, attr_typ) in entity_type.attributes().iter() {
                Self::check_undeclared_in_type(
                    &attr_typ.attr_type,
                    entity_types,
                    &mut undeclared_e,
                );
            }
        }

        // Check for undeclared entity types within common types.
        for common_type in common_types {
            Self::check_undeclared_in_type(&common_type.ty, entity_types, &mut undeclared_e);
        }

        // Undeclared actions in a `memberOf` list.
        let undeclared_a = undeclared_parent_actions.into_iter();
        // For actions, we check entity references in the context attribute
        // types and `appliesTo` lists. See the `entity_types` loop for why the
        // `descendants` list is not checked.
        for action in action_ids.values() {
            Self::check_undeclared_in_type(&action.context, entity_types, &mut undeclared_e);

            for p_entity in action.applies_to_principals() {
                if !entity_types.contains_key(p_entity) {
                    undeclared_e.insert(p_entity.clone());
                }
            }

            for r_entity in action.applies_to_resources() {
                if !entity_types.contains_key(r_entity) {
                    undeclared_e.insert(r_entity.clone());
                }
            }
        }
        if let Some(types) = NonEmpty::collect(undeclared_e) {
            return Err(UndeclaredEntityTypesError { types }.into());
        }
        if let Some(euids) = NonEmpty::collect(undeclared_a) {
            // This should not happen, because undeclared actions should be caught
            // earlier, when we are resolving action names into fully-qualified [`Name`]s.
            return Err(ActionInvariantViolationError { euids }.into());
        }

        Ok(())
    }

    fn record_attributes_or_none(ty: ValidatorType) -> Option<(Attributes, OpenTag)> {
        match ty.ty {
            Type::EntityOrRecord(EntityRecordKind::Record {
                attrs,
                open_attributes,
            }) => Some((attrs, open_attributes)),
            _ => None,
        }
    }

    /// Check that all entity types appearing inside a type are in the set of
    /// declared entity types, adding any undeclared entity types to the
    /// `undeclared_types` set.
    fn check_undeclared_in_type(
        ty: &Type,
        entity_types: &HashMap<EntityType, ValidatorEntityType>,
        undeclared_types: &mut BTreeSet<EntityType>,
    ) {
        match ty {
            Type::EntityOrRecord(EntityRecordKind::Entity(lub)) => {
                for name in lub.iter() {
                    if !entity_types.contains_key(name) {
                        undeclared_types.insert(name.clone());
                    }
                }
            }

            Type::EntityOrRecord(EntityRecordKind::Record { attrs, .. }) => {
                for (_, attr_ty) in attrs.iter() {
                    Self::check_undeclared_in_type(
                        &attr_ty.attr_type,
                        entity_types,
                        undeclared_types,
                    );
                }
            }

            Type::Set {
                element_type: Some(element_type),
            } => Self::check_undeclared_in_type(element_type, entity_types, undeclared_types),

            _ => (),
        }
    }

    /// Lookup the [`ValidatorActionId`] object in the schema with the given name.
    pub fn get_action_id(&self, action_id: &EntityUID) -> Option<&ValidatorActionId> {
        self.action_ids.get(action_id)
    }

    /// Lookup the [`ValidatorEntityType`] object in the schema with the given name.
    pub fn get_entity_type<'a>(
        &'a self,
        entity_type_id: &EntityType,
    ) -> Option<&'a ValidatorEntityType> {
        self.entity_types.get(entity_type_id)
    }

    /// Return true when the `action_id` corresponds to a valid action.
    pub(crate) fn is_known_action_id(&self, action_id: &EntityUID) -> bool {
        self.action_ids.contains_key(action_id)
    }

    /// Return true when the `entity_type` corresponds to a valid entity type.
    pub(crate) fn is_known_entity_type(&self, entity_type: &EntityType) -> bool {
        entity_type.is_action() || self.entity_types.contains_key(entity_type)
    }

    /// Return true when `euid` has an entity type declared by the schema.
    pub(crate) fn euid_has_known_entity_type(&self, euid: &EntityUID) -> bool {
        self.is_known_entity_type(euid.entity_type())
    }

    /// An iterator over the `ValidatorActionId`s in the schema.
    pub fn action_ids(&self) -> impl Iterator<Item = &ValidatorActionId> {
        self.action_ids.values()
    }

    /// An iterator over the entity type names in the schema.
    pub fn entity_type_names(&self) -> impl Iterator<Item = &EntityType> {
        self.entity_types.keys()
    }

    /// An iterator over the `ValidatorEntityType`s in the schema.
    pub fn entity_types(&self) -> impl Iterator<Item = &ValidatorEntityType> {
        self.entity_types.values()
    }

    /// Get all entity types in the schema where an `{entity0} in {entity}` can
    /// evaluate to `true` for some `entity0` with that entity type. This
    /// includes all entity types that are descendants of the type of `entity`
    /// according  to the schema, and the type of `entity` itself because
    /// `entity in entity` evaluates to `true`.
    pub(crate) fn get_entity_types_in<'a>(&'a self, entity: &'a EntityUID) -> Vec<&'a EntityType> {
        let mut descendants = self
            .get_entity_type(entity.entity_type())
            .map(|v_ety| v_ety.descendants.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        descendants.push(entity.entity_type());
        descendants
    }

    /// Get all entity types in the schema where an `{entity0} in {euids}` can
    /// evaluate to `true` for some `entity0` with that entity type. See comment
    /// on `get_entity_types_in`.
    pub(crate) fn get_entity_types_in_set<'a>(
        &'a self,
        euids: impl IntoIterator<Item = &'a EntityUID>,
    ) -> impl Iterator<Item = &'a EntityType> {
        euids.into_iter().flat_map(|e| self.get_entity_types_in(e))
    }

    /// Get all action entities in the schema where `action in euids` evaluates
    /// to `true`. This includes all actions which are descendants of some
    /// element of `euids`, and all elements of `euids`.
    pub(crate) fn get_actions_in_set<'a>(
        &'a self,
        euids: impl IntoIterator<Item = &'a EntityUID> + 'a,
    ) -> Option<Vec<&'a EntityUID>> {
        euids
            .into_iter()
            .map(|e| {
                self.get_action_id(e).map(|action| {
                    action
                        .descendants
                        .iter()
                        .chain(std::iter::once(&action.name))
                })
            })
            .collect::<Option<Vec<_>>>()
            .map(|v| v.into_iter().flatten().collect::<Vec<_>>())
    }

    /// Get the `Type` of context expected for the given `action`.
    /// This always returns a closed record type.
    ///
    /// Returns `None` if the action is not in the schema.
    pub fn context_type(&self, action: &EntityUID) -> Option<&Type> {
        // INVARIANT: `ValidatorActionId::context_type` always returns a closed
        // record type
        self.get_action_id(action)
            .map(ValidatorActionId::context_type)
    }

    /// Invert the action hierarchy to get the ancestor relation expected for
    /// the `Entity` datatype instead of descendants as stored by the schema.
    pub(crate) fn action_entities_iter(
        action_ids: &HashMap<EntityUID, ValidatorActionId>,
    ) -> impl Iterator<Item = crate::ast::Entity> + '_ {
        // We could store the un-inverted `memberOf` relation for each action,
        // but I [john-h-kastner-aws] judge that the current implementation is
        // actually less error prone, as it minimizes the threading of data
        // structures through some complicated bits of schema construction code,
        // and avoids computing the TC twice.
        let mut action_ancestors: HashMap<&EntityUID, HashSet<EntityUID>> = HashMap::new();
        for (action_euid, action_def) in action_ids {
            for descendant in &action_def.descendants {
                action_ancestors
                    .entry(descendant)
                    .or_default()
                    .insert(action_euid.clone());
            }
        }
        action_ids.iter().map(move |(action_id, action)| {
            Entity::new_with_attr_partial_value(
                action_id.clone(),
                action.attributes.clone(),
                HashSet::new(),
                action_ancestors.remove(action_id).unwrap_or_default(),
                [], // actions cannot have entity tags
            )
        })
    }

    /// Construct an `Entity` object for each action in the schema
    pub fn action_entities(&self) -> std::result::Result<Entities, EntitiesError> {
        let extensions = Extensions::all_available();
        Entities::from_entities(
            self.actions.values().map(|entity| entity.as_ref().clone()),
            None::<&crate::entities::NoEntitiesSchema>, // we don't want to tell `Entities::from_entities()` to add the schema's action entities, that would infinitely recurse
            TCComputation::AssumeAlreadyComputed,
            extensions,
        )
    }
}

/// Used to write a schema implicitly overriding the default handling of action
/// groups.
#[derive(Debug, Clone, Deserialize)]
#[serde(bound(deserialize = "N: Deserialize<'de> + From<RawName>"))]
#[serde(transparent)]
pub(crate) struct NamespaceDefinitionWithActionAttributes<N>(
    pub(crate) json_schema::NamespaceDefinition<N>,
);

impl TryInto<ValidatorSchema> for NamespaceDefinitionWithActionAttributes<RawName> {
    type Error = SchemaError;

    fn try_into(self) -> Result<ValidatorSchema> {
        ValidatorSchema::from_schema_fragments(
            [ValidatorSchemaFragment::from_namespaces([
                ValidatorNamespaceDef::from_namespace_definition(
                    None,
                    self.0,
                    crate::validator::ActionBehavior::PermitAttributes,
                    Extensions::all_available(),
                )?,
            ])],
            Extensions::all_available(),
        )
    }
}

/// Get a [`ValidatorSchemaFragment`] describing the items that implicitly exist
/// in the `__cedar` namespace.
fn cedar_fragment(
    extensions: &Extensions<'_>,
) -> ValidatorSchemaFragment<ConditionalName, ConditionalName> {
    // PANIC SAFETY: these are valid `Id`s
    #[allow(clippy::unwrap_used)]
    let mut common_types = HashMap::from_iter(primitive_types());
    for ext_type in extensions.ext_types() {
        assert!(
            ext_type.is_unqualified(),
            "expected extension type names to be unqualified"
        );
        let ext_type = ext_type.basename().clone();
        common_types.insert(
            ext_type.clone(),
            json_schema::Type::Type {
                ty: json_schema::TypeVariant::Extension { name: ext_type },
                loc: None,
            },
        );
    }

    // PANIC SAFETY: this is a valid schema fragment. This code is tested by every test that constructs `ValidatorSchema`, and this fragment is the same every time, modulo active extensions.
    #[allow(clippy::unwrap_used)]
    ValidatorSchemaFragment(vec![ValidatorNamespaceDef::from_common_type_defs(
        Some(InternalName::__cedar()),
        common_types,
    )
    .unwrap()])
}

/// Get a [`ValidatorSchemaFragment`] containing just one common-type definition,
/// defining the unqualified name `id` in the empty namespace as an alias for
/// the fully-qualified name `def`. (This will eventually cause an error if
/// `def` is not defined somewhere.)
///
/// `def` is allowed to be [`InternalName`] because it's totally valid to define
/// `type Foo = __cedar::String` etc.
fn single_alias_in_empty_namespace(
    id: UnreservedId,
    def: InternalName,
    loc: Option<Loc>,
) -> ValidatorSchemaFragment<ConditionalName, ConditionalName> {
    ValidatorSchemaFragment(vec![ValidatorNamespaceDef::from_common_type_def(
        None,
        (
            id,
            json_schema::Type::Type {
                ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: ConditionalName::unconditional(def, ReferenceType::CommonOrEntity),
                },
                loc,
            },
        ),
    )])
}

/// Get the names of all primitive types, as unqualified `UnreservedId`s,
/// paired with the primitive [`json_schema::Type`]s they represent
fn primitive_types<N>() -> impl Iterator<Item = (UnreservedId, json_schema::Type<N>)> {
    // PANIC SAFETY: these are valid `UnreservedId`s
    #[allow(clippy::unwrap_used)]
    [
        (
            UnreservedId::from_str("Bool").unwrap(),
            json_schema::Type::Type {
                ty: json_schema::TypeVariant::Boolean,
                loc: None,
            },
        ),
        (
            UnreservedId::from_str("Long").unwrap(),
            json_schema::Type::Type {
                ty: json_schema::TypeVariant::Long,
                loc: None,
            },
        ),
        (
            UnreservedId::from_str("String").unwrap(),
            json_schema::Type::Type {
                ty: json_schema::TypeVariant::String,
                loc: None,
            },
        ),
    ]
    .into_iter()
}

/// Convert an [`InternalName`] to an [`EntityType`].
/// If this fails (because the name contained `__cedar`), this throws a
/// `ReservedNameError`. As of this writing, there are no valid entity types
/// containing `__cedar`.
fn internal_name_to_entity_type(
    name: InternalName,
) -> std::result::Result<EntityType, crate::ast::ReservedNameError> {
    Name::try_from(name).map(Into::into)
}

/// Holds the sets of all entity type, common type, and action definitions
/// (fully-qualified names) in all fragments.
#[derive(Debug)]
pub struct AllDefs {
    /// All entity type definitions, in all fragments, as fully-qualified names.
    entity_defs: HashSet<InternalName>,
    /// All common type definitions, in all fragments, as fully-qualified names.
    common_defs: HashSet<InternalName>,
    /// All action definitions, in all fragments, with fully-qualified typenames.
    action_defs: HashSet<EntityUID>,
}

impl AllDefs {
    /// Build the sets of all entity type, common type, and action definitions
    /// (fully-qualified names) in all fragments.
    pub fn new<'a, N: 'a, A: 'a, I>(fragments: impl Fn() -> I) -> Self
    where
        I: Iterator<Item = &'a ValidatorSchemaFragment<N, A>>,
    {
        Self {
            entity_defs: fragments()
                .flat_map(|f| f.0.iter())
                .flat_map(|ns_def| ns_def.all_declared_entity_type_names().cloned())
                .collect(),
            common_defs: fragments()
                .flat_map(|f| f.0.iter())
                .flat_map(|ns_def| ns_def.all_declared_common_type_names().cloned())
                .collect(),
            action_defs: fragments()
                .flat_map(|f| f.0.iter())
                .flat_map(|ns_def| ns_def.all_declared_action_names().cloned())
                .collect(),
        }
    }

    /// Build an [`AllDefs`] assuming that the given fragment is the only
    /// fragment that exists.
    /// Any names referring to definitions in other fragments will not resolve
    /// properly.
    pub fn single_fragment<N, A>(fragment: &ValidatorSchemaFragment<N, A>) -> Self {
        Self::new(|| std::iter::once(fragment))
    }

    /// Is the given (fully-qualified) [`InternalName`] defined as an entity
    /// type in any fragment?
    pub fn is_defined_as_entity(&self, name: &InternalName) -> bool {
        self.entity_defs.contains(name)
    }

    /// Is the given (fully-qualified) [`InternalName`] defined as a common type
    /// in any fragment?
    pub fn is_defined_as_common(&self, name: &InternalName) -> bool {
        self.common_defs.contains(name)
    }

    /// Is the given (fully-qualified) [`EntityUID`] defined as an action in any
    /// fragment?
    pub fn is_defined_as_action(&self, euid: &EntityUID) -> bool {
        self.action_defs.contains(euid)
    }

    /// Mark the given [`InternalName`] as defined as a common type
    pub fn mark_as_defined_as_common_type(&mut self, name: InternalName) {
        self.common_defs.insert(name);
    }

    /// Return an error if the definitions in this [`AllDefs`] violate the
    /// restrictions specified in [RFC 70].
    ///
    /// RFC 70 disallows definitions of entity types, common types, and actions
    /// that would shadow definitions of other entity types, common types, or
    /// actions in the empty namespace.
    ///
    /// [RFC 70]: https://github.com/cedar-policy/rfcs/blob/main/text/0070-disallow-empty-namespace-shadowing.md
    pub fn rfc_70_shadowing_checks(&self) -> Result<()> {
        for unqualified_name in self
            .entity_and_common_names()
            .filter(|name| name.is_unqualified())
        {
            // `unqualified_name` is a definition in the empty namespace
            if let Some(name) = self.entity_and_common_names().find(|name| {
                !name.is_unqualified() // RFC 70 specifies that shadowing an entity typename with a common typename is OK, including in the empty namespace
                && !name.is_reserved() // do not throw an error if the shadowing name is something like `__cedar::String` "shadowing" an empty-namespace declaration of `String`
                && name.basename() == unqualified_name.basename()
            }) {
                return Err(TypeShadowingError {
                    shadowed_def: unqualified_name.clone(),
                    shadowing_def: name.clone(),
                }
                .into());
            }
        }
        for unqualified_action in self
            .action_defs
            .iter()
            .filter(|euid| euid.entity_type().as_ref().is_unqualified())
        {
            // `unqualified_action` is a definition in the empty namespace
            if let Some(action) = self.action_defs.iter().find(|euid| {
                !euid.entity_type().as_ref().is_unqualified() // do not throw an error for an action "shadowing" itself
                // we do not need to check that the basenames are the same, because we assume they are both `Action`
                && euid.eid() == unqualified_action.eid()
            }) {
                return Err(ActionShadowingError {
                    shadowed_def: unqualified_action.clone(),
                    shadowing_def: action.clone(),
                }
                .into());
            }
        }
        Ok(())
    }

    /// Iterate over all (fully-qualified) entity and common-type names defined
    /// in the [`AllDefs`].
    fn entity_and_common_names(&self) -> impl Iterator<Item = &InternalName> {
        self.entity_defs.iter().chain(self.common_defs.iter())
    }
}

#[cfg(test)]
impl AllDefs {
    /// Build an [`AllDefs`] that assumes the given fully-qualified
    /// [`InternalName`]s are defined (by the user) as entity types, and there
    /// are no defined common types or actions.
    pub(crate) fn from_entity_defs(names: impl IntoIterator<Item = InternalName>) -> Self {
        Self {
            entity_defs: names.into_iter().collect(),
            common_defs: HashSet::new(),
            action_defs: HashSet::new(),
        }
    }
}

/// A common type reference resolver.
/// This resolver is designed to operate on fully-qualified references.
/// It facilitates inlining the definitions of common types.
///
/// INVARIANT: There should be no dangling references. That is, all common-type
/// references that occur in the [`json_schema::Type`]s in `defs`, should be to
/// common types that appear as keys in `defs`.
/// This invariant is upheld by callers because the process of converting
/// references to fully-qualified ensures that the targets exist (else, it
/// throws [`TypeNotDefinedError`]).
#[derive(Debug)]
struct CommonTypeResolver<'a> {
    /// Definition of each common type.
    ///
    /// Definitions (values in the map) may refer to other common-type names,
    /// but not in a way that causes a cycle.
    ///
    /// In this map, names are already fully-qualified, both in common-type
    /// definitions (keys in the map) and in common-type references appearing in
    /// [`json_schema::Type`]s (values in the map).
    defs: &'a HashMap<InternalName, json_schema::Type<InternalName>>,
    /// The dependency graph among common type names.
    /// The graph contains a vertex for each [`InternalName`], and
    /// `graph.get(u)` gives the set of vertices `v` for which `(u,v)` is a
    /// directed edge in the graph.
    ///
    /// In this map, names are already fully-qualified, both in keys and values
    /// in the map.
    graph: HashMap<&'a InternalName, HashSet<&'a InternalName>>,
}

impl<'a> CommonTypeResolver<'a> {
    /// Construct the resolver.
    /// Note that this requires that all common-type references are already
    /// fully qualified, because it uses [`InternalName`] and not [`RawName`].
    ///
    /// INVARIANT: There should be no dangling references. That is, all common-type
    /// references that occur in the [`json_schema::Type`]s in `defs`, should be
    /// to common types that appear as keys in `defs`.
    /// This invariant is upheld by callers because the process of converting
    /// references to fully-qualified ensures that the targets exist (else, it
    /// throws [`TypeNotDefinedError`]).
    fn new(defs: &'a HashMap<InternalName, json_schema::Type<InternalName>>) -> Self {
        let mut graph = HashMap::new();
        for (name, ty) in defs {
            graph.insert(name, HashSet::from_iter(ty.common_type_references()));
        }
        Self { defs, graph }
    }

    /// Perform topological sort on the dependency graph
    ///
    /// Let A -> B denote the RHS of type `A` refers to type `B` (i.e., `A`
    /// depends on `B`)
    ///
    /// `topo_sort(A -> B -> C)` produces [C, B, A]
    ///
    /// If there is a cycle, a type name involving in this cycle is the error
    ///
    /// It implements a variant of Kahn's algorithm
    fn topo_sort(&self) -> std::result::Result<Vec<&'a InternalName>, InternalName> {
        // The in-degree map
        // Note that the keys of this map may be a superset of all common type
        // names
        let mut indegrees: HashMap<&InternalName, usize> = HashMap::new();
        for (ty_name, deps) in self.graph.iter() {
            // Ensure that declared common types have values in `indegrees`
            indegrees.entry(ty_name).or_insert(0);
            for dep in deps {
                match indegrees.entry(dep) {
                    std::collections::hash_map::Entry::Occupied(mut o) => {
                        o.insert(o.get() + 1);
                    }
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(1);
                    }
                }
            }
        }

        // The set that contains type names with zero incoming edges
        let mut work_set: HashSet<&'a InternalName> = HashSet::new();
        let mut res: Vec<&'a InternalName> = Vec::new();

        // Find all type names with zero incoming edges
        for (name, degree) in indegrees.iter() {
            let name = *name;
            if *degree == 0 {
                work_set.insert(name);
                // The result only contains *declared* type names
                if self.graph.contains_key(name) {
                    res.push(name);
                }
            }
        }

        // Pop a node
        while let Some(name) = work_set.iter().next().copied() {
            work_set.remove(name);
            if let Some(deps) = self.graph.get(name) {
                for dep in deps {
                    if let Some(degree) = indegrees.get_mut(dep) {
                        // There will not be any underflows here because
                        // in order for the in-degree to underflow, `dep`'s
                        // in-degree must be 0 at this point
                        // The only possibility where a node's in-degree
                        // becomes 0 is through the subtraction below, which
                        // means it has been visited and hence has 0 in-degrees
                        // In other words, all its in-coming edges have been
                        // "removed" and hence contradicts with the fact that
                        // one of them is being "removed"
                        *degree -= 1;
                        if *degree == 0 {
                            work_set.insert(dep);
                            if self.graph.contains_key(dep) {
                                res.push(dep);
                            }
                        }
                    }
                }
            }
        }

        // The set of nodes that have not been added to the result
        // i.e., there are still in-coming edges and hence exists a cycle
        let mut set: HashSet<&InternalName> = HashSet::from_iter(self.graph.keys().copied());
        for name in res.iter() {
            set.remove(name);
        }

        if let Some(cycle) = set.into_iter().next() {
            Err(cycle.clone())
        } else {
            // We need to reverse the result because, e.g.,
            // `res` is now [A,B,C] for A -> B -> C because no one depends on A
            res.reverse();
            Ok(res)
        }
    }

    // Substitute common type references in `ty` according to `resolve_table`.
    // Resolved types will still have the source loc of `ty`, unless `ty` is
    // exactly a common type reference, in which case they will have the source
    // loc of the definition of that reference.
    fn resolve_type(
        resolve_table: &HashMap<&InternalName, json_schema::Type<InternalName>>,
        ty: json_schema::Type<InternalName>,
    ) -> Result<json_schema::Type<InternalName>> {
        match ty {
            json_schema::Type::CommonTypeRef { type_name, .. } => resolve_table
                .get(&type_name)
                .ok_or_else(|| CommonTypeInvariantViolationError { name: type_name }.into())
                .cloned(),
            json_schema::Type::Type {
                ty: json_schema::TypeVariant::EntityOrCommon { type_name },
                loc,
            } => match resolve_table.get(&type_name) {
                Some(def) => Ok(def.clone().with_loc(loc)),

                None => Ok(json_schema::Type::Type {
                    ty: json_schema::TypeVariant::Entity { name: type_name },
                    loc,
                }),
            },
            json_schema::Type::Type {
                ty: json_schema::TypeVariant::Set { element },
                loc,
            } => Ok(json_schema::Type::Type {
                ty: json_schema::TypeVariant::Set {
                    element: Box::new(Self::resolve_type(resolve_table, *element)?),
                },
                loc,
            }),
            json_schema::Type::Type {
                ty:
                    json_schema::TypeVariant::Record(json_schema::RecordType {
                        attributes,
                        additional_attributes,
                    }),
                loc,
            } => Ok(json_schema::Type::Type {
                ty: json_schema::TypeVariant::Record(json_schema::RecordType {
                    attributes: BTreeMap::from_iter(
                        attributes
                            .into_iter()
                            .map(|(attr, attr_ty)| -> Result<_> {
                                Ok((
                                    attr,
                                    json_schema::TypeOfAttribute {
                                        required: attr_ty.required,
                                        ty: Self::resolve_type(resolve_table, attr_ty.ty)?,
                                        annotations: attr_ty.annotations,
                                        #[cfg(feature = "extended-schema")]
                                        loc: attr_ty.loc,
                                    },
                                ))
                            })
                            .partition_nonempty::<Vec<_>>()?,
                    ),
                    additional_attributes,
                }),
                loc,
            }),
            _ => Ok(ty),
        }
    }

    // Resolve common type references, returning a map from (fully-qualified)
    // [`InternalName`] of a common type to its [`Type`] definition
    fn resolve(
        &self,
        extensions: &Extensions<'_>,
    ) -> Result<HashMap<&'a InternalName, ValidatorType>> {
        let sorted_names = self.topo_sort().map_err(|n| {
            SchemaError::CycleInCommonTypeReferences(CycleInCommonTypeReferencesError { ty: n })
        })?;

        let mut resolve_table: HashMap<&InternalName, json_schema::Type<InternalName>> =
            HashMap::new();
        let mut tys: HashMap<&'a InternalName, ValidatorType> = HashMap::new();

        for &name in sorted_names.iter() {
            // PANIC SAFETY: `name.basename()` should be an existing common type id
            #[allow(clippy::unwrap_used)]
            let ty = self.defs.get(name).unwrap();
            let substituted_ty = Self::resolve_type(&resolve_table, ty.clone())?;
            resolve_table.insert(name, substituted_ty.clone());
            let substituted_ty_loc = substituted_ty.loc().cloned();
            let validator_type = try_jsonschema_type_into_validator_type(
                substituted_ty,
                extensions,
                substituted_ty_loc,
            )?;
            let validator_type = validator_type.resolve_common_type_refs(&HashMap::new())?;

            tys.insert(name, validator_type);
        }

        Ok(tys)
    }
}

// PANIC SAFETY unit tests
#[allow(clippy::panic)]
// PANIC SAFETY unit tests
#[allow(clippy::indexing_slicing)]
#[cfg(test)]
pub(crate) mod test {
    use std::{
        collections::{BTreeMap, HashSet},
        str::FromStr,
    };

    use crate::validator::json_schema;
    use crate::validator::types::Type;

    use crate::ast::RestrictedExpr;
    use crate::test_utils::{expect_err, ExpectedErrorMessageBuilder};
    use cool_asserts::assert_matches;

    use serde_json::json;

    use super::*;

    pub(crate) mod utils {
        use super::{CedarSchemaError, SchemaError, ValidatorEntityType, ValidatorSchema};
        use crate::extensions::Extensions;

        /// Transform the output of functions like
        /// `ValidatorSchema::from_cedarschema_str()`, which has type `(ValidatorSchema, impl Iterator<...>)`,
        /// into `(ValidatorSchema, Vec<...>)`, which implements `Debug` and thus can be used with
        /// `assert_matches`, `.unwrap_err()`, etc
        pub fn collect_warnings<A, B, E>(
            r: std::result::Result<(A, impl Iterator<Item = B>), E>,
        ) -> std::result::Result<(A, Vec<B>), E> {
            r.map(|(a, iter)| (a, iter.collect()))
        }

        /// Given an entity type as string, get the `ValidatorEntityType` from the
        /// schema, panicking if it does not exist (or if `etype` fails to parse as
        /// an entity type)
        #[track_caller]
        pub fn assert_entity_type_exists<'s>(
            schema: &'s ValidatorSchema,
            etype: &str,
        ) -> &'s ValidatorEntityType {
            schema.get_entity_type(&etype.parse().unwrap()).unwrap()
        }

        #[track_caller]
        pub fn assert_valid_cedar_schema(src: &str) -> ValidatorSchema {
            match ValidatorSchema::from_cedarschema_str(src, Extensions::all_available()) {
                Ok((schema, _)) => schema,
                Err(e) => panic!("{:?}", miette::Report::new(e)),
            }
        }

        #[track_caller]
        pub fn assert_invalid_cedar_schema(src: &str) {
            match ValidatorSchema::from_cedarschema_str(src, Extensions::all_available()) {
                Ok(_) => panic!("{src} should be an invalid schema"),
                Err(CedarSchemaError::Parsing(_)) => {}
                Err(e) => panic!("unexpected error: {:?}", miette::Report::new(e)),
            }
        }

        #[track_caller]
        pub fn assert_valid_json_schema(json: serde_json::Value) -> ValidatorSchema {
            match ValidatorSchema::from_json_value(json, Extensions::all_available()) {
                Ok(schema) => schema,
                Err(e) => panic!("{:?}", miette::Report::new(e)),
            }
        }

        #[track_caller]
        pub fn assert_invalid_json_schema(json: &serde_json::Value) {
            match ValidatorSchema::from_json_value(json.clone(), Extensions::all_available()) {
                Ok(_) => panic!("{json} should be an invalid schema"),
                Err(SchemaError::JsonDeserialization(_)) => {}
                Err(e) => panic!("unexpected error: {:?}", miette::Report::new(e)),
            }
        }
    }

    use utils::*;

    // Well-formed schema
    #[test]
    fn test_from_schema_file() {
        let src = json!(
        {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Group" ]
                },
                "Group": {
                    "memberOfTypes": []
                },
                "Photo": {
                    "memberOfTypes": [ "Album" ]
                },
                "Album": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view_photo": {
                    "appliesTo": {
                        "principalTypes": ["User", "Group"],
                        "resourceTypes": ["Photo"]
                    }
                }
            }
        });
        let schema_file: json_schema::NamespaceDefinition<RawName> =
            serde_json::from_value(src).unwrap();
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert!(schema.is_ok());
    }

    // Duplicate entity "Photo"
    #[test]
    fn test_from_schema_file_duplicate_entity() {
        // Test written using `from_str` instead of `from_value` because the
        // `json!` macro silently ignores duplicate map keys.
        let src = r#"
        {"": {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Group" ]
                },
                "Group": {
                    "memberOfTypes": []
                },
                "Photo": {
                    "memberOfTypes": [ "Album" ]
                },
                "Photo": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view_photo": {
                    "memberOf": [],
                    "appliesTo": {
                        "principalTypes": ["User", "Group"],
                        "resourceTypes": ["Photo"]
                    }
                }
            }
        }}"#;

        match ValidatorSchema::from_json_str(src, Extensions::all_available()) {
            Err(SchemaError::JsonDeserialization(_)) => (),
            _ => panic!("Expected JSON deserialization error due to duplicate entity type."),
        }
    }

    // Duplicate action "view_photo"
    #[test]
    fn test_from_schema_file_duplicate_action() {
        // Test written using `from_str` instead of `from_value` because the
        // `json!` macro silently ignores duplicate map keys.
        let src = r#"
        {"": {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Group" ]
                },
                "Group": {
                    "memberOfTypes": []
                },
                "Photo": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view_photo": {
                    "memberOf": [],
                    "appliesTo": {
                        "principalTypes": ["User", "Group"],
                        "resourceTypes": ["Photo"]
                    }
                },
                "view_photo": { }
            }
        }"#;
        match ValidatorSchema::from_json_str(src, Extensions::all_available()) {
            Err(SchemaError::JsonDeserialization(_)) => (),
            _ => panic!("Expected JSON deserialization error due to duplicate action type."),
        }
    }

    #[test]
    fn test_from_schema_file_missing_parent_action() {
        let src = json!({
            "": {
                "entityTypes": {
                    "Test": {}
                },
                "actions": {
                    "doTests": {
                        "memberOf": [
                            { "type": "Action", "id": "test1" },
                            { "type": "Action", "id": "test2" }
                        ]
                    }
                }
            }
        });
        match ValidatorSchema::from_json_value(src, Extensions::all_available()) {
            Err(SchemaError::ActionNotDefined(missing)) => {
                assert_eq!(missing.0.len(), 2);
            }
            _ => panic!("Expected ActionNotDefined due to unknown actions in memberOf."),
        }
    }

    #[test]
    fn test_from_schema_file_undefined_types_in_common() {
        let src = json!({
            "": {
                "commonTypes": {
                    "My1": {"type": "What"},
                    "My2": {"type": "Ev"},
                    "My3": {"type": "Er"}
                },
                "entityTypes": {
                    "Test": {}
                },
                "actions": {},
            }
        });
        match ValidatorSchema::from_json_value(src, Extensions::all_available()) {
            Err(SchemaError::TypeNotDefined(missing)) => {
                assert_eq!(missing.undefined_types.len(), 3);
            }
            x => panic!(
                "Expected TypeNotDefined due to unknown types in commonTypes, found: {:?}",
                x
            ),
        }
    }

    #[test]
    fn test_from_schema_file_undefined_entities_in_one_action() {
        let src = json!({
            "": {
                "entityTypes": {
                    "Test": {}
                },
                "actions": {
                    "doTests": {
                        "appliesTo": {
                            "principalTypes": ["Usr", "Group"],
                            "resourceTypes": ["Phoot"]
                        }
                    }
                }
            }
        });
        match ValidatorSchema::from_json_value(src, Extensions::all_available()) {
            Err(SchemaError::TypeNotDefined(missing)) => {
                assert_eq!(missing.undefined_types.len(), 3);
            }
            x => panic!(
                "Expected TypeNotDefined due to unknown entities in appliesTo, found: {:?}",
                x
            ),
        }
    }

    // Undefined entity types "Grop", "Usr", "Phoot"
    #[test]
    fn test_from_schema_file_undefined_entities() {
        let src = json!(
        {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Grop" ]
                },
                "Group": {
                    "memberOfTypes": []
                },
                "Photo": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view_photo": {
                    "appliesTo": {
                        "principalTypes": ["Usr", "Group"],
                        "resourceTypes": ["Phoot"]
                    }
                }
            }
        });
        let schema_file: json_schema::NamespaceDefinition<RawName> =
            serde_json::from_value(src.clone()).unwrap();
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"failed to resolve types: Grop, Usr, Phoot"#)
                    .help("`Grop` has not been declared as an entity type")
                    .exactly_one_underline("Grop")
                    .build());
        });
    }

    #[test]
    fn undefined_entity_namespace_member_of() {
        let src = json!(
        {"Foo": {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Foo::Group", "Bar::Group" ]
                },
                "Group": { }
            },
            "actions": {}
        }});
        let schema_file = json_schema::Fragment::from_json_value(src.clone()).unwrap();
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"failed to resolve type: Bar::Group"#)
                    .help("`Bar::Group` has not been declared as an entity type")
                    .exactly_one_underline("Bar::Group")
                    .build());
        });
    }

    #[test]
    fn undefined_entity_namespace_applies_to() {
        let src = json!(
        {"Foo": {
            "entityTypes": { "User": { }, "Photo": { } },
            "actions": {
                "view_photo": {
                    "appliesTo": {
                        "principalTypes": ["Foo::User", "Bar::User"],
                        "resourceTypes": ["Photo", "Bar::Photo"],
                    }
                }
            }
        }});
        let schema_file = json_schema::Fragment::from_json_value(src.clone()).unwrap();
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"failed to resolve types: Bar::User, Bar::Photo"#)
                    .help("`Bar::User` has not been declared as an entity type")
                    .exactly_one_underline("Bar::User")
                    .build());
        });
    }

    // Undefined action "photo_actions"
    #[test]
    fn test_from_schema_file_undefined_action() {
        let src = json!(
        {
            "entityTypes": {
                "User": {
                    "memberOfTypes": [ "Group" ]
                },
                "Group": {
                    "memberOfTypes": []
                },
                "Photo": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view_photo": {
                    "memberOf": [ {"id": "photo_action"} ],
                    "appliesTo": {
                        "principalTypes": ["User", "Group"],
                        "resourceTypes": ["Photo"]
                    }
                }
            }
        });
        let schema_file: json_schema::NamespaceDefinition<RawName> =
            serde_json::from_value(src.clone()).unwrap();
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"undeclared action: Action::"photo_action""#)
                    .help("any actions appearing as parents need to be declared as actions")
                    .build());
        });
    }

    // Trivial cycle in action hierarchy
    // view_photo -> view_photo
    #[test]
    fn test_from_schema_file_action_cycle1() {
        let src = json!(
        {
            "entityTypes": {},
            "actions": {
                "view_photo": {
                    "memberOf": [ {"id": "view_photo"} ]
                }
            }
        });
        let schema_file: json_schema::NamespaceDefinition<RawName> =
            serde_json::from_value(src).unwrap();
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert_matches!(
            schema,
            Err(SchemaError::CycleInActionHierarchy(CycleInActionHierarchyError { uid: euid })) => {
                assert_eq!(euid, r#"Action::"view_photo""#.parse().unwrap());
            }
        )
    }

    // Slightly more complex cycle in action hierarchy
    // view_photo -> edit_photo -> delete_photo -> view_photo
    #[test]
    fn test_from_schema_file_action_cycle2() {
        let src = json!(
        {
            "entityTypes": {},
            "actions": {
                "view_photo": {
                    "memberOf": [ {"id": "edit_photo"} ]
                },
                "edit_photo": {
                    "memberOf": [ {"id": "delete_photo"} ]
                },
                "delete_photo": {
                    "memberOf": [ {"id": "view_photo"} ]
                },
                "other_action": {
                    "memberOf": [ {"id": "edit_photo"} ]
                }
            }
        });
        let schema_file: json_schema::NamespaceDefinition<RawName> =
            serde_json::from_value(src).unwrap();
        let schema: Result<ValidatorSchema> = schema_file.try_into();
        assert_matches!(
            schema,
            // The exact action reported as being in the cycle isn't deterministic.
            Err(SchemaError::CycleInActionHierarchy(_)),
        )
    }

    #[test]
    fn namespaced_schema() {
        let src = r#"
        { "N::S": {
            "entityTypes": {
                "User": {},
                "Photo": {}
            },
            "actions": {
                "view_photo": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Photo"]
                    }
                }
            }
        } }
        "#;
        let schema_file = json_schema::Fragment::from_json_str(src).unwrap();
        let schema: ValidatorSchema = schema_file
            .try_into()
            .expect("Namespaced schema failed to convert.");
        dbg!(&schema);
        let user_entity_type = &"N::S::User"
            .parse()
            .expect("Namespaced entity type should have parsed");
        let photo_entity_type = &"N::S::Photo"
            .parse()
            .expect("Namespaced entity type should have parsed");
        assert!(
            schema.entity_types.contains_key(user_entity_type),
            "Expected and entity type User."
        );
        assert!(
            schema.entity_types.contains_key(photo_entity_type),
            "Expected an entity type Photo."
        );
        assert_eq!(
            schema.entity_types.len(),
            2,
            "Expected exactly 2 entity types."
        );
        assert!(
            schema.action_ids.contains_key(
                &"N::S::Action::\"view_photo\""
                    .parse()
                    .expect("Namespaced action should have parsed")
            ),
            "Expected an action \"view_photo\"."
        );
        assert_eq!(schema.action_ids.len(), 1, "Expected exactly 1 action.");

        let action = &schema.action_ids.values().next().expect("Expected Action");
        assert_eq!(
            action.applies_to_principals().collect::<Vec<_>>(),
            vec![user_entity_type]
        );
        assert_eq!(
            action.applies_to_resources().collect::<Vec<_>>(),
            vec![photo_entity_type]
        );
    }

    #[test]
    fn cant_use_namespace_in_entity_type() {
        let src = r#"
        {
            "entityTypes": { "NS::User": {} },
            "actions": {}
        }
        "#;
        assert_matches!(
            serde_json::from_str::<json_schema::NamespaceDefinition<RawName>>(src),
            Err(_)
        );
    }

    #[test]
    fn entity_attribute_entity_type_with_namespace() {
        let src = json!(
        {"A::B": {
            "entityTypes": {
                "Foo": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "name": { "type": "Entity", "name": "C::D::Foo" }
                        }
                    }
                }
            },
            "actions": {}
          }});
        let schema_json = json_schema::Fragment::from_json_value(src.clone()).unwrap();
        let schema: Result<ValidatorSchema> = schema_json.try_into();
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"failed to resolve type: C::D::Foo"#)
                    .help("`C::D::Foo` has not been declared as an entity type")
                    .exactly_one_underline("C::D::Foo")
                    .build());
        });
    }

    #[test]
    fn entity_attribute_entity_type_with_declared_namespace() {
        let schema_json = json_schema::Fragment::from_json_str(
            r#"
            {"A::B": {
                "entityTypes": {
                    "Foo": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "name": { "type": "Entity", "name": "A::B::Foo" }
                            }
                        }
                    }
                },
                "actions": {}
              }}
            "#,
        )
        .unwrap();

        let schema: ValidatorSchema = schema_json
            .try_into()
            .expect("Expected schema to construct without error.");

        let foo_name: EntityType = "A::B::Foo".parse().expect("Expected entity type name");
        let foo_type = schema
            .entity_types
            .get(&foo_name)
            .expect("Expected to find entity");
        let name_type = foo_type
            .attr("name")
            .expect("Expected attribute name")
            .attr_type
            .clone();
        assert_eq!(name_type, Type::named_entity_reference(foo_name));
    }

    #[test]
    fn cannot_declare_action_type_when_prohibited() {
        let schema_json: json_schema::NamespaceDefinition<RawName> = serde_json::from_str(
            r#"
            {
                "entityTypes": { "Action": {} },
                "actions": {}
              }
            "#,
        )
        .unwrap();
        let schema: Result<ValidatorSchema> = schema_json.try_into();
        assert!(matches!(
            schema,
            Err(SchemaError::ActionEntityTypeDeclared(_))
        ));
    }

    #[test]
    fn can_declare_other_type_when_action_type_prohibited() {
        let schema_json: json_schema::NamespaceDefinition<RawName> = serde_json::from_str(
            r#"
            {
                "entityTypes": { "Foo": { } },
                "actions": {}
              }
            "#,
        )
        .unwrap();

        TryInto::<ValidatorSchema>::try_into(schema_json).expect("Did not expect any errors.");
    }

    #[test]
    fn cannot_declare_action_in_group_when_prohibited() {
        let schema_json = json_schema::Fragment::from_json_str(
            r#"
            {"": {
                "entityTypes": {},
                "actions": {
                    "universe": { },
                    "view_photo": {
                        "attributes": {"id": "universe"}
                    },
                    "edit_photo": {
                        "attributes": {"id": "universe"}
                    },
                    "delete_photo": {
                        "attributes": {"id": "universe"}
                    }
                }
              }}
            "#,
        )
        .unwrap();

        let schema = ValidatorSchemaFragment::from_schema_fragment(
            schema_json,
            ActionBehavior::ProhibitAttributes,
            Extensions::all_available(),
        );
        match schema {
            Err(e) => {
                expect_err(
                    "",
                    &miette::Report::new(e),
                    &ExpectedErrorMessageBuilder::error("unsupported feature used in schema")
                        .source(r#"action declared with attributes: [delete_photo, edit_photo, view_photo]"#)
                        .build()
                )
            }
            _ => panic!("Did not see expected error."),
        }
    }

    #[test]
    fn test_entity_type_no_namespace() {
        let src = json!({"type": "Entity", "name": "Foo"});
        let schema_ty: json_schema::Type<RawName> = serde_json::from_value(src).unwrap();
        assert_eq!(
            schema_ty,
            json_schema::Type::Type {
                ty: json_schema::TypeVariant::Entity {
                    name: "Foo".parse().unwrap()
                },
                loc: None
            },
        );
        let schema_ty = schema_ty.conditionally_qualify_type_references(Some(
            &InternalName::parse_unqualified_name("NS").unwrap(),
        ));
        let all_defs = AllDefs::from_entity_defs([
            InternalName::from_str("NS::Foo").unwrap(),
            InternalName::from_str("Bar").unwrap(),
        ]);
        let schema_ty = schema_ty.fully_qualify_type_references(&all_defs).unwrap();
        let ty: ValidatorType =
            try_jsonschema_type_into_validator_type(schema_ty, Extensions::all_available(), None)
                .expect("Error converting schema type to type.")
                .resolve_common_type_refs(&HashMap::new())
                .unwrap();
        assert_eq!(ty.ty, Type::named_entity_reference_from_str("NS::Foo"));
    }

    #[test]
    fn test_entity_type_namespace() {
        let src = json!({"type": "Entity", "name": "NS::Foo"});
        let schema_ty: json_schema::Type<RawName> = serde_json::from_value(src).unwrap();
        assert_eq!(
            schema_ty,
            json_schema::Type::Type {
                ty: json_schema::TypeVariant::Entity {
                    name: "NS::Foo".parse().unwrap()
                },
                loc: None
            },
        );
        let schema_ty = schema_ty.conditionally_qualify_type_references(Some(
            &InternalName::parse_unqualified_name("NS").unwrap(),
        ));
        let all_defs = AllDefs::from_entity_defs([
            InternalName::from_str("NS::Foo").unwrap(),
            InternalName::from_str("Foo").unwrap(),
        ]);
        let schema_ty = schema_ty.fully_qualify_type_references(&all_defs).unwrap();
        let ty: ValidatorType =
            try_jsonschema_type_into_validator_type(schema_ty, Extensions::all_available(), None)
                .expect("Error converting schema type to type.")
                .resolve_common_type_refs(&HashMap::new())
                .unwrap();
        assert_eq!(ty.ty, Type::named_entity_reference_from_str("NS::Foo"));
    }

    #[test]
    fn test_entity_type_namespace_parse_error() {
        let src = json!({"type": "Entity", "name": "::Foo"});
        assert_matches!(
            serde_json::from_value::<json_schema::Type<RawName>>(src),
            Err(_)
        );
    }

    #[test]
    fn schema_type_record_is_validator_type_record() {
        let src = json!({"type": "Record", "attributes": {}});
        let schema_ty: json_schema::Type<RawName> = serde_json::from_value(src).unwrap();
        assert_eq!(
            schema_ty,
            json_schema::Type::Type {
                ty: json_schema::TypeVariant::Record(json_schema::RecordType {
                    attributes: BTreeMap::new(),
                    additional_attributes: false,
                }),
                loc: None
            },
        );
        let schema_ty = schema_ty.conditionally_qualify_type_references(None);
        let all_defs = AllDefs::from_entity_defs([InternalName::from_str("Foo").unwrap()]);
        let schema_ty = schema_ty.fully_qualify_type_references(&all_defs).unwrap();
        let ty: ValidatorType =
            try_jsonschema_type_into_validator_type(schema_ty, Extensions::all_available(), None)
                .expect("Error converting schema type to type.")
                .resolve_common_type_refs(&HashMap::new())
                .unwrap();
        assert_eq!(ty.ty, Type::closed_record_with_attributes(None));
    }

    #[test]
    fn get_namespaces() {
        let fragment = json_schema::Fragment::from_json_value(json!({
            "Foo::Bar::Baz": {
                "entityTypes": {},
                "actions": {}
            },
            "Foo": {
                "entityTypes": {},
                "actions": {}
            },
            "Bar": {
                "entityTypes": {},
                "actions": {}
            },
        }))
        .unwrap();

        let schema_fragment: ValidatorSchemaFragment<ConditionalName, ConditionalName> =
            fragment.try_into().unwrap();
        assert_eq!(
            schema_fragment
                .0
                .iter()
                .map(|f| f.namespace())
                .collect::<HashSet<_>>(),
            HashSet::from([
                Some(&"Foo::Bar::Baz".parse().unwrap()),
                Some(&"Foo".parse().unwrap()),
                Some(&"Bar".parse().unwrap())
            ])
        );
    }

    #[test]
    fn schema_no_fragments() {
        let schema =
            ValidatorSchema::from_schema_fragments([], Extensions::all_available()).unwrap();
        assert!(schema.entity_types.is_empty());
        assert!(schema.action_ids.is_empty());
    }

    #[test]
    fn same_action_different_namespace() {
        let fragment = json_schema::Fragment::from_json_value(json!({
            "Foo::Bar": {
                "entityTypes": {},
                "actions": {
                    "Baz": {}
                }
            },
            "Bar::Foo": {
                "entityTypes": {},
                "actions": {
                    "Baz": { }
                }
            },
            "Biz": {
                "entityTypes": {},
                "actions": {
                    "Baz": { }
                }
            }
        }))
        .unwrap();

        let schema: ValidatorSchema = fragment.try_into().unwrap();
        assert!(schema
            .get_action_id(&"Foo::Bar::Action::\"Baz\"".parse().unwrap())
            .is_some());
        assert!(schema
            .get_action_id(&"Bar::Foo::Action::\"Baz\"".parse().unwrap())
            .is_some());
        assert!(schema
            .get_action_id(&"Biz::Action::\"Baz\"".parse().unwrap())
            .is_some());
    }

    #[test]
    fn same_type_different_namespace() {
        let fragment = json_schema::Fragment::from_json_value(json!({
            "Foo::Bar": {
                "entityTypes": {"Baz" : {}},
                "actions": { }
            },
            "Bar::Foo": {
                "entityTypes": {"Baz" : {}},
                "actions": { }
            },
            "Biz": {
                "entityTypes": {"Baz" : {}},
                "actions": { }
            }
        }))
        .unwrap();
        let schema: ValidatorSchema = fragment.try_into().unwrap();

        assert_entity_type_exists(&schema, "Foo::Bar::Baz");
        assert_entity_type_exists(&schema, "Bar::Foo::Baz");
        assert_entity_type_exists(&schema, "Biz::Baz");
    }

    #[test]
    fn member_of_different_namespace() {
        let fragment = json_schema::Fragment::from_json_value(json!({
            "Bar": {
                "entityTypes": {
                    "Baz": {
                        "memberOfTypes": ["Foo::Buz"]
                    }
                },
                "actions": {}
            },
            "Foo": {
                "entityTypes": { "Buz": {} },
                "actions": { }
            }
        }))
        .unwrap();
        let schema: ValidatorSchema = fragment.try_into().unwrap();

        let buz = assert_entity_type_exists(&schema, "Foo::Buz");
        assert_eq!(
            buz.descendants,
            HashSet::from(["Bar::Baz".parse().unwrap()])
        );
    }

    #[test]
    fn attribute_different_namespace() {
        let fragment = json_schema::Fragment::from_json_value(json!({
            "Bar": {
                "entityTypes": {
                    "Baz": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "fiz": {
                                    "type": "Entity",
                                    "name": "Foo::Buz"
                                }
                            }
                        }
                    }
                },
                "actions": {}
            },
            "Foo": {
                "entityTypes": { "Buz": {} },
                "actions": { }
            }
        }))
        .unwrap();

        let schema: ValidatorSchema = fragment.try_into().unwrap();
        let baz = assert_entity_type_exists(&schema, "Bar::Baz");
        assert_eq!(
            baz.attr("fiz").unwrap().attr_type,
            Type::named_entity_reference_from_str("Foo::Buz"),
        );
    }

    #[test]
    fn applies_to_different_namespace() {
        let fragment = json_schema::Fragment::from_json_value(json!({
            "Foo::Bar": {
                "entityTypes": { },
                "actions": {
                    "Baz": {
                        "appliesTo": {
                            "principalTypes": [ "Fiz::Buz" ],
                            "resourceTypes": [ "Fiz::Baz" ],
                        }
                    }
                }
            },
            "Fiz": {
                "entityTypes": {
                    "Buz": {},
                    "Baz": {}
                },
                "actions": { }
            }
        }))
        .unwrap();
        let schema: ValidatorSchema = fragment.try_into().unwrap();

        let baz = schema
            .get_action_id(&"Foo::Bar::Action::\"Baz\"".parse().unwrap())
            .unwrap();
        assert_eq!(
            baz.applies_to
                .applicable_principal_types()
                .collect::<HashSet<_>>(),
            HashSet::from([&("Fiz::Buz".parse().unwrap())])
        );
        assert_eq!(
            baz.applies_to
                .applicable_resource_types()
                .collect::<HashSet<_>>(),
            HashSet::from([&("Fiz::Baz".parse().unwrap())])
        );
    }

    #[test]
    fn simple_defined_type() {
        let fragment = json_schema::Fragment::from_json_value(json!({
            "": {
                "commonTypes": {
                    "MyLong": {"type": "Long"}
                },
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": {"type": "MyLong"}
                            }
                        }
                    }
                },
                "actions": {}
            }
        }))
        .unwrap();
        let schema: ValidatorSchema = fragment.try_into().unwrap();
        assert_eq!(
            schema.entity_types.iter().next().unwrap().1.attributes(),
            &Attributes::with_required_attributes([("a".into(), Type::primitive_long())])
        );
    }

    #[test]
    fn defined_record_as_attrs() {
        let fragment = json_schema::Fragment::from_json_value(json!({
            "": {
                "commonTypes": {
                    "MyRecord": {
                        "type": "Record",
                        "attributes":  {
                            "a": {"type": "Long"}
                        }
                    }
                },
                "entityTypes": {
                    "User": { "shape": { "type": "MyRecord", } }
                },
                "actions": {}
            }
        }))
        .unwrap();
        let schema: ValidatorSchema = fragment.try_into().unwrap();
        assert_eq!(
            schema.entity_types.iter().next().unwrap().1.attributes(),
            &Attributes::with_required_attributes([("a".into(), Type::primitive_long())])
        );
    }

    #[test]
    fn cross_namespace_type() {
        let fragment = json_schema::Fragment::from_json_value(json!({
            "A": {
                "commonTypes": {
                    "MyLong": {"type": "Long"}
                },
                "entityTypes": { },
                "actions": {}
            },
            "B": {
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": {"type": "A::MyLong"}
                            }
                        }
                    }
                },
                "actions": {}
            }
        }))
        .unwrap();
        let schema: ValidatorSchema = fragment.try_into().unwrap();
        assert_eq!(
            schema.entity_types.iter().next().unwrap().1.attributes(),
            &Attributes::with_required_attributes([("a".into(), Type::primitive_long())])
        );
    }

    #[test]
    fn cross_fragment_type() {
        let fragment1: ValidatorSchemaFragment<ConditionalName, ConditionalName> =
            json_schema::Fragment::from_json_value(json!({
                "A": {
                    "commonTypes": {
                        "MyLong": {"type": "Long"}
                    },
                    "entityTypes": { },
                    "actions": {}
                }
            }))
            .unwrap()
            .try_into()
            .unwrap();
        let fragment2: ValidatorSchemaFragment<ConditionalName, ConditionalName> =
            json_schema::Fragment::from_json_value(json!({
                "A": {
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "a": {"type": "MyLong"}
                                }
                            }
                        }
                    },
                    "actions": {}
                }
            }))
            .unwrap()
            .try_into()
            .unwrap();
        let schema = ValidatorSchema::from_schema_fragments(
            [fragment1, fragment2],
            Extensions::all_available(),
        )
        .unwrap();

        assert_eq!(
            schema.entity_types.iter().next().unwrap().1.attributes(),
            &Attributes::with_required_attributes([("a".into(), Type::primitive_long())])
        );
    }

    #[test]
    fn cross_fragment_duplicate_type() {
        let fragment1: ValidatorSchemaFragment<ConditionalName, ConditionalName> =
            json_schema::Fragment::from_json_value(json!({
                "A": {
                    "commonTypes": {
                        "MyLong": {"type": "Long"}
                    },
                    "entityTypes": {},
                    "actions": {}
                }
            }))
            .unwrap()
            .try_into()
            .unwrap();
        let fragment2: ValidatorSchemaFragment<ConditionalName, ConditionalName> =
            json_schema::Fragment::from_json_value(json!({
                "A": {
                    "commonTypes": {
                        "MyLong": {"type": "Long"}
                    },
                    "entityTypes": {},
                    "actions": {}
                }
            }))
            .unwrap()
            .try_into()
            .unwrap();

        let schema = ValidatorSchema::from_schema_fragments(
            [fragment1, fragment2],
            Extensions::all_available(),
        );

        // should error because schema fragments have duplicate types
        assert_matches!(schema, Err(SchemaError::DuplicateCommonType(DuplicateCommonTypeError { ty })) => {
            assert_eq!(ty, "A::MyLong".parse().unwrap());
        });
    }

    #[test]
    fn undeclared_type_in_attr() {
        let fragment = json_schema::Fragment::from_json_value(json!({
            "": {
                "commonTypes": { },
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": {"type": "MyLong"}
                            }
                        }
                    }
                },
                "actions": {}
            }
        }))
        .unwrap();
        assert_matches!(
            TryInto::<ValidatorSchema>::try_into(fragment),
            Err(SchemaError::TypeNotDefined(_))
        );
    }

    #[test]
    fn undeclared_type_in_common_types() {
        let fragment = json_schema::Fragment::from_json_value(json!({
            "": {
                "commonTypes": {
                    "a": { "type": "b" }
                },
                "entityTypes": { },
                "actions": {}
            }
        }))
        .unwrap();
        assert_matches!(
            TryInto::<ValidatorSchema>::try_into(fragment),
            Err(SchemaError::TypeNotDefined(_))
        );
    }

    #[test]
    fn shape_not_record() {
        let fragment = json_schema::Fragment::from_json_value(json!({
            "": {
                "commonTypes": {
                    "MyLong": { "type": "Long" }
                },
                "entityTypes": {
                    "User": {
                        "shape": { "type": "MyLong" }
                    }
                },
                "actions": {}
            }
        }))
        .unwrap();
        assert_matches!(
            TryInto::<ValidatorSchema>::try_into(fragment),
            Err(SchemaError::ContextOrShapeNotRecord(_))
        );
    }

    /// This test checks for regressions on (adapted versions of) the examples
    /// mentioned in the thread at
    /// [cedar#134](https://github.com/cedar-policy/cedar/pull/134)
    #[test]
    fn counterexamples_from_cedar_134() {
        // non-normalized entity type name
        let bad1 = json!({
            "": {
                "entityTypes": {
                    "User // comment": {
                        "memberOfTypes": [
                            "UserGroup"
                        ]
                    },
                    "User": {
                        "memberOfTypes": [
                            "UserGroup"
                        ]
                    },
                    "UserGroup": {}
                },
                "actions": {}
            }
        });
        assert_matches!(json_schema::Fragment::from_json_value(bad1), Err(_));

        // non-normalized schema namespace
        let bad2 = json!({
            "ABC     :: //comment \n XYZ  ": {
                "entityTypes": {
                    "User": {
                        "memberOfTypes": []
                    }
                },
                "actions": {}
            }
        });
        assert_matches!(json_schema::Fragment::from_json_value(bad2), Err(_));
    }

    #[test]
    fn simple_action_entity() {
        let src = json!(
        {
            "entityTypes": { },
            "actions": {
                "view_photo": { },
            }
        });

        let schema_file: json_schema::NamespaceDefinition<RawName> =
            serde_json::from_value(src).unwrap();
        let schema: ValidatorSchema = schema_file.try_into().unwrap();
        let actions = schema.action_entities().expect("Entity Construct Error");

        let action_uid = EntityUID::from_str("Action::\"view_photo\"").unwrap();
        let view_photo = actions.entity(&action_uid);
        assert_eq!(
            view_photo.unwrap(),
            &Entity::new_with_attr_partial_value(
                action_uid,
                [],
                HashSet::new(),
                HashSet::new(),
                []
            )
        );
    }

    #[test]
    fn action_entity_hierarchy() {
        let src = json!(
        {
            "entityTypes": { },
            "actions": {
                "read": {},
                "view": {
                    "memberOf": [{"id": "read"}]
                },
                "view_photo": {
                    "memberOf": [{"id": "view"}]
                },
            }
        });

        let schema_file: json_schema::NamespaceDefinition<RawName> =
            serde_json::from_value(src).unwrap();
        let schema: ValidatorSchema = schema_file.try_into().unwrap();
        let actions = schema.action_entities().expect("Entity Construct Error");

        let view_photo_uid = EntityUID::from_str("Action::\"view_photo\"").unwrap();
        let view_uid = EntityUID::from_str("Action::\"view\"").unwrap();
        let read_uid = EntityUID::from_str("Action::\"read\"").unwrap();

        let view_photo_entity = actions.entity(&view_photo_uid);
        assert_eq!(
            view_photo_entity.unwrap(),
            &Entity::new_with_attr_partial_value(
                view_photo_uid,
                [],
                HashSet::new(),
                HashSet::from([view_uid, read_uid.clone()]),
                [],
            )
        );

        let read_entity = actions.entity(&read_uid);
        assert_eq!(
            read_entity.unwrap(),
            &Entity::new_with_attr_partial_value(read_uid, [], HashSet::new(), HashSet::new(), [])
        );
    }

    #[test]
    fn action_entity_attribute() {
        let src = json!(
        {
            "entityTypes": { },
            "actions": {
                "view_photo": {
                    "attributes": { "attr": "foo" }
                },
            }
        });

        let schema_file: NamespaceDefinitionWithActionAttributes<RawName> =
            serde_json::from_value(src).unwrap();
        let schema: ValidatorSchema = schema_file.try_into().unwrap();
        let actions = schema.action_entities().expect("Entity Construct Error");

        let action_uid = EntityUID::from_str("Action::\"view_photo\"").unwrap();
        let view_photo = actions.entity(&action_uid);
        assert_eq!(
            view_photo.unwrap(),
            &Entity::new(
                action_uid,
                [("attr".into(), RestrictedExpr::val("foo"))],
                HashSet::new(),
                HashSet::new(),
                [],
                Extensions::none(),
            )
            .unwrap(),
        );
    }

    #[test]
    fn test_action_namespace_inference_multi_success() {
        let src = json!({
            "Foo" : {
                "entityTypes" : {},
                "actions" : {
                    "read" : {}
                }
            },
            "ExampleCo::Personnel" : {
                "entityTypes" : {},
                "actions" : {
                    "viewPhoto" : {
                        "memberOf" : [
                            {
                                "id" : "read",
                                "type" : "Foo::Action"
                            }
                        ]
                    }
                }
            },
        });
        let schema_fragment =
            json_schema::Fragment::from_json_value(src).expect("Failed to parse schema");
        let schema: ValidatorSchema = schema_fragment.try_into().expect("Schema should construct");
        let view_photo = ValidatorSchema::action_entities_iter(&schema.action_ids)
            .find(|e| e.uid() == &r#"ExampleCo::Personnel::Action::"viewPhoto""#.parse().unwrap())
            .unwrap();
        let ancestors = view_photo.ancestors().collect::<Vec<_>>();
        let read = ancestors[0];
        let read_eid: &str = read.eid().as_ref();
        assert_eq!(read_eid, "read");
        assert_eq!(read.entity_type().to_string(), "Foo::Action");
    }

    #[test]
    fn test_action_namespace_inference_multi() {
        let src = json!({
            "ExampleCo::Personnel::Foo" : {
                "entityTypes" : {},
                "actions" : {
                    "read" : {}
                }
            },
            "ExampleCo::Personnel" : {
                "entityTypes" : {},
                "actions" : {
                    "viewPhoto" : {
                        "memberOf" : [
                            {
                                "id" : "read",
                                "type" : "Foo::Action"
                            }
                        ]
                    }
                }
            },
        });
        let schema_fragment =
            json_schema::Fragment::from_json_value(src).expect("Failed to parse schema");
        let schema: std::result::Result<ValidatorSchema, _> = schema_fragment.try_into();
        schema.expect_err("Schema should fail to construct as the normalization rules treat any qualification as starting from the root");
    }

    #[test]
    fn test_action_namespace_inference() {
        let src = json!({
            "ExampleCo::Personnel" : {
                "entityTypes" : { },
                "actions" : {
                    "read" : {},
                    "viewPhoto" : {
                        "memberOf" : [
                            {
                                "id" :  "read",
                                "type" : "Action"
                            }
                        ]
                    }
                }
            }
        });
        let schema_fragment =
            json_schema::Fragment::from_json_value(src).expect("Failed to parse schema");
        let schema: ValidatorSchema = schema_fragment.try_into().unwrap();
        let view_photo = ValidatorSchema::action_entities_iter(&schema.action_ids)
            .find(|e| e.uid() == &r#"ExampleCo::Personnel::Action::"viewPhoto""#.parse().unwrap())
            .unwrap();
        let ancestors = view_photo.ancestors().collect::<Vec<_>>();
        let read = ancestors[0];
        let read_eid: &str = read.eid().as_ref();
        assert_eq!(read_eid, "read");
        assert_eq!(
            read.entity_type().to_string(),
            "ExampleCo::Personnel::Action"
        );
    }

    #[test]
    fn fallback_to_empty_namespace() {
        let src = json!(
            {
                "Demo": {
                  "entityTypes": {
                    "User": {
                      "memberOfTypes": [],
                      "shape": {
                        "type": "Record",
                        "attributes": {
                          "id": { "type": "id" },
                        }
                      }
                    }
                  },
                  "actions": {}
                },
                "": {
                  "commonTypes": {
                    "id": {
                      "type": "String"
                    },
                  },
                  "entityTypes": {},
                  "actions": {}
                }
              }
        );
        let schema = ValidatorSchema::from_json_value(src, Extensions::all_available()).unwrap();
        let mut attributes = assert_entity_type_exists(&schema, "Demo::User")
            .attributes()
            .iter();
        let (attr_name, attr_ty) = attributes.next().unwrap();
        assert_eq!(attr_name, "id");
        assert_eq!(&attr_ty.attr_type, &Type::primitive_string());
        assert_matches!(attributes.next(), None);
    }

    #[test]
    fn qualified_undeclared_common_types2() {
        let src = json!(
            {
                "Demo": {
                  "entityTypes": {
                    "User": {
                      "memberOfTypes": [],
                      "shape": {
                        "type": "Record",
                        "attributes": {
                          "id": { "type": "Demo::id" },
                        }
                      }
                    }
                  },
                  "actions": {}
                },
                "": {
                  "commonTypes": {
                    "id": {
                      "type": "String"
                    },
                  },
                  "entityTypes": {},
                  "actions": {}
                }
              }
        );
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"failed to resolve type: Demo::id"#)
                    .help("`Demo::id` has not been declared as a common type")
                    .exactly_one_underline("Demo::id")
                    .build());
        });
    }

    #[test]
    fn undeclared_entity_type_in_common_type() {
        let src = json!(
            {
                "": {
                  "commonTypes": {
                    "id": {
                      "type": "Entity",
                      "name": "undeclared"
                    },
                  },
                  "entityTypes": {},
                  "actions": {}
                }
              }
        );
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"failed to resolve type: undeclared"#)
                    .help("`undeclared` has not been declared as an entity type")
                    .exactly_one_underline("undeclared")
                    .build());
        });
    }

    #[test]
    fn undeclared_entity_type_in_common_type_record() {
        let src = json!(
            {
                "": {
                  "commonTypes": {
                    "id": {
                      "type": "Record",
                      "attributes": {
                        "first": {
                            "type": "Entity",
                            "name": "undeclared"
                        }
                      }
                    },
                  },
                  "entityTypes": {},
                  "actions": {}
                }
              }
        );
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"failed to resolve type: undeclared"#)
                    .help("`undeclared` has not been declared as an entity type")
                    .exactly_one_underline("undeclared")
                    .build());
        });
    }

    #[test]
    fn undeclared_entity_type_in_common_type_set() {
        let src = json!(
            {
                "": {
                  "commonTypes": {
                    "id": {
                      "type": "Set",
                      "element": {
                        "type": "Entity",
                        "name": "undeclared"
                      }
                    },
                  },
                  "entityTypes": {},
                  "actions": {}
                }
              }
        );
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error(r#"failed to resolve type: undeclared"#)
                    .help("`undeclared` has not been declared as an entity type")
                    .exactly_one_underline("undeclared")
                    .build());
        });
    }

    #[test]
    fn unknown_extension_type() {
        let src: serde_json::Value = json!({
            "": {
                "commonTypes": { },
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": {
                                    "type": "Extension",
                                    "name": "ip",
                                }
                            }
                        }
                    }
                },
                "actions": {}
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("unknown extension type `ip`")
                    .help("did you mean `ipaddr`?")
                    .build());
        });

        let src: serde_json::Value = json!({
            "": {
                "commonTypes": { },
                "entityTypes": {
                    "User": {},
                    "Folder" :{}
                },
                "actions": {
                    "A": {
                        "appliesTo": {
                            "principalTypes" : ["User"],
                            "resourceTypes" : ["Folder"],
                            "context": {
                                "type": "Record",
                                "attributes": {
                                    "a": {
                                        "type": "Extension",
                                        "name": "deciml",
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("unknown extension type `deciml`")
                    .help("did you mean `decimal`?")
                    .build());
        });

        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "ty": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Extension",
                                "name": "i",
                            }
                        }
                    }
                },
                "entityTypes": { },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("unknown extension type `i`")
                    .help("did you mean `ipaddr`?")
                    .build());
        });

        {
            let src: serde_json::Value = json!({
                "": {
                    "commonTypes": {
                        "ty": {
                            "type": "Record",
                            "attributes": {
                                "a": {
                                    "type": "Extension",
                                    "name": "partial_evaluation",
                                }
                            }
                        }
                    },
                    "entityTypes": { },
                    "actions": { },
                }
            });
            let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
            assert_matches!(schema, Err(e) => {
                expect_err(
                    &src,
                    &miette::Report::new(e),
                    &ExpectedErrorMessageBuilder::error("unknown extension type `partial_evaluation`")
                        .help("did you mean `duration`?")
                        .build());
            });
        }
    }

    #[track_caller]
    fn assert_invalid_json_schema(src: serde_json::Value) {
        let schema = ValidatorSchema::from_json_value(src, Extensions::all_available());
        assert_matches!(schema, Err(SchemaError::JsonDeserialization(e)) if e.to_smolstr().contains("this is reserved and cannot be the basename of a common-type declaration"));
    }

    // Names like `Set`, `Record`, `Entity`, and Extension` are not allowed as common type names, as specified in #1070 and #1139.
    #[test]
    fn test_common_type_name_conflicts() {
        // `Record` cannot be a common type name
        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "Record": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Record"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);

        let src: serde_json::Value = json!({
            "NS": {
                "commonTypes": {
                    "Record": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Record"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);

        // `Extension` cannot be a common type name
        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "Extension": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Extension"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);

        let src: serde_json::Value = json!({
            "NS": {
                "commonTypes": {
                    "Extension": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Extension"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);

        // `Entity` cannot be a common type name
        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "Entity": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Entity"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);

        let src: serde_json::Value = json!({
            "NS": {
                "commonTypes": {
                    "Entity": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Entity"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);

        // `Set` cannot be a common type name
        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "Set": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Set"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);

        let src: serde_json::Value = json!({
            "NS": {
                "commonTypes": {
                    "Set": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Set"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);

        // `Long` cannot be a common type name
        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "Long": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Long"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);

        let src: serde_json::Value = json!({
            "NS": {
                "commonTypes": {
                    "Long": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Long"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);

        // `Boolean` cannot be a common type name
        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "Boolean": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Boolean"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);

        let src: serde_json::Value = json!({
            "NS": {
                "commonTypes": {
                    "Boolean": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "Boolean"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);

        // `String` cannot be a common type name
        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "String": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "String"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);

        let src: serde_json::Value = json!({
            "NS": {
                "commonTypes": {
                    "String": {
                        "type": "Record",
                        "attributes": {
                            "a": {
                                "type": "Long",
                            }
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" : {
                            "type" : "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "String"
                                }
                        }
                    }
                }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);

        // Cedar examines common type name declarations eagerly.
        // So it throws an error for the following example even though `Record`
        // is not referenced.
        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "Record": {
                        "type": "Set",
                        "element": {
                            "type": "Long"
                        }
                    }
                },
                "entityTypes": {
                    "b": {
                        "shape" :
                        {
                            "type": "Record",
                            "attributes" : {
                                "c" : {
                                    "type" : "String"
                                }
                            }
                        }
                    }
                },
                "actions": { },
            }
        });
        assert_invalid_json_schema(src);
    }

    #[test]
    fn reserved_namespace() {
        let src: serde_json::Value = json!({
            "__cedar": {
                "commonTypes": { },
                "entityTypes": { },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src, Extensions::all_available());
        assert_matches!(schema, Err(SchemaError::JsonDeserialization(_)));

        let src: serde_json::Value = json!({
            "__cedar::A": {
                "commonTypes": { },
                "entityTypes": { },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src, Extensions::all_available());
        assert_matches!(schema, Err(SchemaError::JsonDeserialization(_)));

        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "__cedar": {
                        "type": "String",
                    }
                },
                "entityTypes": { },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src, Extensions::all_available());
        assert_matches!(schema, Err(SchemaError::JsonDeserialization(_)));

        let src: serde_json::Value = json!({
            "A": {
                "commonTypes": {
                    "__cedar": {
                        "type": "String",
                    }
                },
                "entityTypes": { },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src, Extensions::all_available());
        assert_matches!(schema, Err(SchemaError::JsonDeserialization(_)));

        let src: serde_json::Value = json!({
            "": {
                "commonTypes": {
                    "A": {
                        "type": "__cedar",
                    }
                },
                "entityTypes": { },
                "actions": { },
            }
        });
        let schema = ValidatorSchema::from_json_value(src.clone(), Extensions::all_available());
        assert_matches!(schema, Err(e) => {
            expect_err(
                &src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("failed to resolve type: __cedar")
                    .help("`__cedar` has not been declared as a common type")
                    .exactly_one_underline("__cedar")
                    .build(),
            );
        });
    }

    #[test]
    fn attr_named_tags() {
        let src = r#"
            entity E { tags: Set<{key: String, value: Set<String>}> };
        "#;
        assert_valid_cedar_schema(src);
    }
}

#[cfg(test)]
mod test_579; // located in separate file test_579.rs

#[cfg(test)]
#[allow(clippy::cognitive_complexity)]
mod test_rfc70 {
    use super::test::utils::*;
    use super::ValidatorSchema;
    use crate::validator::types::Type;
    use crate::{
        extensions::Extensions,
        test_utils::{expect_err, ExpectedErrorMessageBuilder},
    };
    use cool_asserts::assert_matches;
    use serde_json::json;

    /// Common type shadowing a common type is disallowed in both syntaxes
    #[test]
    fn common_common_conflict() {
        let src = "
            type T = String;
            namespace NS {
                type T = String;
                entity User { t: T };
            }
        ";
        assert_matches!(collect_warnings(ValidatorSchema::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("definition of `NS::T` illegally shadows the existing definition of `T`")
                    .help("try renaming one of the definitions, or moving `T` to a different namespace")
                    .exactly_one_underline("type T = String;")
                    .build(),
            );
        });

        let src_json = json!({
            "": {
                "commonTypes": {
                    "T": { "type": "String" },
                },
                "entityTypes": {},
                "actions": {},
            },
            "NS": {
                "commonTypes": {
                    "T": { "type": "String" },
                },
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "t": { "type": "T" },
                            },
                        }
                    }
                },
                "actions": {},
            }
        });
        assert_matches!(ValidatorSchema::from_json_value(src_json.clone(), Extensions::all_available()), Err(e) => {
            expect_err(
                &src_json,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("definition of `NS::T` illegally shadows the existing definition of `T`")
                    .help("try renaming one of the definitions, or moving `T` to a different namespace")
                    .build(),
            );
        });
    }

    /// Entity type shadowing an entity type is disallowed in both syntaxes
    #[test]
    fn entity_entity_conflict() {
        let src = "
            entity T in T { foo: String };
            namespace NS {
                entity T { bar: String };
                entity User { t: T };
            }
        ";
        assert_matches!(collect_warnings(ValidatorSchema::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("definition of `NS::T` illegally shadows the existing definition of `T`")
                    .help("try renaming one of the definitions, or moving `T` to a different namespace")
                    .exactly_one_underline("entity T { bar: String };")
                    .build(),
            );
        });

        // still disallowed even if there are no ambiguous references to `T`
        let src = "
            entity T { foo: String };
            namespace NS {
                entity T { bar: String };
            }
        ";
        assert_matches!(collect_warnings(ValidatorSchema::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("definition of `NS::T` illegally shadows the existing definition of `T`")
                    .help("try renaming one of the definitions, or moving `T` to a different namespace")
                    .exactly_one_underline("entity T { bar: String };")
                    .build(),
            );
        });

        let src_json = json!({
            "": {
                "entityTypes": {
                    "T": {
                        "memberOfTypes": ["T"],
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "foo": { "type": "String" },
                            },
                        }
                    }
                },
                "actions": {},
            },
            "NS": {
                "entityTypes": {
                    "T": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "bar": { "type": "String" },
                            },
                        }
                    },
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "t": { "type": "Entity", "name": "T" },
                            },
                        }
                    },
                },
                "actions": {},
            }
        });
        assert_matches!(ValidatorSchema::from_json_value(src_json.clone(), Extensions::all_available()), Err(e) => {
            expect_err(
                &src_json,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("definition of `NS::T` illegally shadows the existing definition of `T`")
                    .help("try renaming one of the definitions, or moving `T` to a different namespace")
                    .build(),
            );
        });
    }

    /// Common type shadowing an entity type is disallowed in both syntaxes,
    /// even though it would be unambiguous in the JSON syntax
    #[test]
    fn common_entity_conflict() {
        let src = "
            entity T in T { foo: String };
            namespace NS {
                type T = String;
                entity User { t: T };
            }
        ";
        assert_matches!(collect_warnings(ValidatorSchema::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("definition of `NS::T` illegally shadows the existing definition of `T`")
                    .help("try renaming one of the definitions, or moving `T` to a different namespace")
                    .exactly_one_underline("type T = String;")
                    .build(),
            );
        });

        let src_json = json!({
            "": {
                "entityTypes": {
                    "T": {
                        "memberOfTypes": ["T"],
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "foo": { "type": "String" },
                            },
                        }
                    }
                },
                "actions": {},
            },
            "NS": {
                "commonTypes": {
                    "T": { "type": "String" },
                },
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "t": { "type": "T" },
                            }
                        }
                    }
                },
                "actions": {},
            }
        });
        assert_matches!(ValidatorSchema::from_json_value(src_json.clone(), Extensions::all_available()), Err(e) => {
            expect_err(
                &src_json,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("definition of `NS::T` illegally shadows the existing definition of `T`")
                    .help("try renaming one of the definitions, or moving `T` to a different namespace")
                    .build(),
            );
        });
    }

    /// Entity type shadowing a common type is disallowed in both syntaxes, even
    /// though it would be unambiguous in the JSON syntax
    #[test]
    fn entity_common_conflict() {
        let src = "
            type T = String;
            namespace NS {
                entity T in T { foo: String };
                entity User { t: T };
            }
        ";
        assert_matches!(collect_warnings(ValidatorSchema::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("definition of `NS::T` illegally shadows the existing definition of `T`")
                    .help("try renaming one of the definitions, or moving `T` to a different namespace")
                    .exactly_one_underline("entity T in T { foo: String };")
                    .build(),
            );
        });

        let src_json = json!({
            "": {
                "commonTypes": {
                    "T": { "type": "String" },
                },
                "entityTypes": {},
                "actions": {},
            },
            "NS": {
                "entityTypes": {
                    "T": {
                        "memberOfTypes": ["T"],
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "foo": { "type": "String" },
                            },
                        }
                    },
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "t": { "type": "T" },
                            }
                        }
                    }
                },
                "actions": {},
            }
        });
        assert_matches!(ValidatorSchema::from_json_value(src_json.clone(), Extensions::all_available()), Err(e) => {
            expect_err(
                &src_json,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("definition of `NS::T` illegally shadows the existing definition of `T`")
                    .help("try renaming one of the definitions, or moving `T` to a different namespace")
                    .build(),
            );
        });
    }

    /// Action shadowing an action is disallowed in both syntaxes
    #[test]
    fn action_action_conflict() {
        let src = "
            action A;
            namespace NS {
                action A;
            }
        ";
        assert_matches!(collect_warnings(ValidatorSchema::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            let assertion = ExpectedErrorMessageBuilder::error("definition of `NS::Action::\"A\"` illegally shadows the existing definition of `Action::\"A\"`")
                .help("try renaming one of the actions, or moving `Action::\"A\"` to a different namespace");
            #[cfg(feature = "extended-schema")]
            let assertion = assertion.exactly_one_underline("A");

            expect_err(
                src,
                &miette::Report::new(e),
                &assertion.build()
            );
        });

        let src_json = json!({
            "": {
                "entityTypes": {},
                "actions": {
                    "A": {},
                },
            },
            "NS": {
                "entityTypes": {},
                "actions": {
                    "A": {},
                },
            }
        });
        assert_matches!(ValidatorSchema::from_json_value(src_json.clone(), Extensions::all_available()), Err(e) => {
            expect_err(
                &src_json,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("definition of `NS::Action::\"A\"` illegally shadows the existing definition of `Action::\"A\"`")
                    .help("try renaming one of the actions, or moving `Action::\"A\"` to a different namespace")
                    .build(),
            );
        });
    }

    /// Action with same name as a common type is allowed
    #[test]
    fn action_common_conflict() {
        let src = "
            action A;
            action B; // same name as a common type in same (empty) namespace
            action C; // same name as a common type in different (nonempty) namespace
            type B = String;
            type E = String;
            namespace NS1 {
                type C = String;
                entity User { b: B, c: C, e: E };
            }
            namespace NS2 {
                type D = String;
                action D; // same name as a common type in same (nonempty) namespace
                action E; // same name as a common type in different (empty) namespace
                entity User { b: B, d: D, e: E };
            }
        ";
        assert_valid_cedar_schema(src);

        let src_json = json!({
            "": {
                "commonTypes": {
                    "B": { "type": "String" },
                    "E": { "type": "String" },
                },
                "entityTypes": {},
                "actions": {
                    "A": {},
                    "B": {},
                    "C": {},
                },
            },
            "NS1": {
                "commonTypes": {
                    "C": { "type": "String" },
                },
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "b": { "type": "B" },
                                "c": { "type": "C" },
                                "e": { "type": "E" },
                            }
                        }
                    },
                },
                "actions": {}
            },
            "NS2": {
                "commonTypes": {
                    "D": { "type": "String" },
                },
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "b": { "type": "B" },
                                "d": { "type": "D" },
                                "e": { "type": "E" },
                            }
                        }
                    }
                },
                "actions": {
                    "D": {},
                    "E": {},
                }
            }
        });
        assert_valid_json_schema(src_json);
    }

    /// Action with same name as an entity type is allowed
    #[test]
    fn action_entity_conflict() {
        let src = "
            action A;
            action B; // same name as an entity type in same (empty) namespace
            action C; // same name as an entity type in different (nonempty) namespace
            entity B;
            entity E;
            namespace NS1 {
                entity C;
                entity User { b: B, c: C, e: E };
            }
            namespace NS2 {
                entity D;
                action D; // same name as an entity type in same (nonempty) namespace
                action E; // same name as an entity type in different (empty) namespace
                entity User { b: B, d: D, e: E };
            }
        ";
        assert_valid_cedar_schema(src);

        let src_json = json!({
            "": {
                "entityTypes": {
                    "B": {},
                    "E": {},
                },
                "actions": {
                    "A": {},
                    "B": {},
                    "C": {},
                },
            },
            "NS1": {
                "entityTypes": {
                    "C": {},
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "b": { "type": "Entity", "name": "B" },
                                "c": { "type": "Entity", "name": "C" },
                                "e": { "type": "Entity", "name": "E" },
                            }
                        }
                    },
                },
                "actions": {}
            },
            "NS2": {
                "entityTypes": {
                    "D": {},
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "b": { "type": "Entity", "name": "B" },
                                "d": { "type": "Entity", "name": "D" },
                                "e": { "type": "Entity", "name": "E" },
                            }
                        }
                    }
                },
                "actions": {
                    "D": {},
                    "E": {},
                }
            }
        });
        assert_valid_json_schema(src_json);
    }

    /// Common type shadowing an entity type in the same namespace is allowed.
    /// In the JSON syntax, but not the Cedar syntax, you can even define
    /// `entity T; type T = T;`. (In the Cedar syntax, there's no way to specify
    /// that the RHS `T` should refer to the entity type, but in the JSON syntax
    /// there is.)
    #[test]
    fn common_shadowing_entity_same_namespace() {
        let src = "
            entity T;
            type T = Bool; // works in the empty namespace
            namespace NS {
                entity E;
                type E = Bool; // works in a nonempty namespace
            }
        ";
        assert_valid_cedar_schema(src);

        let src_json = json!({
            "": {
                "commonTypes": {
                    "T": { "type": "Entity", "name": "T" },
                },
                "entityTypes": {
                    "T": {},
                },
                "actions": {}
            },
            "NS1": {
                "commonTypes": {
                    "E": { "type": "Entity", "name": "E" },
                },
                "entityTypes": {
                    "E": {},
                },
                "actions": {}
            },
            "NS2": {
                "commonTypes": {
                    "E": { "type": "String" },
                },
                "entityTypes": {
                    "E": {},
                },
                "actions": {}
            }
        });
        assert_valid_json_schema(src_json);
    }

    /// Common type shadowing a JSON schema primitive type is disallowed per #1139;
    /// you can still refer to the primitive type using __cedar
    #[test]
    fn common_shadowing_primitive() {
        let src = "
            type String = Long;
            entity E {
                a: String,
                b: __cedar::String,
                c: Long,
                d: __cedar::Long,
            };
            namespace NS {
                type Bool = Long;
                entity F {
                    a: Bool,
                    b: __cedar::Bool,
                    c: Long,
                    d: __cedar::Long,
                };
            }
        ";
        assert_invalid_cedar_schema(src);
        let src = "
            type _String = Long;
            entity E {
                a: _String,
                b: __cedar::String,
                c: Long,
                d: __cedar::Long,
            };
            namespace NS {
                type _Bool = Long;
                entity F {
                    a: _Bool,
                    b: __cedar::Bool,
                    c: Long,
                    d: __cedar::Long,
                };
            }
        ";
        let schema = assert_valid_cedar_schema(src);
        let e = assert_entity_type_exists(&schema, "E");
        assert_matches!(e.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long()); // using the common type definition
        });
        assert_matches!(e.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_string());
        });
        assert_matches!(e.attr("c"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
        assert_matches!(e.attr("d"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
        let f = assert_entity_type_exists(&schema, "NS::F");
        assert_matches!(f.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long()); // using the common type definition
        });
        assert_matches!(f.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_boolean());
        });
        assert_matches!(f.attr("c"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
        assert_matches!(f.attr("d"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });

        let src_json = json!({
            "": {
                "commonTypes": {
                    "String": { "type": "Long" },
                },
                "entityTypes": {
                    "E": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": { "type": "String" },
                                "b": { "type": "__cedar::String" },
                                "c": { "type": "Long" },
                                "d": { "type": "__cedar::Long" },
                            }
                        }
                    },
                },
                "actions": {}
            },
            "NS": {
                "commonTypes": {
                    "Bool": { "type": "Long" },
                },
                "entityTypes": {
                    "F": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": { "type": "Bool" },
                                "b": { "type": "__cedar::Bool" },
                                "c": { "type": "Long" },
                                "d": { "type": "__cedar::Long" },
                            }
                        }
                    },
                },
                "actions": {}
            }
        });
        assert_invalid_json_schema(&src_json);
        let src_json = json!({
            "": {
                "commonTypes": {
                    "_String": { "type": "Long" },
                },
                "entityTypes": {
                    "E": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": { "type": "_String" },
                                "b": { "type": "__cedar::String" },
                                "c": { "type": "Long" },
                                "d": { "type": "__cedar::Long" },
                            }
                        }
                    },
                },
                "actions": {}
            },
            "NS": {
                "commonTypes": {
                    "_Bool": { "type": "Long" },
                },
                "entityTypes": {
                    "F": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": { "type": "_Bool" },
                                "b": { "type": "__cedar::Bool" },
                                "c": { "type": "Long" },
                                "d": { "type": "__cedar::Long" },
                            }
                        }
                    },
                },
                "actions": {}
            }
        });
        let schema = assert_valid_json_schema(src_json);
        let e = assert_entity_type_exists(&schema, "E");
        assert_matches!(e.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
        assert_matches!(e.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_string());
        });
        assert_matches!(e.attr("c"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
        assert_matches!(e.attr("d"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
        let f = assert_entity_type_exists(&schema, "NS::F");
        assert_matches!(f.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long()); // using the common type definition
        });
        assert_matches!(f.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_boolean());
        });
        assert_matches!(f.attr("c"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
        assert_matches!(f.attr("d"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
    }

    /// Common type shadowing an extension type is allowed;
    /// you can still refer to the extension type using __cedar
    #[test]
    fn common_shadowing_extension() {
        let src = "
            type ipaddr = Long;
            entity E {
                a: ipaddr,
                b: __cedar::ipaddr,
                c: Long,
                d: __cedar::Long,
            };
            namespace NS {
                type decimal = Long;
                entity F {
                    a: decimal,
                    b: __cedar::decimal,
                    c: Long,
                    d: __cedar::Long,
                };
            }
        ";
        let schema = assert_valid_cedar_schema(src);
        let e = assert_entity_type_exists(&schema, "E");
        assert_matches!(e.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long()); // using the common type definition
        });
        assert_matches!(e.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::extension("ipaddr".parse().unwrap()));
        });
        assert_matches!(e.attr("c"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
        assert_matches!(e.attr("d"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
        let f = assert_entity_type_exists(&schema, "NS::F");
        assert_matches!(f.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long()); // using the common type definition
        });
        assert_matches!(f.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::extension("decimal".parse().unwrap()));
        });
        assert_matches!(f.attr("c"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
        assert_matches!(f.attr("d"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });

        let src_json = json!({
            "": {
                "commonTypes": {
                    "ipaddr": { "type": "Long" },
                },
                "entityTypes": {
                    "E": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": { "type": "ipaddr" },
                                "b": { "type": "__cedar::ipaddr" },
                                "c": { "type": "Long" },
                                "d": { "type": "__cedar::Long" },
                            }
                        }
                    },
                },
                "actions": {}
            },
            "NS": {
                "commonTypes": {
                    "decimal": { "type": "Long" },
                },
                "entityTypes": {
                    "F": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": { "type": "decimal" },
                                "b": { "type": "__cedar::decimal" },
                                "c": { "type": "Long" },
                                "d": { "type": "__cedar::Long" },
                            }
                        }
                    },
                },
                "actions": {}
            }
        });
        let schema = assert_valid_json_schema(src_json);
        let e = assert_entity_type_exists(&schema, "E");
        assert_matches!(e.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long()); // using the common type definition
        });
        assert_matches!(e.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::extension("ipaddr".parse().unwrap()));
        });
        assert_matches!(e.attr("c"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
        assert_matches!(e.attr("d"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
        let f = assert_entity_type_exists(&schema, "NS::F");
        assert_matches!(f.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long()); // using the common type definition
        });
        assert_matches!(f.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::extension("decimal".parse().unwrap()));
        });
        assert_matches!(f.attr("c"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
        assert_matches!(f.attr("d"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_long());
        });
    }

    /// Entity type shadowing a primitive type is allowed;
    /// you can still refer to the primitive type using __cedar
    #[test]
    fn entity_shadowing_primitive() {
        let src = "
            entity String;
            entity E {
                a: String,
                b: __cedar::String,
            };
            namespace NS {
                entity Bool;
                entity F {
                    a: Bool,
                    b: __cedar::Bool,
                };
            }
        ";
        let schema = assert_valid_cedar_schema(src);
        let e = assert_entity_type_exists(&schema, "E");
        assert_matches!(e.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::named_entity_reference_from_str("String"));
        });
        assert_matches!(e.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_string());
        });
        let f = assert_entity_type_exists(&schema, "NS::F");
        assert_matches!(f.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::named_entity_reference_from_str("NS::Bool")); // using the common type definition
        });
        assert_matches!(f.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_boolean());
        });

        let src_json = json!({
            "": {
                "entityTypes": {
                    "String": {},
                    "E": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": { "type": "Entity", "name": "String" },
                                "b": { "type": "__cedar::String" },
                            }
                        }
                    },
                },
                "actions": {}
            },
            "NS": {
                "entityTypes": {
                    "Bool": {},
                    "F": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": { "type": "Entity", "name": "Bool" },
                                "b": { "type": "__cedar::Bool" },
                            }
                        }
                    },
                },
                "actions": {}
            }
        });
        let schema = assert_valid_json_schema(src_json);
        let e = assert_entity_type_exists(&schema, "E");
        assert_matches!(e.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::named_entity_reference_from_str("String"));
        });
        assert_matches!(e.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_string());
        });
        let f = assert_entity_type_exists(&schema, "NS::F");
        assert_matches!(f.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::named_entity_reference_from_str("NS::Bool"));
        });
        assert_matches!(f.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::primitive_boolean());
        });
    }

    /// Entity type shadowing an extension type is allowed;
    /// you can still refer to the extension type using __cedar
    #[test]
    fn entity_shadowing_extension() {
        let src = "
            entity ipaddr;
            entity E {
                a: ipaddr,
                b: __cedar::ipaddr,
            };
            namespace NS {
                entity decimal;
                entity F {
                    a: decimal,
                    b: __cedar::decimal,
                };
            }
        ";
        let schema = assert_valid_cedar_schema(src);
        let e = assert_entity_type_exists(&schema, "E");
        assert_matches!(e.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::named_entity_reference_from_str("ipaddr"));
        });
        assert_matches!(e.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::extension("ipaddr".parse().unwrap()));
        });
        let f = assert_entity_type_exists(&schema, "NS::F");
        assert_matches!(f.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::named_entity_reference_from_str("NS::decimal"));
        });
        assert_matches!(f.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::extension("decimal".parse().unwrap()));
        });

        let src_json = json!({
            "": {
                "entityTypes": {
                    "ipaddr": {},
                    "E": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": { "type": "Entity", "name": "ipaddr" },
                                "b": { "type": "__cedar::ipaddr" },
                            }
                        }
                    },
                },
                "actions": {}
            },
            "NS": {
                "entityTypes": {
                    "decimal": {},
                    "F": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "a": { "type": "Entity", "name": "decimal" },
                                "b": { "type": "__cedar::decimal" },
                            }
                        }
                    },
                },
                "actions": {}
            }
        });
        let schema = assert_valid_json_schema(src_json);
        let e = assert_entity_type_exists(&schema, "E");
        assert_matches!(e.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::named_entity_reference_from_str("ipaddr"));
        });
        assert_matches!(e.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::extension("ipaddr".parse().unwrap()));
        });
        let f = assert_entity_type_exists(&schema, "NS::F");
        assert_matches!(f.attr("a"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::named_entity_reference_from_str("NS::decimal"));
        });
        assert_matches!(f.attr("b"), Some(atype) => {
            assert_eq!(&atype.attr_type, &Type::extension("decimal".parse().unwrap()));
        });
    }
}

/// Tests involving entity tags (RFC 82)
#[cfg(test)]
#[allow(clippy::cognitive_complexity)]
mod entity_tags {
    use super::{test::utils::*, *};
    use crate::{
        extensions::Extensions,
        test_utils::{expect_err, ExpectedErrorMessageBuilder},
    };
    use cool_asserts::assert_matches;
    use serde_json::json;

    use crate::validator::types::Primitive;

    #[test]
    fn cedar_syntax_tags() {
        // This schema taken directly from the RFC 82 text
        let src = "
          entity User = {
            jobLevel: Long,
          } tags Set<String>;
          entity Document = {
            owner: User,
          } tags Set<String>;
        ";
        assert_matches!(collect_warnings(ValidatorSchema::from_cedarschema_str(src, Extensions::all_available())), Ok((schema, warnings)) => {
            assert!(warnings.is_empty());
            let user = assert_entity_type_exists(&schema, "User");
            assert_matches!(user.tag_type(), Some(Type::Set { element_type: Some(el_ty) }) => {
                assert_matches!(&**el_ty, Type::Primitive { primitive_type: Primitive::String });
            });
            let doc = assert_entity_type_exists(&schema, "Document");
            assert_matches!(doc.tag_type(), Some(Type::Set { element_type: Some(el_ty) }) => {
                assert_matches!(&**el_ty, Type::Primitive { primitive_type: Primitive::String });
            });
        });
    }

    #[test]
    fn json_syntax_tags() {
        // This schema taken directly from the RFC 82 text
        let json = json!({"": {
            "entityTypes": {
                "User" : {
                    "shape" : {
                        "type" : "Record",
                        "attributes" : {
                            "jobLevel" : {
                                "type" : "Long"
                            },
                        }
                    },
                    "tags" : {
                        "type" : "Set",
                        "element": { "type": "String" }
                    }
                },
                "Document" : {
                    "shape" : {
                        "type" : "Record",
                        "attributes" : {
                            "owner" : {
                                "type" : "Entity",
                                "name" : "User"
                            },
                        }
                    },
                    "tags" : {
                      "type" : "Set",
                      "element": { "type": "String" }
                    }
                }
            },
            "actions": {}
        }});
        assert_matches!(ValidatorSchema::from_json_value(json, Extensions::all_available()), Ok(schema) => {
            let user = assert_entity_type_exists(&schema, "User");
            assert_matches!(user.tag_type(), Some(Type::Set { element_type: Some(el_ty) }) => {
                assert_matches!(&**el_ty, Type::Primitive { primitive_type: Primitive::String });
            });
            let doc = assert_entity_type_exists(&schema, "Document");
            assert_matches!(doc.tag_type(), Some(Type::Set { element_type: Some(el_ty) }) => {
                assert_matches!(&**el_ty, Type::Primitive { primitive_type: Primitive::String });
            });
        });
    }

    #[test]
    fn other_tag_types() {
        let src = "
            entity E;
            type Blah = {
                foo: Long,
                bar: Set<E>,
            };
            entity Foo1 in E {
                bool: Bool,
            } tags Bool;
            entity Foo2 in E {
                bool: Bool,
            } tags { bool: Bool };
            entity Foo3 in E tags E;
            entity Foo4 in E tags Set<E>;
            entity Foo5 in E tags { a: String, b: Long };
            entity Foo6 in E tags Blah;
            entity Foo7 in E tags Set<Set<{a: Blah}>>;
            entity Foo8 in E tags Foo7;
        ";
        assert_matches!(collect_warnings(ValidatorSchema::from_cedarschema_str(src, Extensions::all_available())), Ok((schema, warnings)) => {
            assert!(warnings.is_empty());
            let e = assert_entity_type_exists(&schema, "E");
            assert_matches!(e.tag_type(), None);
            let foo1 = assert_entity_type_exists(&schema, "Foo1");
            assert_matches!(foo1.tag_type(), Some(Type::Primitive { primitive_type: Primitive::Bool }));
            let foo2 = assert_entity_type_exists(&schema, "Foo2");
            assert_matches!(foo2.tag_type(), Some(Type::EntityOrRecord(EntityRecordKind::Record { .. })));
            let foo3 = assert_entity_type_exists(&schema, "Foo3");
            assert_matches!(foo3.tag_type(), Some(Type::EntityOrRecord(EntityRecordKind::Entity(_))));
            let foo4 = assert_entity_type_exists(&schema, "Foo4");
            assert_matches!(foo4.tag_type(), Some(Type::Set { element_type }) => assert_matches!(element_type.as_deref(), Some(Type::EntityOrRecord(EntityRecordKind::Entity(_)))));
            let foo5 = assert_entity_type_exists(&schema, "Foo5");
            assert_matches!(foo5.tag_type(), Some(Type::EntityOrRecord(EntityRecordKind::Record { .. })));
            let foo6 = assert_entity_type_exists(&schema, "Foo6");
            assert_matches!(foo6.tag_type(), Some(Type::EntityOrRecord(EntityRecordKind::Record { .. })));
            let foo7 = assert_entity_type_exists(&schema, "Foo7");
            assert_matches!(foo7.tag_type(), Some(Type::Set { element_type }) => assert_matches!(element_type.as_deref(), Some(Type::Set { element_type }) => assert_matches!(element_type.as_deref(), Some(Type::EntityOrRecord(EntityRecordKind::Record { .. })))));
            let foo8 = assert_entity_type_exists(&schema, "Foo8");
            assert_matches!(foo8.tag_type(), Some(Type::EntityOrRecord(EntityRecordKind::Entity(_))));
        });
    }

    #[test]
    fn invalid_tags() {
        let src = "entity E tags Undef;";
        assert_matches!(collect_warnings(ValidatorSchema::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("failed to resolve type: Undef")
                    .help("`Undef` has not been declared as a common or entity type")
                    .exactly_one_underline("Undef")
                    .build(),
            );
        });
    }
}

#[cfg(test)]
mod test_resolver {
    use std::collections::HashMap;

    use crate::{ast::InternalName, extensions::Extensions};
    use cool_asserts::assert_matches;

    use super::{AllDefs, CommonTypeResolver, ValidatorType};
    use crate::validator::{
        err::SchemaError, json_schema, types::Type, ConditionalName, ValidatorSchemaFragment,
    };

    fn resolve(
        schema_json: serde_json::Value,
    ) -> Result<HashMap<InternalName, ValidatorType>, SchemaError> {
        let sfrag = json_schema::Fragment::from_json_value(schema_json).unwrap();
        let schema: ValidatorSchemaFragment<ConditionalName, ConditionalName> =
            sfrag.try_into().unwrap();
        let all_defs = AllDefs::single_fragment(&schema);
        let schema = schema.fully_qualify_type_references(&all_defs).unwrap();
        let mut defs = HashMap::new();
        for def in schema.0 {
            defs.extend(def.common_types.defs.into_iter());
        }
        let resolver = CommonTypeResolver::new(&defs);
        resolver
            .resolve(Extensions::all_available())
            .map(|map| map.into_iter().map(|(k, v)| (k.clone(), v)).collect())
    }

    #[test]
    fn test_simple() {
        let schema = serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "b"
                        },
                        "b": {
                            "type": "Boolean"
                        }
                    }
                }
            }
        );
        let res = resolve(schema).unwrap();
        assert_eq!(
            res,
            HashMap::from_iter([
                (
                    "a".parse().unwrap(),
                    ValidatorType::new(Type::primitive_boolean())
                ),
                (
                    "b".parse().unwrap(),
                    ValidatorType::new(Type::primitive_boolean())
                )
            ])
        );

        let schema = serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "b"
                        },
                        "b": {
                            "type": "c"
                        },
                        "c": {
                            "type": "Boolean"
                        }
                    }
                }
            }
        );
        let res = resolve(schema).unwrap();
        assert_eq!(
            res,
            HashMap::from_iter([
                (
                    "a".parse().unwrap(),
                    ValidatorType::new(Type::primitive_boolean())
                ),
                (
                    "b".parse().unwrap(),
                    ValidatorType::new(Type::primitive_boolean())
                ),
                (
                    "c".parse().unwrap(),
                    ValidatorType::new(Type::primitive_boolean())
                )
            ])
        );
    }

    #[test]
    fn test_set() {
        let schema = serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "Set",
                            "element": {
                                "type": "b"
                            }
                        },
                        "b": {
                            "type": "Boolean"
                        }
                    }
                }
            }
        );
        let res = resolve(schema).unwrap();
        assert_eq!(
            res,
            HashMap::from_iter([
                (
                    "a".parse().unwrap(),
                    ValidatorType::new(Type::set(Type::primitive_boolean()))
                ),
                (
                    "b".parse().unwrap(),
                    ValidatorType::new(Type::primitive_boolean())
                )
            ])
        );
    }

    #[test]
    fn test_record() {
        let schema = serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "Record",
                            "attributes": {
                                "foo": {
                                    "type": "b"
                                }
                            }
                        },
                        "b": {
                            "type": "Boolean"
                        }
                    }
                }
            }
        );
        let res = resolve(schema).unwrap();
        assert_eq!(
            res,
            HashMap::from_iter([
                (
                    "a".parse().unwrap(),
                    ValidatorType::new(Type::record_with_required_attributes(
                        [("foo".into(), Type::primitive_boolean())],
                        crate::validator::types::OpenTag::ClosedAttributes
                    ))
                ),
                (
                    "b".parse().unwrap(),
                    ValidatorType::new(Type::primitive_boolean())
                )
            ])
        );
    }

    #[test]
    fn test_names() {
        let schema = serde_json::json!(
            {
                "A": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "B::a"
                        }
                    }
                },
                "B": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "Boolean"
                        }
                    }
                }
            }
        );
        let res = resolve(schema).unwrap();
        assert_eq!(
            res,
            HashMap::from_iter([
                (
                    "A::a".parse().unwrap(),
                    ValidatorType::new(Type::primitive_boolean())
                ),
                (
                    "B::a".parse().unwrap(),
                    ValidatorType::new(Type::primitive_boolean())
                )
            ])
        );
    }

    #[test]
    fn test_cycles() {
        // self reference
        let schema = serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "a"
                        }
                    }
                }
            }
        );
        let res = resolve(schema);
        assert_matches!(res, Err(SchemaError::CycleInCommonTypeReferences(_)));

        // 2 node loop
        let schema = serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "b"
                        },
                        "b" : {
                            "type": "a"
                        }
                    }
                }
            }
        );
        let res = resolve(schema);
        assert_matches!(res, Err(SchemaError::CycleInCommonTypeReferences(_)));

        // 3 node loop
        let schema = serde_json::json!(
            {
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "b"
                        },
                        "b" : {
                            "type": "c"
                        },
                        "c" : {
                            "type": "a"
                        }
                    }
                }
            }
        );
        let res = resolve(schema);
        assert_matches!(res, Err(SchemaError::CycleInCommonTypeReferences(_)));

        // cross-namespace 2 node loop
        let schema = serde_json::json!(
            {
                "A": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "B::a"
                        }
                    }
                },
                "B": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "A::a"
                        }
                    }
                }
            }
        );
        let res = resolve(schema);
        assert_matches!(res, Err(SchemaError::CycleInCommonTypeReferences(_)));

        // cross-namespace 3 node loop
        let schema = serde_json::json!(
            {
                "A": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "B::a"
                        }
                    }
                },
                "B": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "C::a"
                        }
                    }
                },
                "C": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "A::a"
                        }
                    }
                }
            }
        );
        let res = resolve(schema);
        assert_matches!(res, Err(SchemaError::CycleInCommonTypeReferences(_)));

        // cross-namespace 3 node loop
        let schema = serde_json::json!(
            {
                "A": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "B::a"
                        }
                    }
                },
                "B": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "a" : {
                            "type": "c"
                        },
                        "c": {
                            "type": "A::a"
                        }
                    }
                }
            }
        );
        let res = resolve(schema);
        assert_matches!(res, Err(SchemaError::CycleInCommonTypeReferences(_)));
    }
}

#[cfg(test)]
mod test_access {
    use super::*;

    fn schema() -> ValidatorSchema {
        let src = r#"
        type Task = {
    "id": Long,
    "name": String,
    "state": String,
};

type Tasks = Set<Task>;
entity List in [Application] = {
  "editors": Team,
  "name": String,
  "owner": User,
  "readers": Team,
  "tasks": Tasks,
};
entity Application;
entity User in [Team, Application] = {
  "joblevel": Long,
  "location": String,
};

entity CoolList;

entity Team in [Team, Application];

action Read, Write, Create;

action DeleteList, EditShare, UpdateList, CreateTask, UpdateTask, DeleteTask in Write appliesTo {
    principal: [User],
    resource : [List]
};

action GetList in Read appliesTo {
    principal : [User],
    resource : [List, CoolList]
};

action GetLists in Read appliesTo {
    principal : [User],
    resource : [Application]
};

action CreateList in Create appliesTo {
    principal : [User],
    resource : [Application]
};

        "#;

        src.parse().unwrap()
    }

    #[test]
    fn principals() {
        let schema = schema();
        let principals = schema.principals().collect::<HashSet<_>>();
        assert_eq!(principals.len(), 1);
        let user: EntityType = "User".parse().unwrap();
        assert!(principals.contains(&user));
        let principals = schema.principals().collect::<Vec<_>>();
        assert!(principals.len() > 1);
        assert!(principals.iter().all(|ety| **ety == user));
    }

    #[test]
    fn empty_schema_principals_and_resources() {
        let empty: ValidatorSchema = "".parse().unwrap();
        assert!(empty.principals().next().is_none());
        assert!(empty.resources().next().is_none());
    }

    #[test]
    fn resources() {
        let schema = schema();
        let resources = schema.resources().cloned().collect::<HashSet<_>>();
        let expected: HashSet<EntityType> = HashSet::from([
            "List".parse().unwrap(),
            "Application".parse().unwrap(),
            "CoolList".parse().unwrap(),
        ]);
        assert_eq!(resources, expected);
    }

    #[test]
    fn principals_for_action() {
        let schema = schema();
        let delete_list: EntityUID = r#"Action::"DeleteList""#.parse().unwrap();
        let delete_user: EntityUID = r#"Action::"DeleteUser""#.parse().unwrap();
        let got = schema
            .principals_for_action(&delete_list)
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(got, vec!["User".parse().unwrap()]);
        assert!(schema.principals_for_action(&delete_user).is_none());
    }

    #[test]
    fn resources_for_action() {
        let schema = schema();
        let delete_list: EntityUID = r#"Action::"DeleteList""#.parse().unwrap();
        let delete_user: EntityUID = r#"Action::"DeleteUser""#.parse().unwrap();
        let create_list: EntityUID = r#"Action::"CreateList""#.parse().unwrap();
        let get_list: EntityUID = r#"Action::"GetList""#.parse().unwrap();
        let got = schema
            .resources_for_action(&delete_list)
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(got, vec!["List".parse().unwrap()]);
        let got = schema
            .resources_for_action(&create_list)
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(got, vec!["Application".parse().unwrap()]);
        let got = schema
            .resources_for_action(&get_list)
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(
            got,
            HashSet::from(["List".parse().unwrap(), "CoolList".parse().unwrap()])
        );
        assert!(schema.principals_for_action(&delete_user).is_none());
    }

    #[test]
    fn principal_parents() {
        let schema = schema();
        let user: EntityType = "User".parse().unwrap();
        let parents = schema
            .ancestors(&user)
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        let expected = HashSet::from(["Team".parse().unwrap(), "Application".parse().unwrap()]);
        assert_eq!(parents, expected);
        let parents = schema
            .ancestors(&"List".parse().unwrap())
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        let expected = HashSet::from(["Application".parse().unwrap()]);
        assert_eq!(parents, expected);
        assert!(schema.ancestors(&"Foo".parse().unwrap()).is_none());
        let parents = schema
            .ancestors(&"CoolList".parse().unwrap())
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        let expected = HashSet::from([]);
        assert_eq!(parents, expected);
    }

    #[test]
    fn action_groups() {
        let schema = schema();
        let groups = schema.action_groups().cloned().collect::<HashSet<_>>();
        let expected = ["Read", "Write", "Create"]
            .into_iter()
            .map(|ty| format!("Action::\"{ty}\"").parse().unwrap())
            .collect::<HashSet<EntityUID>>();
        assert_eq!(groups, expected);
    }

    #[test]
    fn actions() {
        let schema = schema();
        let actions = schema.actions().cloned().collect::<HashSet<_>>();
        let expected = [
            "Read",
            "Write",
            "Create",
            "DeleteList",
            "EditShare",
            "UpdateList",
            "CreateTask",
            "UpdateTask",
            "DeleteTask",
            "GetList",
            "GetLists",
            "CreateList",
        ]
        .into_iter()
        .map(|ty| format!("Action::\"{ty}\"").parse().unwrap())
        .collect::<HashSet<EntityUID>>();
        assert_eq!(actions, expected);
    }

    #[test]
    fn entities() {
        let schema = schema();
        let entities = schema
            .entity_types()
            .map(ValidatorEntityType::name)
            .cloned()
            .collect::<HashSet<_>>();
        let expected = ["List", "Application", "User", "CoolList", "Team"]
            .into_iter()
            .map(|ty| ty.parse().unwrap())
            .collect::<HashSet<EntityType>>();
        assert_eq!(entities, expected);
    }
}

#[cfg(test)]
mod test_access_namespace {
    use super::*;

    fn schema() -> ValidatorSchema {
        let src = r#"
        namespace Foo {
        type Task = {
    "id": Long,
    "name": String,
    "state": String,
};

type Tasks = Set<Task>;
entity List in [Application] = {
  "editors": Team,
  "name": String,
  "owner": User,
  "readers": Team,
  "tasks": Tasks,
};
entity Application;
entity User in [Team, Application] = {
  "joblevel": Long,
  "location": String,
};

entity CoolList;

entity Team in [Team, Application];

action Read, Write, Create;

action DeleteList, EditShare, UpdateList, CreateTask, UpdateTask, DeleteTask in Write appliesTo {
    principal: [User],
    resource : [List]
};

action GetList in Read appliesTo {
    principal : [User],
    resource : [List, CoolList]
};

action GetLists in Read appliesTo {
    principal : [User],
    resource : [Application]
};

action CreateList in Create appliesTo {
    principal : [User],
    resource : [Application]
};
    }

        "#;

        src.parse().unwrap()
    }

    #[test]
    fn principals() {
        let schema = schema();
        let principals = schema.principals().collect::<HashSet<_>>();
        assert_eq!(principals.len(), 1);
        let user: EntityType = "Foo::User".parse().unwrap();
        assert!(principals.contains(&user));
        let principals = schema.principals().collect::<Vec<_>>();
        assert!(principals.len() > 1);
        assert!(principals.iter().all(|ety| **ety == user));
    }

    #[test]
    fn empty_schema_principals_and_resources() {
        let empty: ValidatorSchema = "".parse().unwrap();
        assert!(empty.principals().next().is_none());
        assert!(empty.resources().next().is_none());
    }

    #[test]
    fn resources() {
        let schema = schema();
        let resources = schema.resources().cloned().collect::<HashSet<_>>();
        let expected: HashSet<EntityType> = HashSet::from([
            "Foo::List".parse().unwrap(),
            "Foo::Application".parse().unwrap(),
            "Foo::CoolList".parse().unwrap(),
        ]);
        assert_eq!(resources, expected);
    }

    #[test]
    fn principals_for_action() {
        let schema = schema();
        let delete_list: EntityUID = r#"Foo::Action::"DeleteList""#.parse().unwrap();
        let delete_user: EntityUID = r#"Foo::Action::"DeleteUser""#.parse().unwrap();
        let got = schema
            .principals_for_action(&delete_list)
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(got, vec!["Foo::User".parse().unwrap()]);
        assert!(schema.principals_for_action(&delete_user).is_none());
    }

    #[test]
    fn resources_for_action() {
        let schema = schema();
        let delete_list: EntityUID = r#"Foo::Action::"DeleteList""#.parse().unwrap();
        let delete_user: EntityUID = r#"Foo::Action::"DeleteUser""#.parse().unwrap();
        let create_list: EntityUID = r#"Foo::Action::"CreateList""#.parse().unwrap();
        let get_list: EntityUID = r#"Foo::Action::"GetList""#.parse().unwrap();
        let got = schema
            .resources_for_action(&delete_list)
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(got, vec!["Foo::List".parse().unwrap()]);
        let got = schema
            .resources_for_action(&create_list)
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(got, vec!["Foo::Application".parse().unwrap()]);
        let got = schema
            .resources_for_action(&get_list)
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(
            got,
            HashSet::from([
                "Foo::List".parse().unwrap(),
                "Foo::CoolList".parse().unwrap()
            ])
        );
        assert!(schema.principals_for_action(&delete_user).is_none());
    }

    #[test]
    fn principal_parents() {
        let schema = schema();
        let user: EntityType = "Foo::User".parse().unwrap();
        let parents = schema
            .ancestors(&user)
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        let expected = HashSet::from([
            "Foo::Team".parse().unwrap(),
            "Foo::Application".parse().unwrap(),
        ]);
        assert_eq!(parents, expected);
        let parents = schema
            .ancestors(&"Foo::List".parse().unwrap())
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        let expected = HashSet::from(["Foo::Application".parse().unwrap()]);
        assert_eq!(parents, expected);
        assert!(schema.ancestors(&"Foo::Foo".parse().unwrap()).is_none());
        let parents = schema
            .ancestors(&"Foo::CoolList".parse().unwrap())
            .unwrap()
            .cloned()
            .collect::<HashSet<_>>();
        let expected = HashSet::from([]);
        assert_eq!(parents, expected);
    }

    #[test]
    fn action_groups() {
        let schema = schema();
        let groups = schema.action_groups().cloned().collect::<HashSet<_>>();
        let expected = ["Read", "Write", "Create"]
            .into_iter()
            .map(|ty| format!("Foo::Action::\"{ty}\"").parse().unwrap())
            .collect::<HashSet<EntityUID>>();
        assert_eq!(groups, expected);
    }

    #[test]
    fn actions() {
        let schema = schema();
        let actions = schema.actions().cloned().collect::<HashSet<_>>();
        let expected = [
            "Read",
            "Write",
            "Create",
            "DeleteList",
            "EditShare",
            "UpdateList",
            "CreateTask",
            "UpdateTask",
            "DeleteTask",
            "GetList",
            "GetLists",
            "CreateList",
        ]
        .into_iter()
        .map(|ty| format!("Foo::Action::\"{ty}\"").parse().unwrap())
        .collect::<HashSet<EntityUID>>();
        assert_eq!(actions, expected);
    }

    #[test]
    fn entities() {
        let schema = schema();
        let entities = schema
            .entity_types()
            .map(ValidatorEntityType::name)
            .cloned()
            .collect::<HashSet<_>>();
        let expected = [
            "Foo::List",
            "Foo::Application",
            "Foo::User",
            "Foo::CoolList",
            "Foo::Team",
        ]
        .into_iter()
        .map(|ty| ty.parse().unwrap())
        .collect::<HashSet<EntityType>>();
        assert_eq!(entities, expected);
    }
}
