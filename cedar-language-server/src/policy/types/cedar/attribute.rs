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

use std::{collections::BTreeMap, fmt::Display, hash::Hash, sync::Arc};

use cedar_policy_core::validator::{types::AttributeType, ValidatorSchema};
use smol_str::{format_smolstr, SmolStr, ToSmolStr};

use crate::documentation::ToDocumentationString;

use super::CedarTypeKind;

/// Represents a record type in the Cedar type system.
///
/// A record is a collection of named attributes with potentially different types.
/// In Cedar policies, records can appear in several contexts:
/// - As literal values: `{ "name": "Alice", "age": 30 }`
/// - As attribute values of entities or context objects
/// - As intermediate results of expressions
///
/// This structure maintains a mapping from attribute names to their type information,
/// which is used for type checking and providing auto-completion suggestions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Record {
    /// The mapping of attribute names to their attribute information.
    ///
    /// This field stores all attributes available on the record, including
    /// their types, required, and source locations.
    pub(crate) attrs: Arc<BTreeMap<SmolStr, Attribute>>,
}

impl Record {
    #[must_use]
    pub(crate) fn attr(&self, attr: &str) -> Option<&Attribute> {
        self.attrs.get(attr)
    }
}

impl From<Arc<BTreeMap<SmolStr, Attribute>>> for Record {
    fn from(value: Arc<BTreeMap<SmolStr, Attribute>>) -> Self {
        Self { attrs: value }
    }
}

/// Represents metadata about an attribute in the Cedar type system.
///
/// Attributes are named properties that can be accessed on entities, records,
/// and context objects in Cedar policies. This structure captures information
/// about an attribute's name, type, whether it's required, and its location
/// in the source code.
///
/// Attributes appear in Cedar policies in expressions like:
/// - `principal.department`
/// - `resource has owner`
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub(crate) struct Attribute {
    /// The name of the attribute.
    name: SmolStr,
    /// Whether the attribute is required to be present on its parent object.
    ///
    /// Required attributes must always have a value, while optional attributes
    /// might not be present.
    required: bool,
    /// The Cedar type of the attribute's value, if known.
    ///
    /// This represents what kind of value the attribute holds and is used
    /// for type checking and auto-completion of nested expressions.
    cedar_type: Option<CedarTypeKind>,
}

impl Attribute {
    #[must_use]
    pub(crate) fn new(name: SmolStr, required: bool, cedar_type: Option<CedarTypeKind>) -> Self {
        Self {
            name,
            required,
            cedar_type,
        }
    }

    #[must_use]
    pub(crate) fn cedar_type(&self) -> Option<CedarTypeKind> {
        self.cedar_type.clone()
    }

    #[must_use]
    pub(crate) fn to_label(&self) -> SmolStr {
        if self.required {
            self.name.clone()
        } else {
            format_smolstr!("{}?", self.name)
        }
    }

    #[must_use]
    pub(crate) fn name(&self) -> SmolStr {
        self.name.clone()
    }

    #[must_use]
    pub(crate) fn detail(&self) -> SmolStr {
        self.cedar_type()
            .map_or_else(|| self.name(), |cedar_type| cedar_type.to_smolstr())
    }
}

impl ToDocumentationString for Attribute {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> String {
        self.cedar_type().map_or_else(
            || self.name().to_string(),
            |cedar_type| cedar_type.to_documentation_string(schema),
        )
    }
}

impl Display for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.cedar_type() {
            Some(ct) => write!(f, "{ct}"),
            None => write!(f, "{}", self.name()),
        }
    }
}

impl<N> From<(N, AttributeType)> for Attribute
where
    N: ToSmolStr,
{
    fn from((name, attr): (N, AttributeType)) -> Self {
        Self::new(
            name.to_smolstr(),
            attr.is_required(),
            Some(attr.attr_type.into()),
        )
    }
}

impl<N> From<(N, &AttributeType)> for Attribute
where
    N: ToSmolStr,
{
    fn from((name, attr): (N, &AttributeType)) -> Self {
        Self::new(
            name.to_smolstr(),
            attr.is_required(),
            Some(attr.attr_type.clone().into()),
        )
    }
}
