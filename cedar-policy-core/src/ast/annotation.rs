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

use std::collections::BTreeMap;

use educe::Educe;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::parser::MaybeLoc;

use super::AnyId;

/// Struct which holds the annotations for a policy
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Annotations(BTreeMap<AnyId, Annotation>);

impl std::fmt::Display for Annotations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (k, v) in &self.0 {
            writeln!(f, "@{k}({v})")?
        }
        Ok(())
    }
}

impl Annotations {
    /// Create a new empty `Annotations` (with no annotations)
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Get an annotation by key
    pub fn get(&self, key: &AnyId) -> Option<&Annotation> {
        self.0.get(key)
    }

    /// Iterate over all annotations
    pub fn iter(&self) -> impl Iterator<Item = (&AnyId, &Annotation)> {
        self.0.iter()
    }

    /// Tell if it's empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Wraps the [`BTreeMap`] into an opaque type so we can change it later if need be
#[derive(Debug)]
pub struct IntoIter(std::collections::btree_map::IntoIter<AnyId, Annotation>);

impl Iterator for IntoIter {
    type Item = (AnyId, Annotation);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl IntoIterator for Annotations {
    type Item = (AnyId, Annotation);

    type IntoIter = IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self.0.into_iter())
    }
}

impl Default for Annotations {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<(AnyId, Annotation)> for Annotations {
    fn from_iter<T: IntoIterator<Item = (AnyId, Annotation)>>(iter: T) -> Self {
        Self(BTreeMap::from_iter(iter))
    }
}

impl From<BTreeMap<AnyId, Annotation>> for Annotations {
    fn from(value: BTreeMap<AnyId, Annotation>) -> Self {
        Self(value)
    }
}

/// Struct which holds the value of a particular annotation
#[derive(Educe, Clone, Debug, Serialize, Deserialize, Default)]
#[educe(Hash, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct Annotation {
    /// Annotation value
    pub val: SmolStr,
    /// Source location. Note this is the location of _the entire key-value
    /// pair_ for the annotation, not just `val` above
    #[serde(skip)]
    #[educe(Hash(ignore))]
    #[educe(PartialEq(ignore))]
    #[educe(PartialOrd(ignore))]
    pub loc: MaybeLoc,
}

impl std::fmt::Display for Annotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self.val.escape_debug())
    }
}

impl Annotation {
    /// Construct an Annotation with an optional value.  This function is used
    /// to construct annotations from the CST and EST representation where a
    /// value is not required, but an absent value is equivalent to `""`.
    /// Here, a `None` constructs an annotation containing the value `""`.`
    pub fn with_optional_value(val: Option<SmolStr>, loc: MaybeLoc) -> Self {
        Self {
            val: val.unwrap_or_default(),
            loc,
        }
    }
}

impl AsRef<str> for Annotation {
    fn as_ref(&self) -> &str {
        &self.val
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Annotation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            val: u.arbitrary::<&str>()?.into(),
            loc: None,
        })
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        <&str as arbitrary::Arbitrary>::size_hint(depth)
    }
}
