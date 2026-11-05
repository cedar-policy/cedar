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

//! Depth of JSON schema types once common types are inlined

use std::collections::HashMap;
use std::hash::Hash;

use super::json_schema::{Type, TypeVariant};

/// The depth of `ty` once common types are inlined, given the depth of each
/// common type, computed without inlining
pub(crate) fn type_depth<N: Eq + Hash>(
    ty: &Type<N>,
    common_type_depths: &HashMap<&N, usize>,
) -> usize {
    let mut max = 0;
    let mut stack = vec![(ty, 0)];
    while let Some((ty, depth)) = stack.pop() {
        let leaf_depth = match ty {
            Type::Type { ty: variant, .. } => match variant {
                TypeVariant::String
                | TypeVariant::Long
                | TypeVariant::Boolean
                | TypeVariant::Entity { .. }
                | TypeVariant::Extension { .. } => 0,
                TypeVariant::Set { element } => {
                    stack.push((element.as_ref(), depth + 1));
                    0
                }
                TypeVariant::Record(record) => {
                    stack.extend(record.attributes.values().map(|attr| (&attr.ty, depth + 1)));
                    0
                }
                TypeVariant::EntityOrCommon { type_name } => {
                    common_type_depths.get(type_name).copied().unwrap_or(0)
                }
            },
            Type::CommonTypeRef { type_name, .. } => {
                common_type_depths.get(type_name).copied().unwrap_or(0)
            }
        };
        max = max.max(depth + leaf_depth);
    }
    max
}
