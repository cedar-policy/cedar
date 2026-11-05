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

use yaspar_macros::stack_safe;

use super::json_schema::{Type, TypeVariant};

/// The depth of `ty` once common types are inlined, given the depth of each
/// common type, computed without inlining
#[stack_safe]
pub(crate) fn type_depth<N: Eq + Hash>(
    ty: &Type<N>,
    common_type_depths: &HashMap<&N, usize>,
) -> usize {
    match ty {
        Type::Type { ty: variant, .. } => match variant {
            TypeVariant::String
            | TypeVariant::Long
            | TypeVariant::Boolean
            | TypeVariant::Entity { .. }
            | TypeVariant::Extension { .. } => 0,
            TypeVariant::Set { element } => 1 + type_depth(element, common_type_depths),
            TypeVariant::Record(record) => {
                let mut depth = 0;
                for attr in record.attributes.values() {
                    depth = depth.max(1 + type_depth(&attr.ty, common_type_depths));
                }
                depth
            }
            TypeVariant::EntityOrCommon { type_name } => {
                common_type_depths.get(type_name).copied().unwrap_or(0)
            }
        },
        Type::CommonTypeRef { type_name, .. } => {
            common_type_depths.get(type_name).copied().unwrap_or(0)
        }
    }
}
