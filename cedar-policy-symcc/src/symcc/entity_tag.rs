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
use std::{collections::BTreeMap, ops::Deref};

use smol_str::SmolStr;

pub struct EntityTag<T>(pub BTreeMap<SmolStr, T>);

impl<T> Deref for EntityTag<T> {
    type Target = BTreeMap<SmolStr, T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> EntityTag<T> {
    pub fn mk(entity: T, tag: T) -> Self {
        Self(
            [("entity".into(), entity), ("tag".into(), tag)]
                .into_iter()
                .collect(),
        )
    }
}
