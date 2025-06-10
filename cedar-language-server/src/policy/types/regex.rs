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

use std::sync::LazyLock;

use regex::Regex;

pub(crate) static PRINCIPAL_IS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"principal\s+is\s*").unwrap());

pub(crate) static ACTION_IN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"action\s+in\s*").unwrap());
pub(crate) static ACTION_EQ_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"action\s+==\s*").unwrap());
pub(crate) static ACTION_IN_ARRAY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"action\s+in\s+\[(?:\s*(?:[A-Za-z]+::)?Action::"[\w]+?"\s*,?)*\s*"#).unwrap()
});

pub(crate) static RESOURCE_IS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"resource\s+is\s*").unwrap());
