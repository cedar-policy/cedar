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

use cedar_policy_core::validator::ValidatorSchema;

use crate::impl_documentation_from_markdown_file;

use super::ToDocumentationString;

impl_documentation_from_markdown_file!(AndDocumentation, "markdown/logical_and.md");
impl_documentation_from_markdown_file!(OrDocumentation, "markdown/logical_or.md");
impl_documentation_from_markdown_file!(NotDocumentation, "markdown/logical_not.md");
impl_documentation_from_markdown_file!(IfDocumentation, "markdown/logical_if.md");
