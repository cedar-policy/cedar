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

use crate::impl_documentation_from_markdown_file;

impl_documentation_from_markdown_file!(EqualsDocumentation, "markdown/comparison/equals.md");
impl_documentation_from_markdown_file!(NotEqualsDocumentation, "markdown/comparison/not_equals.md");
impl_documentation_from_markdown_file!(LessThanDocumentation, "markdown/comparison/less_than.md");
impl_documentation_from_markdown_file!(
    LessThanOrEqualsDocumentation,
    "markdown/comparison/less_than_or_equals.md"
);
impl_documentation_from_markdown_file!(
    GreaterThanDocumentation,
    "markdown/comparison/greater_than.md"
);
impl_documentation_from_markdown_file!(
    GreaterThanOrEqualsDocumentation,
    "markdown/comparison/greater_than_or_equals.md"
);
impl_documentation_from_markdown_file!(LikeDocumentation, "markdown/comparison/like.md");
