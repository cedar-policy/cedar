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

impl_documentation_from_markdown_file!(DecimalDocumentation, "../markdown/extension_decimal.md");
impl_documentation_from_markdown_file!(
    DecimalLessThanDocumentation,
    "../markdown/extension_decimal_less_than.md"
);
impl_documentation_from_markdown_file!(
    DecimalLessThanOrEqualDocumentation,
    "../markdown/extension_decimal_less_than_or_equal.md"
);
impl_documentation_from_markdown_file!(
    DecimalGreaterThanDocumentation,
    "../markdown/extension_decimal_greater_than.md"
);
impl_documentation_from_markdown_file!(
    DecimalGreaterThanOrEqualDocumentation,
    "../markdown/extension_decimal_greater_than_or_equal.md"
);
