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

use crate::markdown::MarkdownBuilder;
use super::ToDocumentationString;
use cedar_policy_core::validator::ValidatorSchema;

pub(crate) struct LongDocumentation;

impl ToDocumentationString for LongDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("long *(integer type)*")
            .paragraph("A whole number without decimals that can range from -9223372036854775808 to 9223372036854775807 (64-bit signed integer).") .build()
    }
}

pub(crate) struct StringDocumentation;

impl ToDocumentationString for StringDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("string")
            .paragraph("A sequence of characters consisting of letters, numbers, or symbols.")
            .build()
    }
}

pub(crate) struct BoolDocumentation;

impl ToDocumentationString for BoolDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("Boolean")
            .paragraph("A value that is either `true` or `false`.")
            .build()
    }
}
