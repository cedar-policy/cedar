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

use crate::markdown::{MarkdownBuilder, ToDocumentationString};
use indoc::indoc;

pub(crate) struct AndDocumentation;

impl ToDocumentationString for AndDocumentation {
    fn to_documentation_string(
        &self,
        _schema: Option<&cedar_policy_core::validator::ValidatorSchema>,
    ) -> String {
        MarkdownBuilder::new()
            .header("&& *(AND)*")
            .header("Usage:")
            .code_block("cedar", "<boolean> && <boolean>")
            .paragraph(indoc! {"
                Binary operator that performs logical AND between two boolean expressions. It evaluates
                to true only if both operands evaluate to true. Uses short-circuit evaluation: if the
                first operand is false, the second operand is not evaluated."
            })
            .build()
    }
}

pub(crate) struct OrDocumentation;

impl ToDocumentationString for OrDocumentation {
    fn to_documentation_string(
        &self,
        _schema: Option<&cedar_policy_core::validator::ValidatorSchema>,
    ) -> String {
        MarkdownBuilder::new()
            .header("|| *(OR)*")
            .header("Usage:")
            .code_block("cedar", "<boolean> || <boolean>")
            .paragraph(indoc! {"
                Binary operator that performs logical OR between two boolean expressions. It evaluates
                to true if either operand evaluates to true. Uses short-circuit evaluation: if the
                first operand is true, the second operand is not evaluated."
            })
            .build()
    }
}

pub(crate) struct NotDocumentation;

impl ToDocumentationString for NotDocumentation {
    fn to_documentation_string(
        &self,
        _schema: Option<&cedar_policy_core::validator::ValidatorSchema>,
    ) -> String {
        MarkdownBuilder::new()
            .header("! *(NOT)*")
            .header("Usage:")
            .code_block("cedar", "!<boolean>")
            .paragraph(indoc! {"
            Unary operator that inverts the value of a boolean operand: true becomes false, and
            false becomes true. If the operand is not a boolean, both evaluation and validation
            will result in an error."
            })
            .build()
    }
}

pub(crate) struct IfDocumentation;

impl ToDocumentationString for IfDocumentation {
    fn to_documentation_string(
        &self,
        _schema: Option<&cedar_policy_core::validator::ValidatorSchema>,
    ) -> String {
        MarkdownBuilder::new()
            .header("if *(CONDITIONAL)*")
            .header("Usage:")
            .code_block("cedar", "if <boolean> then <T> else <U>")
            .paragraph(indoc! {"
                Conditional operator that evaluates based on a boolean condition. Returns the 'then'
                expression if the condition is true, or the 'else' expression if the condition is
                false. The condition must evaluate to a boolean value or an error will occur."
            })
            .build()
    }
}
