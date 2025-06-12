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
use cedar_policy_core::validator::ValidatorSchema;
use indoc::indoc;

pub(crate) struct EqualsDocumentation;

impl ToDocumentationString for EqualsDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("== *(equality)*")
            .header("Usage:")
            .code_block("cedar", "<value> == <value>")
            .paragraph(indoc! {"
                Binary operator that compares two operands of any type and evaluates to true only if
                they are exactly the same type and the same value."
            })
            .build()
    }
}

pub(crate) struct NotEqualsDocumentation;

impl ToDocumentationString for NotEqualsDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("!= *(inequality)*")
            .header("Usage:")
            .code_block("cedar", "<value> != <value>")
            .paragraph(indoc! {"
                Binary operator that compares two operands of any type and evaluates to true if the
                operands have different values or are of different types. You can use != only in when
                and unless clauses. As with the == operator, the validator only accepts policies that
                use != on two expressions of (possibly differing) entity type, or the same non-entity type.
            "})
            .build()
    }
}

pub(crate) struct LessThanDocumentation;

impl ToDocumentationString for LessThanDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("< *(less than)*")
            .header("Usage:")
            .code_block("cedar", "<long> < <long>")
            .paragraph(indoc! {"
                Binary operator that compares two long integer operands and evaluates to true
                if the left operand is numerically less than the right operand. If either
                operand is not a long then evaluation (and validation) results in an error.
            "})
            .build()
    }
}

pub(crate) struct LessThanOrEqualsDocumentation;

impl ToDocumentationString for LessThanOrEqualsDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("<= *(less than or equal)*")
            .header("Usage:")
            .code_block("cedar", "<long> <= <long>")
            .paragraph(indoc! {"
                Binary operator that compares two long integer operands and evaluates to true
                if the left operand is numerically less than or equal to the right operand. If either
                operand is not a long then evaluation (and validation) results in an error.
            "})
            .build()
    }
}

pub(crate) struct GreaterThanDocumentation;

impl ToDocumentationString for GreaterThanDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("> *(greater than)*")
            .header("Usage:")
            .code_block("cedar", "<long> > <long>")
            .paragraph(indoc! {"
                Binary operator that compares two long integer operands and evaluates to true
                if the left operand is numerically greater than the right operand. If either
                operand is not a long then evaluation (and validation) results in an error.
            "})
            .build()
    }
}

pub(crate) struct GreaterThanOrEqualsDocumentation;

impl ToDocumentationString for GreaterThanOrEqualsDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header(">= *(greater than or equal)*")
            .header("Usage:")
            .code_block("cedar", "<long> >= <long>")
            .paragraph(indoc! {"
                Binary operator that compares two long integer operands and evaluates to true
                if the left operand is numerically greater than or equal to the right operand. If either
                operand is not a long then evaluation (and validation) results in an error.
            "})
            .build()
    }
}

pub(crate) struct LikeDocumentation;

impl ToDocumentationString for LikeDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("like *(string matching with wildcard)*")
            .header("Usage:")
            .code_block("cedar", "<string> like <string possibly with wildcards>")
            .paragraph(indoc! {"
                Binary operator that evaluates to true if the string in the left operand matches the pattern string
                in the right operand. The pattern string can include one or more asterisks (*) as wildcard characters
                that match 0 or more of any character.

                To match a literal asterisk character, use the escaped \\* sequence in the pattern string.
            "})
            .build()
    }
}
