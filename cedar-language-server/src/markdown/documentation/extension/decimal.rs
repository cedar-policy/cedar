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
use indoc::indoc;

use crate::markdown::{MarkdownBuilder, ToDocumentationString};

pub(crate) struct DecimalDocumentation;

impl ToDocumentationString for DecimalDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("decimal() *(parse string and convert to decimal)*")
            .header("Usage:")
            .code_block("cedar", "decimal(<string>)")
            .paragraph(indoc! {"
                Function that parses the string and tries to convert it to type decimal. If the string doesn't represent
                a valid decimal value, it generates an error."
            })
            .paragraph(indoc! {"
                To be interpreted successfully as a decimal value, the string must contain a decimal separator (.)
                and at least one digit before and at least one digit after the separator. There can be no more than
                4 digits after the separator. The value must be within the valid range of the decimal type, from
                -922337203685477.5808 to 922337203685477.5807."
            })
            .build()
    }
}

pub(crate) struct DecimalLessThanDocumentation;

impl ToDocumentationString for DecimalLessThanDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("lessThan() *(decimal 'less than')*")
            .header("Usage:")
            .code_block("cedar", "<decimal>.lessThan(<decimal>)")
            .paragraph(indoc! {"
                Function that compares two decimal operands and evaluates to true if the left operand is numerically
                less than the right operand. If either operand is not a decimal then evaluation (and validation)
                results in an error."
            })
            .build()
    }
}

pub(crate) struct DecimalLessThanOrEqualDocumentation;

impl ToDocumentationString for DecimalLessThanOrEqualDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("lessThanOrEqual() *(decimal 'less than or equal')*")
            .header("Usage:")
            .code_block("cedar", "<decimal>.lessThanOrEqual(<decimal>)")
            .paragraph(indoc! {"
                Function that compares two decimal operands and evaluates to true if the left operand is numerically
                less than or equal to the right operand. If either operand is not a decimal then evaluation
                (and validation) results in an error."
            })
            .build()
    }
}

pub(crate) struct DecimalGreaterThanDocumentation;

impl ToDocumentationString for DecimalGreaterThanDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("greaterThan() *(decimal 'greater than')*")
            .header("Usage:")
            .code_block("cedar", "<decimal>.greaterThan(<decimal>)")
            .paragraph(indoc! {"
                Function that compares two decimal operands and evaluates to true if the left operand is numerically
                greater than the right operand. If either operand is not a decimal then evaluation (and validation)
                results in an error."
            })
            .build()
    }
}

pub(crate) struct DecimalGreaterThanOrEqualDocumentation;

impl ToDocumentationString for DecimalGreaterThanOrEqualDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("greaterThanOrEqual() *(decimal 'greater than or equal')*")
            .header("Usage:")
            .code_block("cedar", "<decimal>.greaterThanOrEqual(<decimal>)")
            .paragraph(indoc! {"
                Function that compares two decimal operands and evaluates to true if the left operand is numerically
                greater than or equal to the right operand. If either operand is not a decimal then evaluation
                (and validation) results in an error."
            })
            .build()
    }
}
