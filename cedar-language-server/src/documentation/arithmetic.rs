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

use super::ToDocumentationString;
use crate::markdown::MarkdownBuilder;

pub(crate) struct AddDocumentation;

impl ToDocumentationString for AddDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
                .header("+ *(numeric addition)*")
                .header("Usage:")
                .code_block("cedar", "<long> + <long>")
                .paragraph(indoc! {"
                    Binary operator that adds two long integer values and returns their sum. Both operands
                    must be long integers or evaluation and validation will result in an error. Addition
                    operations that result in overflow will fail at evaluation time, but will pass validation."
                })
                .build()
    }
}

pub(crate) struct SubtractDocumentation;

impl ToDocumentationString for SubtractDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("- *(numeric subtraction or negation)*")
            .header("Usage:")
            .code_block("cedar", indoc! {"
                <long> - <long>    // binary subtraction
                -<long>           // unary negation"
            })
            .paragraph(indoc! {"
                Operator that can function as either binary subtraction or unary negation. As a binary
                operator, it subtracts the second long integer from the first. As a unary operator, it
                negates a single long integer. Both forms require long integer operands or evaluation
                and validation will result in an error. Subtraction operations that result in overflow
                (or underflow) will fail at evaluation time, but will pass validation."
            })
            .build()
    }
}

pub(crate) struct MultiplyDocumentation;

impl ToDocumentationString for MultiplyDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("* *(numeric multiplication)*")
            .header("Usage:")
            .code_block("cedar", "<long> * <long>")
            .paragraph(indoc! {"
                Binary operator that multiplies two long integer operands and returns their product.
                Both operands must be long integers or evaluation and validation will result in an
                error. Multiplication operations that result in overflow will fail at evaluation time,
                but will pass validation."
            })
            .paragraph(indoc! {"
                Note: Cedar does not provide an operator for arithmetic division."
            })
            .build()
    }
}
