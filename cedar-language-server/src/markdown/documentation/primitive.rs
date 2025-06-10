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
use crate::markdown::ToDocumentationString;
use cedar_policy_core::validator::ValidatorSchema;
use indoc::indoc;

pub(crate) struct LongDocumentation;

impl ToDocumentationString for LongDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("long *(integer type)*")
            .paragraph(indoc! {"
                A whole number without decimals that can range from -9223372036854775808 to
                9223372036854775807 (64-bit signed integer)."
            })
            .header("Arithmetic Operations")
            .paragraph(indoc! {"
                Long values support basic arithmetic operations (+, -, *, unary -). However, if an
                operation results in a value outside the valid range, it will cause an overflow error.
                When this happens:

                - The policy evaluation will fail
                - A Permit policy will fail to grant access
                - A Forbid policy will fail to block access"
            })
            .header("Examples:")
            .code_block("cedar", indoc! {"
                // Valid operations
                42                                  //Valid long literal
                -1234                              //Valid negative long
                100 + 200                          //Valid addition
                // Overflow examples
                9223372036854775807 + 1            //Error: overflow
                -9223372036854775808 - 1           //Error: underflow
                9223372036854775807 * 2            //Error: overflow"
            })
            .paragraph(indoc! {"
                Note: While overflow errors are caught during evaluation, they are not detected during
                validation. It's important to consider range limitations when writing policies that
                perform arithmetic operations."
            })
            .build()
    }
}

pub(crate) struct StringDocumentation;

impl ToDocumentationString for StringDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("string")
            .paragraph(indoc! {"
                A sequence of characters consisting of letters, numbers, or symbols.
            "})
            .build()
    }
}

pub(crate) struct BoolDocumentation;

impl ToDocumentationString for BoolDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("Boolean")
            .paragraph("A value that is either `true` or `false`.")
            .header("Common Uses:")
            .bullet_list(&[
                "Condition expressions in `if` statements",
                "Results of comparison operations",
                "Logical operations (`&&`, `||`, `!`)",
            ])
            .header("Examples:")
            .code_block(
                "cedar",
                indoc! {"
                true                                    // Boolean literal
                false                                  // Boolean literal
                principal.active                       // Boolean attribute
                resource.public || resource.isShared   // Logical OR
                !resource.restricted                   // Logical NOT
                value1 == value2                      // Equality comparison
                amount > 100                          // Numeric comparison"
                },
            )
            .build()
    }
}
