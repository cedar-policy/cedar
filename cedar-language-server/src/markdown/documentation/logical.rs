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
            .header("Evaluation Rules:")
            .bullet_list(&[
                "true && true → true",
                "true && false → false",
                "false && true → false",
                "false && false → false",
                "false && <expr> → false (second expression not evaluated)",
            ])
            .header("Example:")
            .paragraph("Common usage pattern in policies:")
            .code_block("cedar", indoc! {"
                permit (principal, action == Action::\"remoteAccess\", resource)
                when {
                    principal.numberOfLaptops < 5 &&
                    principal.jobLevel > 6
                };"
            })
            .paragraph(indoc! {"
                Note: The && operator uses short-circuit evaluation, which can be useful for safe
                attribute access. If the first condition is false, the second condition will not
                be evaluated, preventing potential errors."
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
            .header("Evaluation Rules:")
            .bullet_list(&[
                "true || true → true",
                "true || false → true",
                "false || true → true",
                "false || false → false",
                "true || <expr> → true (second expression not evaluated)",
            ])
            .header("Short-Circuit Evaluation")
            .paragraph(indoc! {"
                The OR operator uses short-circuit evaluation, which is particularly useful for safe
                attribute access. This allows patterns like checking for attribute existence before
                accessing it:"
            })
            .code_block("cedar", indoc! {"
                !(principal has age) || principal.age >= 21"
            })
            .header("Examples:")
            .code_block("cedar", indoc! {"
                permit (principal, action == Action::\"read\", resource)
                when {
                    resource.owner == principal ||
                    resource.tag == \"public\"
                };"
            })
            .paragraph(indoc! {"
                Note on Validation: While the operator uses short-circuit evaluation at runtime,
                the validator will generally reject expressions where either operand could evaluate
                to a non-boolean value. However, the validator can sometimes take short-circuiting
                into account for certain patterns (like the has check example above)."
            })
            .paragraph(indoc! {"
                Common Pattern: Using OR with has to safely handle optional attributes:
                - First check if attribute exists
                - OR evaluate the attribute if it exists
                - Short-circuit prevents errors from missing attributes"
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
            .header("Examples:")
            .code_block(
                "cedar",
                indoc! {"
            !true                           //false
            !false                          //true
            !(principal in Group::\"family\")  //true if principal is not in the family group"
                },
            )
            .paragraph(indoc! {"
                Common usage pattern in policies - these two forms are equivalent:"
            })
            .code_block(
                "cedar",
                indoc! {"
            forbid (principal, action, resource)
            when {
                !(principal in Group::\"family\")
            };

            forbid (principal, action, resource)
            unless {
                principal in Group::\"family\"
            };"
                },
            )
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
            .header("Evaluation Rules")
            .bullet_list(&[
                "First argument must be a boolean",
                "Second and third arguments can be of any type",
                "Uses short-circuit evaluation:",
                "  - When condition is true, 'else' expression is not evaluated",
                "  - When condition is false, 'then' expression is not evaluated",
            ])
            .header("Validation")
            .paragraph(indoc! {"
                For validation, typically both the 'then' and 'else' expressions must have the same
                type. However, the validator can sometimes account for short-circuit behavior in
                specific cases."
            })
            .header("Examples:")
            .code_block(
                "cedar",
                indoc! {"
                // Basic conditional
                if isAdmin then true else false

                // Policy example
                permit (principal, action == Action::\"remoteAccess\", resource)
                when {
                    if principal.numberOfLaptops < 5 then
                        principal.jobLevel > 6
                    else
                        false
                };"
                },
            )
            .paragraph(indoc! {"
                Common Pattern: Using if with has for safe attribute access:"
            })
            .code_block(
                "cedar",
                indoc! {"
                if principal has age then
                    principal.age >= 21
                else
                    false"
                },
            )
            .paragraph(indoc! {"
                Note: The if operator's short-circuit evaluation makes it useful for safely handling
                optional attributes or conditions that might otherwise cause errors. Always ensure
                the condition evaluates to a boolean to prevent runtime errors."
            })
            .build()
    }
}
