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

use crate::markdown::{MarkdownBuilder, ToDocumentationString};
use indoc::indoc;

pub(crate) struct InDocumentation;

impl ToDocumentationString for InDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("in *(hierarchy membership)*")
            .header("Usage:")
            .code_block("cedar", "<entity> in <entity>")
            .paragraph(indoc! {"
                Binary operator that evaluates to true if the entity in the left operand is a
                descendant in the hierarchy under the entity in the right operand. Evaluation
                (and validation) produces an error if the first (lhs) operand of in is not an
                entity, or the (rhs) is not an entity or a set thereof."
            })
            .build()
    }
}

pub(crate) struct HasDocumentation;

impl ToDocumentationString for HasDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("has *(presence of attribute test)*")
            .header("Usage:")
            .code_block(
                "cedar",
                indoc! {"
                <entity or record> has <attribute>
                <entity or record> has <accessor.path>"
                },
            )
            .paragraph(indoc! {"
                Boolean operator that tests whether an entity or record has a specified attribute or
                attribute path defined. It evaluates to true if the attribute exists, false if it
                doesn't. Both evaluation and validation will result in an error if the left operand
                is not an entity or record type."
            })
            .build()
    }
}

pub(crate) struct IsDocumentation;

impl ToDocumentationString for IsDocumentation {
    fn to_documentation_string(
        &self,
        _schema: Option<&cedar_policy_core::validator::ValidatorSchema>,
    ) -> String {
        MarkdownBuilder::new()
            .header("is *(entity type test)*")
            .header("Usage:")
            .code_block("cedar", indoc! {"
                <entity> is <entity-type>
                <entity> is <entity-type> in <entity>
                <entity> is <entity-type> in set(<entity>)"
            })
            .paragraph(indoc! {"
                Boolean operator that tests whether an entity has a specific type. It evaluates to true
                if the left operand is an entity of the specified type, and false if it's an entity of
                a different type. Both evaluation and validation will result in an error if the left
                operand is not an entity or if the right operand is not a known entity type from the schema."
            })
            .build()
    }
}

pub(crate) struct ContainsDocumentation;

impl ToDocumentationString for ContainsDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("contains() *(single element set membership test)*")
            .header("Usage:")
            .code_block("cedar", "<set>.contains(<value>)")
            .paragraph(indoc! {"
                Function that evaluates to true if the operand is a member of the receiver
                on the left side of the function. The receiver must be of type Set or
                evaluation produces an error. To be accepted by the policy validator,
                contains must be called on a receiver that is a Set of some type T,
                with an argument that also has type T."
            })
            .build()
    }
}

pub(crate) struct ContainsAllDocumentation;

impl ToDocumentationString for ContainsAllDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("containsAll() *(all element set membership test)*")
            .header("Usage:")
            .code_block("cedar", "<set>.containsAll(<set>)")
            .paragraph(indoc! {"
                    Function that evaluates to true if every member of the operand set is a member
                    of the receiver set. Both the receiver and the operand must be of type set or
                    evaluation results in an error. To be accepted by the validator, the receiver
                    and argument to containsAll must be homogeneous sets of the same type."
            })
            .build()
    }
}

pub(crate) struct ContainsAnyDocumentation;

impl ToDocumentationString for ContainsAnyDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("containsAny() *(any element set membership test)*")
            .header("Usage:")
            .code_block("cedar", "<set>.containsAny(<set>)")
            .paragraph(indoc! {"
                    Function that evaluates to true if any one or more members of the operand
                    set is a member of the receiver set. Both the receiver and the operand must
                    be of type set or evaluation produces an error. To be accepted by the policy
                    validator, calls to containsAny must be on homogeneous sets of the same type."
            })
            .build()
    }
}

pub(crate) struct IsEmptyDocumentation;

impl ToDocumentationString for IsEmptyDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("isEmpty() *(set emptiness test)*")
            .header("Syntax:")
            .code_block("cedar", "<set>.isEmpty()")
            .paragraph(indoc! {"
                Function that evaluates to `true` if the set is empty.
                The receiver must be of type set or evaluation produces an error."
            })
            .build()
    }
}

#[derive(Default)]
pub(crate) struct SetDocumentation(Option<String>);

impl SetDocumentation {
    pub(crate) fn new<T>(set_type: T) -> Self
    where
        T: Into<Option<String>>,
    {
        Self(set_type.into())
    }
}

impl ToDocumentationString for SetDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        let element_type = self.0.as_ref().map_or("?", |t| t.as_str());
        MarkdownBuilder::new()
            .header("Set Type")
            .code_block("cedarschema", &format!("Set<{element_type}>"))
            .paragraph(&format!(
                "A collection type tha contains elements of type `{element_type}`."
            ))
            .build()
    }
}
