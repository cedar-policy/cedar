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
            .header("Properties:")
            .paragraph(indoc! {"
                - **Transitive**: If A is in B, and B is in C, then A is also in C. This allows
                  modeling of multi-tier hierarchies (e.g., nested folders).
                - **Reflexive**: An entity is always in its own hierarchy. A is always in A."
            })
            .header("Examples:")
            .code_block("cedar", indoc! {"
                // Simple hierarchy check
                Group::\"engineering\" in Group::\"tech\" //Evaluates to true if engineering is under tech

                // Reflexive property
                Group::\"tech\" in Group::\"tech\" //Always evaluates to true

                // Transitive property
                Group::\"mobile\" in Group::\"engineering\" //Evaluates to true if mobile is under engineering
                Group::\"engineering\" in Group::\"tech\" //Evaluates to true if engineering is under tech
                Group::\"mobile\" in Group::\"tech\" //Evaluates to true due to transitivity

                // Error cases
                \"engineering\" in Group::\"tech\" //error - left operand must be an entity
                Group::\"engineering\" in \"tech\" //error - right operand must be an entity

                // Set membership (special case)
                principal in [Group::\"admin\", Group::\"users\"]  //Evaluates to true if principal is in either group"
            })
            .paragraph(indoc! {"
                Note: The `in` operator can also be used with a set of entities on the right-hand side.
                In this case, it evaluates to true if the left entity is in the hierarchy of any entity
                in the set."
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
            .code_block("cedar", indoc! {"
                <entity or record> has <attribute>
                <entity or record> has <accessor.path>"
            })
            .paragraph(indoc! {"
                Boolean operator that tests whether an entity or record has a specified attribute or
                attribute path defined. It evaluates to true if the attribute exists, false if it
                doesn't. Both evaluation and validation will result in an error if the left operand
                is not an entity or record type."
            })
            .header("Extended Path Syntax")
            .paragraph(indoc! {"
                The has operator supports testing nested attributes using dot notation. When checking
                a path, it verifies that every attribute in the chain exists. This is particularly
                useful for safely accessing nested attributes."
            })
            .header("Examples:")
            .code_block("cedar", indoc! {"
                // Basic attribute checking
                user has email                      //true if user has email attribute
                photo has owner                     //true if photo has owner attribute

                // Nested attribute checking
                user has contactInfo.address        //true if both contactInfo and address exist
                user has profile.settings.privacy   //true if entire path exists"
            })
            .paragraph("Common usage pattern in policies:")
            .code_block("cedar", indoc! {"
                permit(principal, action, resource)
                when {
                    principal has contactInfo.address.zip &&
                    principal.contactInfo.address.zip == \"12345\"
                };"
            })
            .paragraph(indoc! {"
                Note: Using has before accessing attributes helps prevent runtime errors. The has
                operator is particularly useful when some attributes might be optional or when
                dealing with nested data structures."
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
            .header("Extended Syntax")
            .paragraph(indoc! {"
                The is operator can be combined with in for convenient type-checking and membership testing:

                - `entity is Type in other` is equivalent to `entity is Type && entity in other`
                - `entity is Type in set(other)` is equivalent to `entity is Type && entity in set(other)`"
            })
            .header("Examples:")
            .code_block("cedar", indoc! {"
                resource is Photo                   //true if resource is a Photo entity
                principal is User                   //true if principal is a User entity
                resource is Photo in photoAlbum     //true if resource is a Photo and in photoAlbum"
            })
            .paragraph("Common usage pattern in policies:")
            .code_block("cedar", indoc! {"
                permit(principal, action == Action::\"view\", resource)
                when {
                    resource is Photo && resource.owner == principal
                };"
            })
            .paragraph(indoc! {"
                Note: Using is for type checking before accessing type-specific attributes helps prevent
                errors, as Cedar uses short-circuit evaluation for logical operators. In the example
                above, resource.owner is only accessed if resource is Photo evaluates to true."
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
            .header("Examples:")
            .paragraph(indoc! {"
                Examples labeled with //error both fail to evaluate and fail to validate.
                Examples that evaluate to a result may fail to validate."
            })
            .code_block("cedar", indoc! {"
                [1,2,3].contains(1)                             //Evaluates to true //Validates
                [1,\"something\",2].contains(1)                   //Evaluates to true //Doesn't validate (heterogeneous set)
                [1,\"something\",2].contains(\"Something\")         //Evaluates to false (string comparison is case-sensitive) //Doesn't validate (heterogeneous set)
                [\"some\", \"useful\", \"tags\"].contains(\"useful\")   //Evaluates to true //Validates
                [].contains(100)                                //Evaluates to false // Doesn't validate (has empty-set literal)
                context.role.contains(\"admin\")                  //Evaluates to true (if the `context.role` set contains string \"admin\") //Validates
                [User::\"alice\"].contains(principal)             //Evaluates to true (if principal == User::\"alice\") //Validates
                \"ham and ham\".contains(\"ham\")                   //error - 'contains' is not allowed on strings"
            })
            .paragraph(indoc! {"
                A heterogeneous set, as shown in several examples, contains more than one type.
                None of the validates: false examples is a valid set. See valid sets for more info."
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
                .header("Examples:")
                .paragraph(indoc! {"
                    In the examples that follow, those labeled //error both evaluate and validate
                    to an error. The remaining examples evaluate to a proper result, but some fail
                    to validate, as indicated in the labels."
                })
                .code_block("cedar", indoc! {"
                    [1, -22, 34].containsAll([-22, 1])                                //Evaluates to true //Validates
                    [1, -22, 34].containsAll([-22])                                   //Evaluates to true //Validates
                    [43, 34].containsAll([34, 43])                                    //Evaluates to true //Validates
                    [1, -2, 34].containsAll([1, -22])                                 //Evaluates to false //Validates
                    [1, 34].containsAll([1, 101, 34])                                 //Evaluates to false //Validates
                    [false, 3, [47, 0], \"some\"].containsAll([3, \"some\"])              //Evaluates to true //Doesn't validate (heterogeneous set)
                    [false, 3, [47, 0], {\"2\": \"ham\"}].containsAll([3, {\"2\": \"ham\"}])  //Evaluates to true //Doesn't validate (heterogeneous set)
                    [2, 43].containsAll([])                                           //Evaluates to true //Doesn't validate (emptyset literal)
                    [].containsAll([2, 43])                                           //Evaluates to false //Doesn't validate (emptyset literal)
                    [false, 3, [47, 0], \"thing\"].containsAll(\"thing\")                 //error - operand a string
                    \"ham and eggs\".containsAll(\"ham\")                                 //error - prefix and operand are strings
                    {\"2\": \"ham\", \"3\": \"eggs \"}.containsAll({\"2\": \"ham\"})              //error - prefix and operand are records"
                })
                .paragraph("Some examples evaluate to a result but fail to validate for one or more of the following reasons:")
                .bullet_list(&[
                    "They operate on heterogeneous sets: values of multiple types",
                    "They reference the empty-set literal []",
                    "They don't operate on sets at all. See valid sets for more info.",
                ])
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
                .header("Examples:")
                .paragraph(indoc! {"
                    In the examples that follow, those labeled //error both evaluate and validate
                    to an error. The remaining examples evaluate to a proper result, but some fail
                    to validate, as indicated in the labels."
                })
                .code_block("cedar", indoc! {"
                    [1, -22, 34].containsAny([1, -22])                             //Evaluates to true //Validates
                    [1, -22].containsAny([1, -22, 34])                             //Evaluates to true //Validates
                    [-22].containsAny([1, -22, 34])                                //Evaluates to true //Validates
                    [1, 101].containsAny([1, -22, 34])                             //Evaluates to true //Validates
                    [1, 101].containsAny([-22, 34])                                //Evaluates to false //Validates
                    [\"alice\",\"bob\",\"charlie\"].containsAny([\"david\",\"bob\",\"juan\"])  //Evaluates to true //Validates
                    [].containsAny([\"bob\"])                                        //Evaluates to false //Doesn't validate (emptyset literal)
                    [\"bob\"].containsAny([])                                        //Evaluates to false //Doesn't validate (emptyset literal)
                    \"ham\".containsAny(\"ham and eggs\")                              //error - operand is a string
                    {\"2\": \"ham\"}.containsAny({\"2\": \"ham\", \"3\": \"eggs \"})           //error - prefix and operands are records"
                })
                .paragraph(indoc! {"
                    The examples that evaluate to a result but fail to validate reference the
                    empty-set literal []. See valid sets for more info."
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
            .header("Examples:")
            .code_block(
                "cedar",
                indoc! {"
                [1, -22, 34].isEmpty() // Evaluates to false
                [].isEmpty()           // Evaluates to true
                \"\".isEmpty()           // Error - operand is a string, not a set"
                },
            )
            .paragraph("**Returns:** `bool`")
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
            .paragraph("A collection type that:")
            .bullet_list(&[
                "Contains unique elements",
                &format!("Elements are of type `{element_type}`"),
                "Supports operations like:",
            ])
            .bullet_list(&[
                "  `isEmpty()`",
                "  `contains(element)`",
                "  `containsAll(other)`",
                "  `containsAny(other)`",
            ])
            .build()
    }
}
