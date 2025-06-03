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
            .paragraph(indoc! {"
                While Cedar can evaluate expressions where operands have different types (usually giving
                false), such comparisons are not accepted by the policy validator. For validation,
                both operands must either have the same type, or both must be entities (though not
                necessarily of the same entity type)."
            })
            .header("Examples:")
            .paragraph("Examples below show evaluation results, with validation status noted where relevant:")
            .code_block("cedar", indoc! {"
                1 == 1                                        //true //Validates
                \"something\" == \"something\"                    //true //Validates
                [1, 2, 40] == [1, 2, 40]                     //true //Validates
                [1, 2, 40] == [1, 40, 2]                     //true //Validates
                User::\"alice\" == User::\"alice\"                //true //Validates
                User::\"alice\" == Admin::\"alice\"               //false //Validates (both are entities)
                5 == \"5\"                                      //false //Doesn't validate (different types)
                \"alice\" == User::\"alice\"                     //false //Doesn't validate (different types)"
            })
            .bullet_list(&[
                "Both operands must have the same type, or",
                "Both operands must be entities (though not necessarily the same entity type)",
            ])
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
            .header("Example:")
            .code_block("cedar", indoc! {"
                forbid (principal, action, resource)
                when{
                    resource.tag != \"public\"
                };"
            })
            .bullet_list(&[
                "Both operands must have the same type, or",
                "Both operands must be entities (though not necessarily the same entity type)",
            ])
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
            .header("Example:")
            .code_block(
                "cedar",
                indoc! {"
                3 < 303               //true
                principal.age < 22    //true (assuming principal.age is 21)
                3 < \"3\"             //error - operator not allowed on non-long
                false < true          //error - operator not allowed on non-long
                \"\" < \"zzz\"         //error - operator not allowed on non-long
                [1, 2] < [47, 0]      //error - operator not allowed on non-long"
                },
            )
            .bullet_list(&[
                "Both operands must have the same type, or",
                "Both operands must be entities (though not necessarily the same entity type)",
            ])
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
            .header("Example:")
            .code_block("cedar", indoc! {"
                3 <= 303               //true
                principal.age <= 21    //true (assuming principal.age is 21)
                3 <= \"3\"             //error - operator not allowed on non-long
                false <= true          //error - operator not allowed on non-long
                \"\" <= \"zzz\"        //error - operator not allowed on non-long
                [1, 2] <= [47, 0]      //error - operator not allowed on non-long"
            })
            .bullet_list(&[
                "Both operands must have the same type, or",
                "Both operands must be entities (though not necessarily the same entity type)",
            ])
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
            .header("Example:")
            .code_block(
                "cedar",
                indoc! {"
                303 > 3               //true
                principal.age > 21    //true (assuming principal.age is 21)
                3 > \"3\"             //error - operator not allowed on non-long
                false > true          //error - operator not allowed on non-long
                \"\" > \"zzz\"        //error - operator not allowed on non-long
                [47, 0] > [1, 2]      //error - operator not allowed on non-long"
                },
            )
            .bullet_list(&[
                "Both operands must have the same type, or",
                "Both operands must be entities (though not necessarily the same entity type)",
            ])
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
            .header("Example:")
            .code_block("cedar", indoc! {"
                303 >= 3               //true
                principal.age >= 21    //true (assuming principal.age is 21)
                3 >= \"3\"             //error - operator not allowed on non-long
                false >= true          //error - operator not allowed on non-long
                \"\" >= \"zzz\"        //error - operator not allowed on non-long
                [47, 0] >= [1, 2]      //error - operator not allowed on non-long"
            })
            .bullet_list(&[
                "Both operands must have the same type, or",
                "Both operands must be entities (though not necessarily the same entity type)",
            ])
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
            .header("Example:")
            .code_block("cedar", indoc! {"
                \"ham and eggs\" like \"ham*\"           //true
                \"eggs and ham\" like \"*ham\"           //true
                \"eggs, ham, and spinach\" like \"*ham*\" //true
                \"ham\" like \"*h*a*m*\"                 //true
                \"string*with*stars\" like \"string\\*with\\*stars\" //true
                \"eggs\" like \"ham*\"                   //false
            "})
            .build()
    }
}
