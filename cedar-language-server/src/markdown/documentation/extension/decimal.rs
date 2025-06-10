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
            .paragraph(indoc! {"
                Cedar can properly evaluate decimal(e) where e is any Cedar expression that evaluates to a valid string.
                For example, the expression decimal(if true then \"1.1\" else \"2.1\") will evaluate to the decimal
                number 1.1. However, Cedar's policy validator only permits e to be a string literal that will not
                result in an error or overflow."
            })
            .header("Examples:")
            .paragraph(indoc! {"
                In the examples below, suppose context.time is \"12.25\" while context.date is \"12/27/91\".
                Examples labeled error indicate both a validation and evaluation error. Unlabeled examples
                evaluate and validate correctly."
            })
            .code_block("cedar", indoc! {"
                decimal(\"1.0\")
                decimal(\"-1.0\")
                decimal(\"123.456\")
                decimal(\"0.1234\")
                decimal(\"-0.0123\")
                decimal(\"55.1\")
                decimal(\"00.000\")
                decimal(context.time)            //Evaluates //Doesn't validate (parameter not a string literal)
                decimal(context.date)            //error - invalid format (not valid as parameter not a string literal)
                decimal(\"1234\")                  //error - missing decimal
                decimal(\"1.0.\")                  //error - stray period at end
                decimal(\"1.\")                    //error - missing fractional part
                decimal(\".1\")                    //error - missing whole number part
                decimal(\"1.a\")                   //error - invalid fractional part
                decimal(\"-.\")                    //error - invalid format
                decimal(\"1000000000000000.0\")    //error - overflow
                decimal(\"922337203685477.5808\")  //error - overflow
                decimal(\"0.12345\")               //error - too many fractional digits"
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
            .header("Examples:")
            .paragraph("In the following examples, //error indicates both an evaluation and a validation error.")
            .code_block("cedar", indoc! {"
                decimal(\"1.23\").lessThan(decimal(\"1.24\"))     //true
                decimal(\"1.23\").lessThan(decimal(\"1.23\"))     //false
                decimal(\"123.45\").lessThan(decimal(\"1.23\"))   //false
                decimal(\"-1.23\").lessThan(decimal(\"1.23\"))    //true
                decimal(\"-1.23\").lessThan(decimal(\"-1.24\"))   //false
                decimal(\"1.1\").lessThan(2)                    //error -- not a decimal operand
                ip(\"1.1.2.3\").lessThan(decimal(\"1.2\"))        //error -- not a decimal operand"
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
            .header("Examples:")
            .paragraph("In the following examples, //error indicates both an evaluation and a validation error.")
            .code_block("cedar", indoc! {"
                decimal(\"1.23\").lessThanOrEqual(decimal(\"1.24\"))    //true
                decimal(\"1.23\").lessThanOrEqual(decimal(\"1.23\"))    //true
                decimal(\"123.45\").lessThanOrEqual(decimal(\"1.23\"))  //false
                decimal(\"-1.23\").lessThanOrEqual(decimal(\"1.23\"))   //true
                decimal(\"-1.23\").lessThanOrEqual(decimal(\"-1.24\"))  //false
                decimal(\"1.1\").lessThanOrEqual(2)                   //error -- not a decimal operand
                ip(\"1.1.2.3\").lessThanOrEqual(decimal(\"1.2\"))       //error -- not a decimal operand"
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
            .header("Examples:")
            .paragraph("In the following examples, //error indicates both an evaluation and a validation error.")
            .code_block("cedar", indoc! {"
                decimal(\"1.23\").greaterThan(decimal(\"1.24\"))    //false
                decimal(\"1.23\").greaterThan(decimal(\"1.23\"))    //false
                decimal(\"123.45\").greaterThan(decimal(\"1.23\"))  //true
                decimal(\"-1.23\").greaterThan(decimal(\"1.23\"))   //false
                decimal(\"-1.23\").greaterThan(decimal(\"-1.24\"))  //true
                decimal(\"1.1\").greaterThan(2)                   //error -- not a decimal operand
                ip(\"1.1.2.3\").greaterThan(decimal(\"1.2\"))       //error -- not a decimal operand"
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
            .header("Examples:")
            .paragraph("In the following examples, //error indicates both an evaluation and a validation error.")
            .code_block("cedar", indoc! {"
                decimal(\"1.23\").greaterThanOrEqual(decimal(\"1.24\"))    //false
                decimal(\"1.23\").greaterThanOrEqual(decimal(\"1.23\"))    //true
                decimal(\"123.45\").greaterThanOrEqual(decimal(\"1.23\"))  //true
                decimal(\"-1.23\").greaterThanOrEqual(decimal(\"1.23\"))   //false
                decimal(\"-1.23\").greaterThanOrEqual(decimal(\"-1.24\"))  //true
                decimal(\"1.1\").greaterThanOrEqual(2)                   //error -- not a decimal operand
                ip(\"1.1.2.3\").greaterThanOrEqual(decimal(\"1.2\"))       //error -- not a decimal operand"
            })
            .build()
    }
}
