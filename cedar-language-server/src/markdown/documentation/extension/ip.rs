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

pub(crate) struct IpDocumentation;

impl ToDocumentationString for IpDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("ip() *(parse string and convert to ipaddr)*")
            .header("Usage:")
            .code_block("cedar", "ip(<string>)")
            .paragraph(indoc! {"
                Function that parses the string and attempts to convert it to type ipaddr.
                If the string doesn't represent a valid IP address or range, then the ip()
                expression generates an error when evaluated."
            })
            .paragraph(indoc! {"
                Cedar can properly evaluate ip(e) where e is any Cedar expression that evaluates
                to a valid string. For example, the expression ip(if true then \"1.1.1.1/24\" else \"2.1.1.1/32\")
                will evaluate to the IP address 1.1.1.1/24. However, Cedar's policy validator only
                permits e to be a string literal."
            })
            .header("Examples:")
            .paragraph(indoc! {"
                In the examples below, suppose context.addr is \"12.25.27.15\" while context.date
                is \"12/27/91\". Examples labeled error indicate both a validation and evaluation error.
                Unlabeled examples evaluate and validate correctly."
            })
            .code_block("cedar", indoc! {"
                ip(\"127.0.0.1\")
                ip(\"::1\")
                ip(\"127.0.0.1/24\")
                ip(\"ffee::/64\")
                ip(\"ff00::2\")
                ip(\"::2\")
                ip(context.addr)                    //Evaluates //Doesn't validate (parameter not a string literal)
                ip(context.time)                    //error - invalid format (not valid as parameter not a string literal)
                ip(\"380.0.0.1\")                     //error – invalid IPv4 address
                ip(\"ab.ab.ab.ab\")                   //error – invalid IPv4 address"
            })
            .header("Comparison Examples:")
            .code_block("cedar", indoc! {"
                ip(\"127.0.0.1\") == ip(\"127.0.0.1\")            //true
                ip(\"192.168.0.1\") == ip(\"8.8.8.8\")            //false
                ip(\"192.168.0.1/24\") == ip(\"8.8.8.8/8\")       //false
                ip(\"192.168.0.1/24\") == ip(\"192.168.0.8/24\")  //false - different host address
                ip(\"127.0.0.1\") == ip(\"::1\")                  //false – different IP versions
                ip(\"127.0.0.1\") == ip(\"192.168.0.1/24\")       //false - address compared to range"
            })
            .paragraph(indoc! {"
                **Note:** IP address comparisons must be between values of the same type.
                Comparing IP addresses with strings or other types will fail validation."
            })
            .build()
    }
}

pub(crate) struct IsIpv4Documentation;

impl ToDocumentationString for IsIpv4Documentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("isIpv4() *(IPv4 address valid test)*")
            .header("Usage:")
            .code_block("cedar", "<ipaddr>.isIpv4()")
            .paragraph(indoc! {"
                Evaluates to true if the receiver is an IPv4 address; evaluates (and validates)
                to an error if receiver does not have ipaddr type. This function takes no operand."
            })
            .header("Examples:")
            .paragraph(indoc! {"
                In the examples that follow, those labeled //error both evaluate and validate to an error."
            })
            .code_block("cedar", indoc! {"
                ip(\"127.0.0.1\").isIpv4()     //true
                ip(\"::1\").isIpv4()           //false
                ip(\"127.0.0.1/24\").isIpv4()  //true
                context.foo.isIpv4()         //error if `context.foo` is not an `ipaddr`"
            })
            .build()
    }
}

pub(crate) struct IsIpv6Documentation;

impl ToDocumentationString for IsIpv6Documentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("isIpv6() *(IPv6 address valid test)*")
            .header("Usage:")
            .code_block("cedar", "<ipaddr>.isIpv6()")
            .paragraph(indoc! {"
                Function that evaluates to true if the receiver is an IPv6 address;
                evaluates (and validates) to an error if received does not have ipaddr type.
                This function takes no operand."
            })
            .header("Examples:")
            .paragraph("In the examples that follow, those labeled //error both evaluate and validate to an error.")
            .code_block("cedar", indoc! {"
                ip(\"127.0.0.1/24\").isIpv6()  //false
                ip(\"ffee::/64\").isIpv6()     //true
                ip(\"::1\").isIpv6()           //true
                context.foo.isIpv6()         //error if `context.foo` is not an `ipaddr`"
            })
            .build()
    }
}

pub(crate) struct IsLoopbackDocumentation;

impl ToDocumentationString for IsLoopbackDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("isLoopback() *(test for IP loopback address)*")
            .header("Usage:")
            .code_block("cedar", "<ipaddr>.isLoopback()")
            .paragraph(indoc! {"
                Function that evaluates to true if the receiver is a valid loopback address
                for its IP version type; evaluates (and validates) to an error if receiver
                does not have ipaddr type. This function takes no operand."
            })
            .header("Examples:")
            .paragraph("In the examples that follow, those labeled //error both evaluate and validate to an error.")
            .code_block("cedar", indoc! {"
                ip(\"127.0.0.2\").isLoopback()  //true
                ip(\"::1\").isLoopback()        //true
                ip(\"::2\").isLoopback()        //false
                context.foo.isLoopback()      //error if `context.foo` is not an `ipaddr`"
            })
            .build()
    }
}

pub(crate) struct IsMulticastDocumentation;

impl ToDocumentationString for IsMulticastDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("isMulticast() *(test for multicast address)*")
            .header("Usage:")
            .code_block("cedar", "<ipaddr>.isMulticast()")
            .paragraph(indoc! {"
                Function that evaluates to true if the receiver is a multicast address
                for its IP version type; evaluates (and validates) to an error if receiver
                does not have ipaddr type. This function takes no operand."
            })
            .header("Examples:")
            .paragraph("In the examples that follow, those labeled //error both evaluate and validate to an error.")
            .code_block("cedar", indoc! {"
                ip(\"127.0.0.1\").isMulticast()  //false
                ip(\"ff00::2\").isMulticast()    //true
                context.foo.isMulticast()      //error if `context.foo` is not an `ipaddr`"
            })
            .build()
    }
}

pub(crate) struct IsInRangeDocumentation;

impl ToDocumentationString for IsInRangeDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> String {
        MarkdownBuilder::new()
            .header("isInRange() *(test for inclusion in IP address range)*")
            .header("Usage:")
            .code_block("cedar", "<ipaddr>.isInRange(<ipaddr>)")
            .paragraph(indoc! {"
                Function that evaluates to true if the receiver is an IP address or a range
                of addresses that fall completely within the range specified by the operand.
                This function evaluates (and validates) to an error if either operand does
                not have ipaddr type."
            })
            .header("Examples:")
            .paragraph("In the examples that follow, those labeled //error both evaluate and validate to an error.")
            .code_block("cedar", indoc! {"
                ip(\"192.168.0.1\").isInRange(ip(\"192.168.0.1/24\"))   //true
                ip(\"192.168.0.1\").isInRange(ip(\"192.168.0.1/28\"))   //true
                ip(\"192.168.0.75\").isInRange(ip(\"192.168.0.1/24\"))  //true
                ip(\"192.168.0.75\").isInRange(ip(\"192.168.0.1/28\"))  //false
                ip(\"1:2:3:4::\").isInRange(ip(\"1:2:3:4::/48\"))       //true
                ip(\"192.168.0.1\").isInRange(ip(\"1:2:3:4::\"))        //false
                ip(\"192.168.0.1\").isInRange(1)                      //error - operand is not an ipaddr
                context.foo.isInRange(ip(\"192.168.0.1/24\"))         //error if `context.foo` is not an `ipaddr`"
            })
            .build()
    }
}
