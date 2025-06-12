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
            .build()
    }
}
