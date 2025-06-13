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

use crate::impl_documentation_from_markdown_file;

use super::ToDocumentationString;

impl_documentation_from_markdown_file!(IpDocumentation, "../markdown/extension_ip.md");
impl_documentation_from_markdown_file!(IsIpv4Documentation, "../markdown/extension_ip_is_ipv4.md");
impl_documentation_from_markdown_file!(IsIpv6Documentation, "../markdown/extension_ip_is_ipv6.md");
impl_documentation_from_markdown_file!(
    IsLoopbackDocumentation,
    "../markdown/extension_ip_is_loopback.md"
);
impl_documentation_from_markdown_file!(
    IsMulticastDocumentation,
    "../markdown/extension_ip_is_multicast.md"
);
impl_documentation_from_markdown_file!(
    IsInRangeDocumentation,
    "../markdown/extension_ip_is_in_range.md"
);
