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

use std::borrow::Cow;

use super::ToDocumentationString;
use cedar_policy_core::validator::ValidatorSchema;

pub(crate) struct ExtensionName<'a>(pub(crate) &'a str);

impl ToDocumentationString for ExtensionName<'_> {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> Cow<'static, str> {
        match self.0 {
            "ip" => IpDocumentation.to_documentation_string(schema),
            "isIpv4" => IsIpv4Documentation.to_documentation_string(schema),
            "isIpv6" => IsIpv6Documentation.to_documentation_string(schema),
            "isLoopback" => IsLoopbackDocumentation.to_documentation_string(schema),
            "isMulticast" => IsMulticastDocumentation.to_documentation_string(schema),
            "isInRange" => IsInRangeDocumentation.to_documentation_string(schema),
            "decimal" => DecimalDocumentation.to_documentation_string(schema),
            "lessThan" => DecimalLessThanDocumentation.to_documentation_string(schema),
            "lessThanOrEqual" => {
                DecimalLessThanOrEqualDocumentation.to_documentation_string(schema)
            }
            "greaterThan" => DecimalGreaterThanDocumentation.to_documentation_string(schema),
            "greaterThanOrEqual" => {
                DecimalGreaterThanOrEqualDocumentation.to_documentation_string(schema)
            }
            "datetime" => DateTimeDocumentation.to_documentation_string(schema),
            "duration" => DurationDocumentation.to_documentation_string(schema),
            "offset" => OffsetDocumentation.to_documentation_string(schema),
            "durationSince" => DurationSinceDocumentation.to_documentation_string(schema),
            "toDate" => ToDateDocumentation.to_documentation_string(schema),
            "toTime" => ToTimeDocumentation.to_documentation_string(schema),
            "toMilliseconds" => ToMillisecondsDocumentation.to_documentation_string(schema),
            "toSeconds" => ToSecondsDocumentation.to_documentation_string(schema),
            "toMinutes" => ToMinutesDocumentation.to_documentation_string(schema),
            "toHours" => ToHoursDocumentation.to_documentation_string(schema),
            "toDays" => ToDaysDocumentation.to_documentation_string(schema),
            _ => self.0.to_string().into(),
        }
    }
}

pub(crate) use decimal::*;
mod decimal {
    use crate::impl_documentation_from_markdown_file;
    impl_documentation_from_markdown_file!(
        DecimalDocumentation,
        "markdown/extension/decimal/decimal.md"
    );
    impl_documentation_from_markdown_file!(
        DecimalLessThanDocumentation,
        "markdown/extension/decimal/less_than.md"
    );
    impl_documentation_from_markdown_file!(
        DecimalLessThanOrEqualDocumentation,
        "markdown/extension/decimal/less_than_or_equal.md"
    );
    impl_documentation_from_markdown_file!(
        DecimalGreaterThanDocumentation,
        "markdown/extension/decimal/greater_than.md"
    );
    impl_documentation_from_markdown_file!(
        DecimalGreaterThanOrEqualDocumentation,
        "markdown/extension/decimal/greater_than_or_equal.md"
    );
}

pub(crate) use ip::*;
mod ip {
    use crate::impl_documentation_from_markdown_file;
    impl_documentation_from_markdown_file!(IpDocumentation, "markdown/extension/ip/ip.md");
    impl_documentation_from_markdown_file!(IsIpv4Documentation, "markdown/extension/ip/is_ipv4.md");
    impl_documentation_from_markdown_file!(IsIpv6Documentation, "markdown/extension/ip/is_ipv6.md");
    impl_documentation_from_markdown_file!(
        IsLoopbackDocumentation,
        "markdown/extension/ip/is_loopback.md"
    );
    impl_documentation_from_markdown_file!(
        IsMulticastDocumentation,
        "markdown/extension/ip/is_multicast.md"
    );
    impl_documentation_from_markdown_file!(
        IsInRangeDocumentation,
        "markdown/extension/ip/is_in_range.md"
    );
}

pub(crate) use datetime::*;
mod datetime {
    use crate::impl_documentation_from_markdown_file;
    impl_documentation_from_markdown_file!(
        DateTimeDocumentation,
        "markdown/extension/datetime/datetime.md"
    );
    impl_documentation_from_markdown_file!(
        DurationDocumentation,
        "markdown/extension/datetime/duration.md"
    );
    impl_documentation_from_markdown_file!(
        OffsetDocumentation,
        "markdown/extension/datetime/offset.md"
    );
    impl_documentation_from_markdown_file!(
        DurationSinceDocumentation,
        "markdown/extension/datetime/duration_since.md"
    );
    impl_documentation_from_markdown_file!(
        ToDateDocumentation,
        "markdown/extension/datetime/to_date.md"
    );
    impl_documentation_from_markdown_file!(
        ToTimeDocumentation,
        "markdown/extension/datetime/to_time.md"
    );
    impl_documentation_from_markdown_file!(
        ToMillisecondsDocumentation,
        "markdown/extension/datetime/to_milliseconds.md"
    );
    impl_documentation_from_markdown_file!(
        ToSecondsDocumentation,
        "markdown/extension/datetime/to_seconds.md"
    );
    impl_documentation_from_markdown_file!(
        ToMinutesDocumentation,
        "markdown/extension/datetime/to_minutes.md"
    );
    impl_documentation_from_markdown_file!(
        ToHoursDocumentation,
        "markdown/extension/datetime/to_hours.md"
    );
    impl_documentation_from_markdown_file!(
        ToDaysDocumentation,
        "markdown/extension/datetime/to_days.md"
    );
}
