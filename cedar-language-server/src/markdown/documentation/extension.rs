use crate::markdown::ToDocumentationString;
use cedar_policy_core::validator::ValidatorSchema;

mod decimal;
mod ip;

pub(crate) use decimal::*;
pub(crate) use ip::*;

pub(crate) struct ExtensionName<'a>(pub(crate) &'a str);

impl ToDocumentationString for ExtensionName<'_> {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> String {
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
            _ => self.0.to_string(),
        }
    }
}
