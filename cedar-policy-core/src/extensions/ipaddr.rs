/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

//! This module contains the Cedar 'ipaddr' extension.

use crate::ast::{
    CallStyle, Extension, ExtensionFunction, ExtensionOutputValue, ExtensionValue,
    ExtensionValueWithArgs, Literal, Name, StaticallyTyped, Type, Value,
};
use crate::entities::SchemaType;
use crate::evaluator;
use std::sync::Arc;

// PANIC SAFETY All the names are valid names
#[allow(clippy::expect_used)]
mod names {
    use super::Name;
    lazy_static::lazy_static! {
        pub static ref EXTENSION_NAME : Name = Name::parse_unqualified_name("ipaddr").expect("should be a valid identifier");
        pub static ref IP_FROM_STR_NAME : Name = Name::parse_unqualified_name("ip").expect("should be a valid identifier");
        pub static ref IS_IPV4 : Name = Name::parse_unqualified_name("isIpv4").expect("should be a valid identifier");
        pub static ref IS_IPV6 : Name = Name::parse_unqualified_name("isIpv6").expect("should be a valid identifier");
        pub static ref IS_LOOPBACK : Name = Name::parse_unqualified_name("isLoopback").expect("should be a valid identifier");
        pub static ref IS_MULTICAST : Name = Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier");
        pub static ref IS_IN_RANGE : Name = Name::parse_unqualified_name("isInRange").expect("should be a valid identifier");
    }
}

/// Help message to display when a String was provided where an IP value was expected.
/// This error is likely due to confusion between "127.0.0.1" and ip("127.0.0.1").
const ADVICE_MSG: &str = "Maybe you forgot to apply the `ip` constructor?";

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
struct IPAddr {
    /// the actual address, without subnet
    addr: std::net::IpAddr,
    /// Subnet -- the part after the `/` in CIDR.
    /// A single address will have `32` here (in the IPv4 case) or `128` (in the IPv6 case).
    subnet: u8,
}

impl IPAddr {
    /// The Cedar typename of all ipaddr values
    fn typename() -> Name {
        names::EXTENSION_NAME.clone()
    }

    /// Convert an IP address or subnet, given as a string, into an `IPAddr`
    /// value.
    ///
    /// This accepts both IPv4 and IPv6 addresses, in their standard text
    /// formats. It also accepts both single addresses (like `"10.1.1.0"`) and
    /// subnets (like `"10.1.1.0/24"`).
    /// It does not accept IPv4 addresses embedded in IPv6 (e.g., `"::ffff:192.168.0.1"`).
    /// These addresses can be written as hexadecimal IPv6. Comparisons between any IPv4 address
    ///  and any IPv6 address (including an IPv4 address embedded in IPv6) is false (e.g.,
    ///  `isLoopback("::ffff:ff00:1")` is `false`)
    fn from_str(str: impl AsRef<str>) -> Result<Self, String> {
        // Delegate to `FromStr` implementation
        str.as_ref().parse()
    }

    /// Return true if this is an IPv4 address
    fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// Return true if this is an IPv6 address
    fn is_ipv6(&self) -> bool {
        self.addr.is_ipv6()
    }

    /// Return true if this is a loopback address
    fn is_loopback(&self) -> bool {
        // Loopback addresses are "127.0.0.0/8" for IpV4 and "::1" for IpV6
        // Unlike the implementation of `is_multicast`, we don't need to test prefix
        // The reason for IpV6 is obvious: There's only one loopback address
        // The reason for IpV4 is that provided the truncated ip address is a loopback address, its prefix cannot be less than 8 because otherwise its more significant byte cannot be 127
        self.addr.is_loopback()
    }

    /// Return true if this is a multicast address
    fn is_multicast(&self) -> bool {
        // Multicast addresses are "224.0.0.0/4" for IpV4 and "ff00::/8" for IpV6
        // If an ip range's addresses are multicast addresses, calling
        // `is_in_range()` over it and its associated net above should evaluate
        // to true
        // The implementation uses the property that if `ip1/prefix1` is in range
        // `ip2/prefix2`, then `ip1` is in `ip2/prefix2` and `prefix1 >= prefix2`
        self.addr.is_multicast() && self.subnet >= if self.is_ipv4() { 4 } else { 8 }
    }

    /// Return true if this is contained in the given `IPAddr`
    fn is_in_range(&self, other: &Self) -> bool {
        match (&self.addr, &other.addr) {
            (std::net::IpAddr::V4(self_v4), std::net::IpAddr::V4(other_v4)) => {
                let netmask = |subnet: u8| u32::MAX.checked_shl(32 - subnet as u32).unwrap_or(0);
                let hostmask = |subnet: u8| u32::MAX.checked_shr(subnet as u32).unwrap_or(0);

                let self_network = u32::from(*self_v4) & netmask(self.subnet);
                let other_network = u32::from(*other_v4) & netmask(other.subnet);
                let self_broadcast = u32::from(*self_v4) | hostmask(self.subnet);
                let other_broadcast = u32::from(*other_v4) | hostmask(other.subnet);
                other_network <= self_network && self_broadcast <= other_broadcast
            }
            (std::net::IpAddr::V6(self_v6), std::net::IpAddr::V6(other_v6)) => {
                let netmask = |subnet: u8| u128::MAX.checked_shl(128 - subnet as u32).unwrap_or(0);
                let hostmask = |subnet: u8| u128::MAX.checked_shr(subnet as u32).unwrap_or(0);

                let self_network = u128::from(*self_v6) & netmask(self.subnet);
                let other_network = u128::from(*other_v6) & netmask(other.subnet);
                let self_broadcast = u128::from(*self_v6) | hostmask(self.subnet);
                let other_broadcast = u128::from(*other_v6) | hostmask(other.subnet);
                other_network <= self_network && self_broadcast <= other_broadcast
            }
            (_, _) => false,
        }
    }
}

impl std::str::FromStr for IPAddr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Return Err if string is IPv4 embedded in IPv6 format
        str_contains_colons_and_dots(s)?;

        match std::net::IpAddr::from_str(s) {
            Ok(singleaddr) => Ok(Self {
                addr: singleaddr,
                subnet: if singleaddr.is_ipv4() { 32 } else { 128 },
            }),
            Err(e1) => match s.split_once('/') {
                Some((addr, subnet)) => {
                    // `addr` (the part before the slash) should be a valid IP address,
                    // while `subnet` should be a valid u8 representing the subnet
                    let addr: std::net::IpAddr = addr.parse().map_err(|e| {
                        format!("error parsing IP address from the string `{addr}`: {e}")
                    })?;
                    let subnet: u8 = subnet.parse().map_err(|e| {
                        format!("error parsing subnet from the string `{subnet}`: {e}")
                    })?;
                    if addr.is_ipv4() && subnet > 32 {
                        Err(format!("invalid IPv4 subnet: {subnet}"))
                    } else if addr.is_ipv6() && subnet > 128 {
                        Err(format!("invalid IPv6 subnet: {subnet}"))
                    } else {
                        Ok(Self { addr, subnet })
                    }
                }
                None => Err(format!("invalid IP address: {e1}")),
            },
        }
    }
}

impl std::fmt::Display for IPAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.subnet)
    }
}

impl ExtensionValue for IPAddr {
    fn typename(&self) -> Name {
        Self::typename()
    }
}

fn extension_err(msg: impl Into<String>) -> evaluator::EvaluationError {
    evaluator::EvaluationError::failed_extension_function_application(
        names::EXTENSION_NAME.clone(),
        msg.into(),
    )
}

/// Check whether `s` contains at least three occurences of `c`
fn contains_at_least_two(s: &str, c: char) -> bool {
    let idx = s.find(c);
    match idx {
        Some(i) => {
            // PANIC SAFETY `i` is guaranteed to be < `s.len()`, so this won't panic
            #[allow(clippy::indexing_slicing)]
            let idx = s[i + 1..].find(c);
            idx.is_some()
        }
        None => false,
    }
}

/// To try to avoid confusion, we currently refuse to parse IPv4 embeded in IPv6.
/// Specificially, we reject string reprsentations of IPv4-Compatible IPv6 addresses and IPv4-Mapped IPv6 addresses (https://doc.rust-lang.org/std/net/struct.Ipv6Addr.html#embedding-ipv4-addresses).
/// These addresses mix colon and dot notation: (e.g., "::ffff:192.168.0.1" and "::127.0.0.1")
/// We will, though, parse IPv4 embedded in IPv6 if it is provided in "normal" IPv6 format (e.g., "::ffff:ff00:1"). Such addresses are treated as IPv6 addresses
/// These addresses must contain at least two colons and three periods. (We check for more than one to allow adding IPv4 addresses with ports in the future)
/// To simplify the implementation, we reject addresses with at least two colons and two periods.
fn str_contains_colons_and_dots(s: &str) -> Result<(), String> {
    if contains_at_least_two(s, ':') && contains_at_least_two(s, '.') {
        return Err(format!(
            "error parsing IP address from string: We do not accept IPv4 embedded in IPv6 (e.g., ::ffff:127.0.0.1). Found: `{}`", &s.to_string()));
    }
    Ok(())
}

/// Cedar function which constructs an `ipaddr` Cedar type from a
/// Cedar string
fn ip_from_str(arg: Value) -> evaluator::Result<ExtensionOutputValue> {
    let str = arg.get_as_string()?;
    let function_name = names::IP_FROM_STR_NAME.clone();
    let ipaddr = ExtensionValueWithArgs::new(
        Arc::new(IPAddr::from_str(str.as_str()).map_err(extension_err)?),
        vec![arg.into()],
        function_name,
    );
    Ok(Value::ExtensionValue(Arc::new(ipaddr)).into())
}

fn as_ipaddr(v: &Value) -> Result<&IPAddr, evaluator::EvaluationError> {
    match v {
        Value::ExtensionValue(ev) if ev.typename() == IPAddr::typename() => {
            // PANIC SAFETY Conditional above performs a typecheck
            #[allow(clippy::expect_used)]
            let ipaddr = ev
                .value()
                .as_any()
                .downcast_ref::<IPAddr>()
                .expect("already typechecked, so this downcast should succeed");
            Ok(ipaddr)
        }
        Value::Lit(Literal::String(_)) => Err(evaluator::EvaluationError::type_error_with_advice(
            vec![Type::Extension {
                name: IPAddr::typename(),
            }],
            v.type_of(),
            ADVICE_MSG.into(),
        )),
        _ => Err(evaluator::EvaluationError::type_error(
            vec![Type::Extension {
                name: IPAddr::typename(),
            }],
            v.type_of(),
        )),
    }
}

/// Cedar function which tests whether an `ipaddr` Cedar type is an IPv4
/// address, returning a Cedar bool
fn is_ipv4(arg: Value) -> evaluator::Result<ExtensionOutputValue> {
    let ipaddr = as_ipaddr(&arg)?;
    Ok(ipaddr.is_ipv4().into())
}

/// Cedar function which tests whether an `ipaddr` Cedar type is an IPv6
/// address, returning a Cedar bool
fn is_ipv6(arg: Value) -> evaluator::Result<ExtensionOutputValue> {
    let ipaddr = as_ipaddr(&arg)?;
    Ok(ipaddr.is_ipv6().into())
}

/// Cedar function which tests whether an `ipaddr` Cedar type is a
/// loopback address, returning a Cedar bool
fn is_loopback(arg: Value) -> evaluator::Result<ExtensionOutputValue> {
    let ipaddr = as_ipaddr(&arg)?;
    Ok(ipaddr.is_loopback().into())
}

/// Cedar function which tests whether an `ipaddr` Cedar type is a
/// multicast address, returning a Cedar bool
fn is_multicast(arg: Value) -> evaluator::Result<ExtensionOutputValue> {
    let ipaddr = as_ipaddr(&arg)?;
    Ok(ipaddr.is_multicast().into())
}

/// Cedar function which tests whether the first `ipaddr` Cedar type is
/// in the IP range represented by the second `ipaddr` Cedar type, returning
/// a Cedar bool
fn is_in_range(child: Value, parent: Value) -> evaluator::Result<ExtensionOutputValue> {
    let child_ip = as_ipaddr(&child)?;
    let parent_ip = as_ipaddr(&parent)?;
    Ok(child_ip.is_in_range(parent_ip).into())
}

/// Construct the extension
pub fn extension() -> Extension {
    let ipaddr_type = SchemaType::Extension {
        name: IPAddr::typename(),
    };
    Extension::new(
        names::EXTENSION_NAME.clone(),
        vec![
            ExtensionFunction::unary(
                names::IP_FROM_STR_NAME.clone(),
                CallStyle::FunctionStyle,
                Box::new(ip_from_str),
                ipaddr_type.clone(),
                Some(SchemaType::String),
            ),
            ExtensionFunction::unary(
                names::IS_IPV4.clone(),
                CallStyle::MethodStyle,
                Box::new(is_ipv4),
                SchemaType::Bool,
                Some(ipaddr_type.clone()),
            ),
            ExtensionFunction::unary(
                names::IS_IPV6.clone(),
                CallStyle::MethodStyle,
                Box::new(is_ipv6),
                SchemaType::Bool,
                Some(ipaddr_type.clone()),
            ),
            ExtensionFunction::unary(
                names::IS_LOOPBACK.clone(),
                CallStyle::MethodStyle,
                Box::new(is_loopback),
                SchemaType::Bool,
                Some(ipaddr_type.clone()),
            ),
            ExtensionFunction::unary(
                names::IS_MULTICAST.clone(),
                CallStyle::MethodStyle,
                Box::new(is_multicast),
                SchemaType::Bool,
                Some(ipaddr_type.clone()),
            ),
            ExtensionFunction::binary(
                names::IS_IN_RANGE.clone(),
                CallStyle::MethodStyle,
                Box::new(is_in_range),
                SchemaType::Bool,
                (Some(ipaddr_type.clone()), Some(ipaddr_type)),
            ),
        ],
    )
}

// PANIC SAFETY: Unit Test Code
#[allow(clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Expr, Type, Value};
    use crate::evaluator::test::{basic_entities, basic_request};
    use crate::evaluator::Evaluator;
    use crate::extensions::Extensions;
    use crate::parser::parse_expr;
    use cool_asserts::assert_matches;

    /// This helper function asserts that a `Result` is actually an
    /// `Err::ExtensionErr` with our extension name
    fn assert_ipaddr_err<T>(res: evaluator::Result<T>) {
        match res {
            Err(e) => match e.error_kind() {
                evaluator::EvaluationErrorKind::FailedExtensionFunctionApplication {
                    extension_name,
                    ..
                } => {
                    assert_eq!(
                        *extension_name,
                        Name::parse_unqualified_name("ipaddr")
                            .expect("should be a valid identifier")
                    )
                }
                _ => panic!("Expected an ipaddr ExtensionErr, got {:?}", e),
            },
            Ok(_) => panic!("Expected an ipaddr ExtensionErr, got Ok"),
        }
    }

    /// This helper function returns an `Expr` that calls `ip()` with the given single argument
    fn ip(arg: impl Into<Literal>) -> Expr {
        Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val(arg)],
        )
    }

    /// this test just ensures that the right functions are marked constructors
    #[test]
    fn constructors() {
        let ext = extension();
        assert!(ext
            .get_func(&Name::parse_unqualified_name("ip").expect("should be a valid identifier"))
            .expect("function should exist")
            .is_constructor());
        assert!(!ext
            .get_func(
                &Name::parse_unqualified_name("isIpv4").expect("should be a valid identifier")
            )
            .expect("function should exist")
            .is_constructor());
        assert!(!ext
            .get_func(
                &Name::parse_unqualified_name("isIpv6").expect("should be a valid identifier")
            )
            .expect("function should exist")
            .is_constructor());
        assert!(!ext
            .get_func(
                &Name::parse_unqualified_name("isLoopback").expect("should be a valid identifier")
            )
            .expect("function should exist")
            .is_constructor());
        assert!(!ext
            .get_func(
                &Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier")
            )
            .expect("function should exist")
            .is_constructor());
        assert!(!ext
            .get_func(
                &Name::parse_unqualified_name("isInRange").expect("should be a valid identifier")
            )
            .expect("function should exist")
            .is_constructor(),);
    }

    #[test]
    fn ip_creation() {
        let ext_array = [extension()];
        let exts = Extensions::specific_extensions(&ext_array);
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(&request, &entities, &exts).unwrap();

        // test that normal stuff still works with ipaddr extension enabled
        assert_eq!(
            eval.interpret_inline_policy(
                &parse_expr(r#""pancakes" like "pan*""#).expect("parsing error")
            ),
            Ok(Value::from(true))
        );

        // test that an ipv4 address parses from string and isIpv4 but not isIpv6
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv4").expect("should be a valid identifier"),
                vec![ip("127.0.0.1")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv6").expect("should be a valid identifier"),
                vec![ip("127.0.0.1")]
            )),
            Ok(Value::from(false))
        );

        // test that an ipv6 address parses from string and isIpv6 but not isIpv4
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv4").expect("should be a valid identifier"),
                vec![ip("::1")]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv6").expect("should be a valid identifier"),
                vec![ip("::1")]
            )),
            Ok(Value::from(true))
        );

        // test that parsing hexadecimal IPv4 embeded in IPv6 address parses from string and isIpv6 but not isIpv4
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv4").expect("should be a valid identifier"),
                vec![ip("::ffff:ff00:1")]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv6").expect("should be a valid identifier"),
                vec![ip("::ffff:ff00:1")]
            )),
            Ok(Value::from(true))
        );

        // test for parse errors when parsing from string
        assert_ipaddr_err(eval.interpret_inline_policy(&ip("380.0.0.1")));
        assert_ipaddr_err(eval.interpret_inline_policy(&ip("?")));
        assert_ipaddr_err(eval.interpret_inline_policy(&ip("ab.ab.ab.ab")));
        assert_ipaddr_err(eval.interpret_inline_policy(&ip("foo::1")));
        //Test parsing IPv4 embedded in IPv6 is an error
        assert_ipaddr_err(eval.interpret_inline_policy(&ip("::ffff:127.0.0.1")));
        assert_ipaddr_err(eval.interpret_inline_policy(&ip("::127.0.0.1")));
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                vec![Expr::set(vec!(
                    Expr::val(127),
                    Expr::val(0),
                    Expr::val(0),
                    Expr::val(1)
                ))]
            )),
            Err(evaluator::EvaluationError::type_error(
                vec![Type::String],
                Type::Set
            ))
        );

        // test that < on ipaddr values is an error
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(ip("127.0.0.1"), ip("10.0.0.10"))),
            Err(evaluator::EvaluationError::type_error(
                vec![Type::Long],
                Type::Extension {
                    name: Name::parse_unqualified_name("ipaddr")
                        .expect("should be a valid identifier")
                },
            ))
        );
        // test that isIpv4 on a String is an error
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv4").expect("should be a valid identifier"),
                vec![Expr::val("127.0.0.1")]
            )),
            Err(evaluator::EvaluationError::type_error_with_advice(
                vec![Type::Extension {
                    name: Name::parse_unqualified_name("ipaddr")
                        .expect("should be a valid identifier")
                }],
                Type::String,
                ADVICE_MSG.into(),
            ))
        );

        // test the Display impl
        assert_eq!(
            eval.interpret_inline_policy(&ip("127.0.0.1"))
                .unwrap()
                .to_string(),
            "127.0.0.1/32"
        );
        assert_eq!(
            eval.interpret_inline_policy(&ip("ffee::11"))
                .unwrap()
                .to_string(),
            "ffee::11/128"
        );
    }

    #[test]
    fn ip_range_creation() {
        let ext_array = [extension()];
        let exts = Extensions::specific_extensions(&ext_array);
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(&request, &entities, &exts).unwrap();

        // test that an ipv4 range parses from string and isIpv4 but not isIpv6
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv4").expect("should be a valid identifier"),
                vec![ip("127.0.0.1/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv6").expect("should be a valid identifier"),
                vec![ip("127.0.0.1/24")]
            )),
            Ok(Value::from(false))
        );

        // test that an ipv6 range parses from string and isIpv6 but not isIpv4
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv4").expect("should be a valid identifier"),
                vec![ip("ffee::/64")]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv6").expect("should be a valid identifier"),
                vec![ip("ffee::/64")]
            )),
            Ok(Value::from(true))
        );

        // test the extremes of valid values for subnet
        assert_matches!(eval.interpret_inline_policy(&ip("127.0.0.1/0")), Ok(_));
        assert_matches!(eval.interpret_inline_policy(&ip("127.0.0.1/32")), Ok(_));
        assert_matches!(eval.interpret_inline_policy(&ip("ffee::/0")), Ok(_));
        assert_matches!(eval.interpret_inline_policy(&ip("ffee::/128")), Ok(_));

        // test for parse errors related to subnets specifically
        assert_ipaddr_err(eval.interpret_inline_policy(&ip("127.0.0.1/8/24")));
        assert_ipaddr_err(eval.interpret_inline_policy(&ip("fee::/64::1")));
        assert_ipaddr_err(eval.interpret_inline_policy(&ip("172.0.0.1/64")));
        assert_ipaddr_err(eval.interpret_inline_policy(&ip("ffee::/132")));

        // test the Display impl
        assert_eq!(
            eval.interpret_inline_policy(&ip("127.0.0.1/0"))
                .unwrap()
                .to_string(),
            "127.0.0.1/0"
        );
        assert_eq!(
            eval.interpret_inline_policy(&ip("127.0.0.1/8"))
                .unwrap()
                .to_string(),
            "127.0.0.1/8"
        );
        assert_eq!(
            eval.interpret_inline_policy(&ip("127.0.0.1/32"))
                .unwrap()
                .to_string(),
            "127.0.0.1/32"
        );
        assert_eq!(
            eval.interpret_inline_policy(&ip("ffee::/64"))
                .unwrap()
                .to_string(),
            "ffee::/64"
        );
    }

    #[test]
    fn ip_equality() {
        let ext_array = [extension()];
        let exts = Extensions::specific_extensions(&ext_array);
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(&request, &entities, &exts).unwrap();

        // basic equality tests
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("127.0.0.1"), ip("127.0.0.1"))),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("192.168.0.1"), ip("8.8.8.8"))),
            Ok(Value::from(false))
        );

        // weirder equality tests: ipv4 address vs ipv6 address, ip address vs string, ip address vs int
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("127.0.0.1"), ip("::1"))),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("127.0.0.1"), Expr::val("127.0.0.1"))),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("::1"), Expr::val(1))),
            Ok(Value::from(false))
        );

        // ip address vs range
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("127.0.0.1"), ip("192.168.0.1/24"))),
            Ok(Value::from(false))
        );
        // range vs range
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("192.168.0.1/24"), ip("8.8.8.8/8"))),
            Ok(Value::from(false))
        );
    }

    #[test]
    fn is_loopback_and_is_multicast() {
        let ext_array = [extension()];
        let exts = Extensions::specific_extensions(&ext_array);
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(&request, &entities, &exts).unwrap();

        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isLoopback").expect("should be a valid identifier"),
                vec![ip("127.0.0.2")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isLoopback").expect("should be a valid identifier"),
                vec![ip("::1")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isLoopback").expect("should be a valid identifier"),
                vec![ip("::2")]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![ip("228.228.228.0")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![ip("224.0.0.0/3")]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![ip("224.0.0.0/5")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![ip("ff00::/7")]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![ip("ff00::/9")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![ip("127.0.0.1")]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![ip("127.0.0.1/1")]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![ip("ff00::2")]
            )),
            Ok(Value::from(true))
        );
    }

    #[test]
    fn ip_is_in_range() {
        let ext_array = [extension()];
        let exts = Extensions::specific_extensions(&ext_array);
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(&request, &entities, &exts).unwrap();

        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("192.168.0.1/24"), ip("192.168.0.1/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("192.168.0.1"), ip("192.168.0.1/28")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("192.168.0.10"), ip("192.168.0.1/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("192.168.0.10"), ip("192.168.0.1/28")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("192.168.0.75"), ip("192.168.0.1/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("192.168.0.75"), ip("192.168.0.1/28")]
            )),
            Ok(Value::from(false))
        );
        // single address is implicitly a /32 range here
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("192.168.0.1"), ip("192.168.0.1")]
            )),
            Ok(Value::from(true))
        );

        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("1:2:3:4::"), ip("1:2:3:4::/48")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("1:2:3:4::"), ip("1:2:3:4::/52")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("1:2:3:6::"), ip("1:2:3:4::/48")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("1:2:3:6::"), ip("1:2:3:4::/52")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("1:2:3:ffff::"), ip("1:2:3:4::/48")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("1:2:3:ffff::"), ip("1:2:3:4::/52")]
            )),
            Ok(Value::from(false))
        );
        // single address is implicitly a /128 range here
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("1:2:3:4::"), ip("1:2:3:4::")]
            )),
            Ok(Value::from(true))
        );

        // test that ipv4 address is not in an ipv6 range
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("192.168.0.1"), ip("1:2:3:4::/48")]
            )),
            Ok(Value::from(false))
        );
    }

    #[test]
    fn more_ip_semantics() {
        let ext_array = [extension()];
        let exts = Extensions::specific_extensions(&ext_array);
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(&request, &entities, &exts).unwrap();

        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("10.0.0.0"), ip("10.0.0.0"))),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("10.0.0.0"), ip("10.0.0.1"))),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("10.0.0.0/32"), ip("10.0.0.0"))),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("10.0.0.0/24"), ip("10.0.0.0"))),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("10.0.0.0/32"), ip("10.0.0.0/32"))),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("10.0.0.0/24"), ip("10.0.0.0/32"))),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("10.0.0.0/24"), ip("10.0.0.1/24"))),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ip("10.0.0.1/24"), ip("10.0.0.1/29"))),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.0"), ip("10.0.0.0/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.0"), ip("10.0.0.0/32")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.0"), ip("10.0.0.1/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.0"), ip("10.0.0.1/32")]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.1"), ip("10.0.0.0/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.1"), ip("10.0.0.1/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.0/24"), ip("10.0.0.0/32")]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.0/32"), ip("10.0.0.0/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.1/24"), ip("10.0.0.0/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.1/24"), ip("10.0.0.1/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.0/24"), ip("10.0.0.1/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.0/24"), ip("10.0.0.0/29")]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.0/29"), ip("10.0.0.0/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.0/24"), ip("10.0.0.1/29")]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.0/29"), ip("10.0.0.1/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.1/24"), ip("10.0.0.0/29")]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.1/29"), ip("10.0.0.0/24")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.0/32"), ip("10.0.0.0/32")]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ip("10.0.0.0/32"), ip("10.0.0.0")]
            )),
            Ok(Value::from(true))
        );
        assert_ipaddr_err(eval.interpret_inline_policy(&Expr::call_extension_fn(
            Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
            vec![ip("10.0.0.0/33"), ip("10.0.0.0/32")],
        )));
    }

    #[test]
    fn test_contains_at_least_two() {
        assert!(contains_at_least_two(":::", ':'));
        assert!(contains_at_least_two("::", ':'));
        assert!(!contains_at_least_two(":", ':'));
    }
}
