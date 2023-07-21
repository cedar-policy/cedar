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
    ExtensionValueWithArgs, Name, StaticallyTyped, Type, Value,
};
use crate::entities::SchemaType;
use crate::evaluator;
use std::str::FromStr;
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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
struct IPAddr {
    /// the actual address, represented internally as an `IpNet`.
    /// A single address is represented as an `IpNet` containing only one address.
    addr: ipnet::IpNet,
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
    /// formats. It also accepts both single addresses (like "10.1.1.0") and
    /// subnets (like "10.1.1.0/24").
    /// It does not accept IPv4 addresses embedded in IPv6 (e.g., "::ffff:192.168.0.1")
    /// These addresses can be written as hexadecimal IPv6. Comparisons between any IPv4 address
    ///  and any IPv6 address (including an IPv4 address embedded in IPv6) is false (e.g., isLoopback("::ffff:ff00:1") == false)
    fn from_str(str: impl AsRef<str>) -> Result<Self, String> {
        //Return Err if string is IPv4 embedded in IPv6 format
        str_contains_colons_and_dots(str.as_ref())?;

        let addr = match std::net::IpAddr::from_str(str.as_ref()) {
            Ok(singleaddr) => ipnet::IpNet::from(singleaddr),
            Err(e1) => match parse_ipnet(str.as_ref()) {
                Ok(net) => net.trunc(),
                Err(e2) => return Err(format!(
                    "error parsing IP address from string:\n  failed to parse as single address: {}\n  failed to parse as subnet: {}", e1, e2)),
            }
        };
        Ok(Self { addr })
    }

    /// Return true if this is an IPv4 address
    fn is_ipv4(&self) -> bool {
        self.addr.addr().is_ipv4()
    }

    /// Return true if this is an IPv6 address
    fn is_ipv6(&self) -> bool {
        self.addr.addr().is_ipv6()
    }

    /// Return true if this is a loopback address
    fn is_loopback(&self) -> bool {
        // Loopback addresses are "127.0.0.0/8" for IpV4 and "::1" for IpV6
        // Unlike the implementation of `is_multicast`, we don't need to test prefix
        // The reason for IpV6 is obvious: There's only one loopback address
        // The reason for IpV4 is that provided the truncated ip address is a loopback address, its prefix cannot be less than 8 because otherwise its more significant byte cannot be 127
        self.addr.addr().is_loopback()
    }

    /// Return true if this is a multicast address
    fn is_multicast(&self) -> bool {
        // Multicast addresses are "224.0.0.0/4" for IpV4 and "ff00::/8" for IpV6
        // If an IpNet's addresses are multicast addresses, calling `is_in_range()` over it and its associated net above should evaluate to true
        // The implementation uses the property that if `ip1/prefix1` is in range `ip2/prefix2`, then `ip1` is in `ip2/prefix2` and `prefix1 >= prefix2`
        self.addr.addr().is_multicast()
            && self.addr.prefix_len() >= if self.is_ipv4() { 4 } else { 8 }
    }

    /// Return true if this is contained in the given `IPAddr`
    fn is_in_range(&self, other: &Self) -> bool {
        other.addr.contains(&self.addr)
    }
}

impl std::fmt::Display for IPAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

impl ExtensionValue for IPAddr {
    fn typename(&self) -> Name {
        Self::typename()
    }
}

fn extension_err(msg: impl Into<String>) -> evaluator::EvaluationError {
    evaluator::EvaluationError::FailedExtensionFunctionApplication {
        extension_name: names::EXTENSION_NAME.clone(),
        msg: msg.into(),
    }
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

/// Parse an IP net representation
/// We split the input string by a slash
/// The first part should be a valid IP address, which along what comes after (including the slash) is further parsed by `ipnet`'s `IpNet` parser
/// This design choice is to avoid the incosistencies between `ipnet`'s and `std::net`'s treatment of IP address representations
fn parse_ipnet(s: &str) -> Result<ipnet::IpNet, String> {
    match s.split_once('/') {
        Some((addr, prefix)) => match std::net::IpAddr::from_str(addr) {
            Ok(addr) => {
                ipnet::IpNet::from_str(&format!("{}/{}", addr, prefix)).map_err(|e| e.to_string())
            }
            Err(e) => Err(e.to_string()),
        },
        None => Err("invalid IP address syntax".to_owned()),
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
            "error parsing IP address from string: We don't accept IPv4 embedded in IPv6 (e.g., ::ffff:127.0.0.1). Found: {}", &s.to_string()));
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

/// Cedar function which tests whether an `ipaddr` Cedar type is an IPv4
/// address, returning a Cedar bool
fn is_ipv4(arg: Value) -> evaluator::Result<ExtensionOutputValue> {
    let ipaddr_ev = match arg {
        Value::ExtensionValue(ev) if ev.typename() == IPAddr::typename() => ev,
        _ => {
            return Err(evaluator::EvaluationError::TypeError {
                expected: vec![Type::Extension {
                    name: IPAddr::typename(),
                }],
                actual: arg.type_of(),
            })
        }
    };
    // PANIC SAFETY Typechecking performed above
    #[allow(clippy::expect_used)]
    let ipaddr = ipaddr_ev
        .value()
        .as_any()
        .downcast_ref::<IPAddr>()
        .expect("already typechecked above, so this downcast should succeed");
    Ok(ipaddr.is_ipv4().into())
}

/// Cedar function which tests whether an `ipaddr` Cedar type is an IPv6
/// address, returning a Cedar bool
fn is_ipv6(arg: Value) -> evaluator::Result<ExtensionOutputValue> {
    let ipaddr_ev = match arg {
        Value::ExtensionValue(ev) if ev.typename() == IPAddr::typename() => ev,
        _ => {
            return Err(evaluator::EvaluationError::TypeError {
                expected: vec![Type::Extension {
                    name: IPAddr::typename(),
                }],
                actual: arg.type_of(),
            })
        }
    };
    // PANIC SAFETY Typechecking performed above
    #[allow(clippy::expect_used)]
    let ipaddr = ipaddr_ev
        .value()
        .as_any()
        .downcast_ref::<IPAddr>()
        .expect("already typechecked above, so this downcast should succeed");
    Ok(ipaddr.is_ipv6().into())
}

/// Cedar function which tests whether an `ipaddr` Cedar type is a
/// loopback address, returning a Cedar bool
fn is_loopback(arg: Value) -> evaluator::Result<ExtensionOutputValue> {
    let ipaddr_ev = match arg {
        Value::ExtensionValue(ev) if ev.typename() == IPAddr::typename() => ev,
        _ => {
            return Err(evaluator::EvaluationError::TypeError {
                expected: vec![Type::Extension {
                    name: IPAddr::typename(),
                }],
                actual: arg.type_of(),
            })
        }
    };
    // PANIC SAFETY Typechecking performed above
    #[allow(clippy::expect_used)]
    let ipaddr = ipaddr_ev
        .value()
        .as_any()
        .downcast_ref::<IPAddr>()
        .expect("already typechecked above, so this downcast should succeed");
    Ok(ipaddr.is_loopback().into())
}

/// Cedar function which tests whether an `ipaddr` Cedar type is a
/// multicast address, returning a Cedar bool
fn is_multicast(arg: Value) -> evaluator::Result<ExtensionOutputValue> {
    let ipaddr_ev = match arg {
        Value::ExtensionValue(ev) if ev.typename() == IPAddr::typename() => ev,
        _ => {
            return Err(evaluator::EvaluationError::TypeError {
                expected: vec![Type::Extension {
                    name: IPAddr::typename(),
                }],
                actual: arg.type_of(),
            })
        }
    };
    // PANIC SAFETY Typechecking performed above
    #[allow(clippy::expect_used)]
    let ipaddr = ipaddr_ev
        .value()
        .as_any()
        .downcast_ref::<IPAddr>()
        .expect("already typechecked above, so this downcast should succeed");
    Ok(ipaddr.is_multicast().into())
}

/// Cedar function which tests whether the first `ipaddr` Cedar type is
/// in the IP range represented by the second `ipaddr` Cedar type, returning
/// a Cedar bool
fn is_in_range(child: Value, parent: Value) -> evaluator::Result<ExtensionOutputValue> {
    let child_ev = match child {
        Value::ExtensionValue(ev) if ev.typename() == IPAddr::typename() => ev,
        _ => {
            return Err(evaluator::EvaluationError::TypeError {
                expected: vec![Type::Extension {
                    name: IPAddr::typename(),
                }],
                actual: child.type_of(),
            })
        }
    };
    let parent_ev = match parent {
        Value::ExtensionValue(ev) if ev.typename() == IPAddr::typename() => ev,
        _ => {
            return Err(evaluator::EvaluationError::TypeError {
                expected: vec![Type::Extension {
                    name: IPAddr::typename(),
                }],
                actual: parent.type_of(),
            })
        }
    };
    // PANIC SAFETY Typechecking performed above
    #[allow(clippy::expect_used)]
    let child_ip = child_ev
        .value()
        .as_any()
        .downcast_ref::<IPAddr>()
        .expect("already typechecked above, so this downcast should succeed");
    // PANIC SAFETY Typechecking performed above
    #[allow(clippy::expect_used)]
    let parent_ip = parent_ev
        .value()
        .as_any()
        .downcast_ref::<IPAddr>()
        .expect("already typechecked above, so this downcast should succeed");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Expr, Type, Value};
    use crate::evaluator::test::{basic_entities, basic_request};
    use crate::evaluator::Evaluator;
    use crate::extensions::Extensions;
    use crate::parser::parse_expr;

    /// This helper function asserts that a `Result` is actually an
    /// `Err::ExtensionErr` with our extension name
    fn assert_ipaddr_err<T>(res: evaluator::Result<T>) {
        match res {
            Err(evaluator::EvaluationError::FailedExtensionFunctionApplication {
                extension_name,
                ..
            }) => {
                assert_eq!(
                    extension_name,
                    Name::parse_unqualified_name("ipaddr").expect("should be a valid identifier")
                )
            }
            Err(e) => panic!("Expected an ipaddr ExtensionErr, got {:?}", e),
            Ok(_) => panic!("Expected an ipaddr ExtensionErr, got Ok"),
        }
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
        let ipv4_addr_from_string = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("127.0.0.1")],
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv4").expect("should be a valid identifier"),
                vec![ipv4_addr_from_string.clone()]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv6").expect("should be a valid identifier"),
                vec![ipv4_addr_from_string]
            )),
            Ok(Value::from(false))
        );

        // test that an ipv6 address parses from string and isIpv6 but not isIpv4
        let ipv6_addr_from_string = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("::1")],
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv4").expect("should be a valid identifier"),
                vec![ipv6_addr_from_string.clone()]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv6").expect("should be a valid identifier"),
                vec![ipv6_addr_from_string]
            )),
            Ok(Value::from(true))
        );

        // test that parsing hexadecimal IPv4 embeded in IPv6 address parses from string and isIpv6 but not isIpv4
        let ipv6_addr_from_string = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("::ffff:ff00:1")],
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv4").expect("should be a valid identifier"),
                vec![ipv6_addr_from_string.clone()]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv6").expect("should be a valid identifier"),
                vec![ipv6_addr_from_string]
            )),
            Ok(Value::from(true))
        );

        // test for parse errors when parsing from string
        assert_ipaddr_err(eval.interpret_inline_policy(&Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("380.0.0.1")],
        )));
        assert_ipaddr_err(eval.interpret_inline_policy(&Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("?")],
        )));
        assert_ipaddr_err(eval.interpret_inline_policy(&Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("ab.ab.ab.ab")],
        )));
        assert_ipaddr_err(eval.interpret_inline_policy(&Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("foo::1")],
        )));
        //Test parsing IPv4 embedded in IPv6 is an error
        assert_ipaddr_err(eval.interpret_inline_policy(&Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("::ffff:127.0.0.1")],
        )));
        assert_ipaddr_err(eval.interpret_inline_policy(&Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("::127.0.0.1")],
        )));
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
            Err(evaluator::EvaluationError::TypeError {
                expected: vec![Type::String],
                actual: Type::Set,
            })
        );

        // test that < on ipaddr values is an error
        assert_eq!(
            eval.interpret_inline_policy(&Expr::less(
                Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("127.0.0.1")],
                ),
                Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("10.0.0.10")],
                )
            )),
            Err(evaluator::EvaluationError::TypeError {
                expected: vec![Type::Long],
                actual: Type::Extension {
                    name: Name::parse_unqualified_name("ipaddr")
                        .expect("should be a valid identifier")
                },
            })
        );
        // test that isIpv4 on a String is an error
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv4").expect("should be a valid identifier"),
                vec![Expr::val("127.0.0.1")]
            )),
            Err(evaluator::EvaluationError::TypeError {
                expected: vec![Type::Extension {
                    name: Name::parse_unqualified_name("ipaddr")
                        .expect("should be a valid identifier")
                }],
                actual: Type::String,
            })
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
        let ipv4_range_from_string = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("127.0.0.1/24")],
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv4").expect("should be a valid identifier"),
                vec![ipv4_range_from_string.clone()]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv6").expect("should be a valid identifier"),
                vec![ipv4_range_from_string]
            )),
            Ok(Value::from(false))
        );

        // test that an ipv6 range parses from string and isIpv6 but not isIpv4
        let ipv6_range_from_string = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("ffee::/64")],
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv4").expect("should be a valid identifier"),
                vec![ipv6_range_from_string.clone()]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isIpv6").expect("should be a valid identifier"),
                vec![ipv6_range_from_string]
            )),
            Ok(Value::from(true))
        );

        // test for parse errors related to subnets specifically
        assert_ipaddr_err(eval.interpret_inline_policy(&Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("127.0.0.1/8/24")],
        )));
        assert_ipaddr_err(eval.interpret_inline_policy(&Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("fee::/64::1")],
        )));
        assert_ipaddr_err(eval.interpret_inline_policy(&Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("172.0.0.1/64")],
        )));
    }

    #[test]
    fn ip_equality() {
        let ext_array = [extension()];
        let exts = Extensions::specific_extensions(&ext_array);
        let request = basic_request();
        let entities = basic_entities();
        let eval = Evaluator::new(&request, &entities, &exts).unwrap();

        let ipv4_addr_a = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("127.0.0.1")],
        );
        let ipv4_addr_b = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("127.0.0.1")],
        );
        let ipv4_addr_c = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("192.168.0.1")],
        );
        let ipv4_addr_d = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("8.8.8.8")],
        );
        let ipv6_addr = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("::1")],
        );
        let ipv4_range_a = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("192.168.0.1/24")],
        );
        let ipv4_range_b = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("8.8.8.8/8")],
        );

        // basic equality tests
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ipv4_addr_a.clone(), ipv4_addr_a.clone())),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ipv4_addr_a.clone(), ipv4_addr_b)),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ipv4_addr_c, ipv4_addr_d)),
            Ok(Value::from(false))
        );

        // weirder equality tests: ipv4 address vs ipv6 address, ip address vs string, ip address vs int
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ipv4_addr_a.clone(), ipv6_addr.clone())),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ipv4_addr_a.clone(), Expr::val("127.0.0.1"))),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ipv6_addr, Expr::val(1))),
            Ok(Value::from(false))
        );

        // ip address vs range
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ipv4_addr_a, ipv4_range_a.clone())),
            Ok(Value::from(false))
        );
        // range vs range
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(ipv4_range_a, ipv4_range_b)),
            Ok(Value::from(false))
        );
        // these ranges are actually the same
        assert_eq!(
            eval.interpret_inline_policy(&Expr::is_eq(
                Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("192.168.0.1/24")]
                ),
                Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("192.168.0.8/24")]
                ),
            )),
            Ok(Value::from(true))
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
                vec![Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("127.0.0.2")]
                )]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isLoopback").expect("should be a valid identifier"),
                vec![Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("::1")]
                )]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isLoopback").expect("should be a valid identifier"),
                vec![Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("::2")]
                )]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("228.228.228.0")]
                )]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("224.0.0.0/3")]
                )]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("224.0.0.0/5")]
                )]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("ff00::/7")]
                )]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("ff00::/9")]
                )]
            )),
            Ok(Value::from(true))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("127.0.0.1")]
                )]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("127.0.0.1")]
                )]
            )),
            Ok(Value::from(false))
        );
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isMulticast").expect("should be a valid identifier"),
                vec![Expr::call_extension_fn(
                    Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
                    vec![Expr::val("ff00::2")]
                )]
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

        let ipv4_range_a = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("192.168.0.1/24")],
        );
        let ipv4_range_b = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("192.168.0.1/28")],
        );
        let ipv4_addr_a = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("192.168.0.1")],
        );
        let ipv4_addr_b = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("192.168.0.10")],
        );
        let ipv4_addr_c = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("192.168.0.75")],
        );

        // test that addr_a is in range_a
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv4_addr_a.clone(), ipv4_range_a.clone()]
            )),
            Ok(Value::from(true))
        );
        // test that addr_a is in range_b
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv4_addr_a.clone(), ipv4_range_b.clone()]
            )),
            Ok(Value::from(true))
        );
        // test that addr_b is in range_a
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv4_addr_b.clone(), ipv4_range_a.clone()]
            )),
            Ok(Value::from(true))
        );
        // test that addr_b is in range_b
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv4_addr_b, ipv4_range_b.clone()]
            )),
            Ok(Value::from(true))
        );
        // test that addr_c is in range_a
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv4_addr_c.clone(), ipv4_range_a]
            )),
            Ok(Value::from(true))
        );
        // test that addr_c is not in range_b
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv4_addr_c, ipv4_range_b]
            )),
            Ok(Value::from(false))
        );
        // test that addr_a is in addr_a (addr_a is implicitly a /32 range here)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv4_addr_a.clone(), ipv4_addr_a.clone()]
            )),
            Ok(Value::from(true))
        );

        let ipv6_range_a = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("1:2:3:4::/48")],
        );
        let ipv6_range_b = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("1:2:3:4::/52")],
        );
        let ipv6_addr_a = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("1:2:3:4::")],
        );
        let ipv6_addr_b = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("1:2:3:6::")],
        );
        let ipv6_addr_c = Expr::call_extension_fn(
            Name::parse_unqualified_name("ip").expect("should be a valid identifier"),
            vec![Expr::val("1:2:3:ffff::")],
        );

        // test that addr_a is in range_a
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv6_addr_a.clone(), ipv6_range_a.clone()]
            )),
            Ok(Value::from(true))
        );
        // test that addr_a is in range_b
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv6_addr_a.clone(), ipv6_range_b.clone()]
            )),
            Ok(Value::from(true))
        );
        // test that addr_b is in range_a
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv6_addr_b.clone(), ipv6_range_a.clone()]
            )),
            Ok(Value::from(true))
        );
        // test that addr_b is in range_b
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv6_addr_b, ipv6_range_b.clone()]
            )),
            Ok(Value::from(true))
        );
        // test that addr_c is in range_a
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv6_addr_c.clone(), ipv6_range_a.clone()]
            )),
            Ok(Value::from(true))
        );
        // test that addr_c is not in range_b
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv6_addr_c, ipv6_range_b]
            )),
            Ok(Value::from(false))
        );
        // test that addr_a is in addr_a (addr_a is implicitly a /128 range here)
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv6_addr_a.clone(), ipv6_addr_a]
            )),
            Ok(Value::from(true))
        );

        // test that ipv4 address is not in an ipv6 range
        assert_eq!(
            eval.interpret_inline_policy(&Expr::call_extension_fn(
                Name::parse_unqualified_name("isInRange").expect("should be a valid identifier"),
                vec![ipv4_addr_a, ipv6_range_a]
            )),
            Ok(Value::from(false))
        );
    }

    #[test]
    fn test_contains_at_least_two() {
        assert!(contains_at_least_two(":::", ':'));
        assert!(contains_at_least_two("::", ':'));
        assert!(!contains_at_least_two(":", ':'));
    }
}
