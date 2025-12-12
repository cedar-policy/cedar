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

//! This module defines Cedar decimal values and functions.
//! It is based on
//! <https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/Cedar/Spec/Ext/Decimal.lean>

// A decimal number consists of an integer part and a fractional part.
// The former is the integer number before the decimal point.
// The latter is the decimal number minus its integer part.
// For instance, 10.234 is a decimal number. Its integer part is 10 and its fractional part is 0.234
// We restrict the number of the digits after the decimal point to 4.

use std::str::FromStr;

use miette::Diagnostic;
use thiserror::Error;

static DECIMAL_DIGITS: u32 = 4;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]

/// Internal representation of Cedar `decimal` values.
///
/// In Lean `Decimal` is just a type-def for `Int64`.
pub struct Decimal(pub i64);

/// Errors in [`Decimal`] operations.
#[derive(Debug, Diagnostic, Error)]
pub enum DecimalError {
    /// Parse error.
    #[error("unable to parse `{0}` as a Decimal")]
    ParseError(String),
}

// ----- Definitions -----

impl FromStr for Decimal {
    type Err = DecimalError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split(".").collect::<Vec<&str>>() {
            #[expect(
                clippy::indexing_slicing,
                reason = "List of length 2 can be indexed by 0"
            )]
            list if list.len() == 2 && list[0] == "-" => {
                Err(DecimalError::ParseError(s.to_string()))
            }
            #[expect(
                clippy::indexing_slicing,
                reason = "List of length 2 can be indexed by 0 or 1"
            )]
            list if list.len() == 2 => {
                let left = list[0];
                let right = list[1];
                let rlen = right.len();
                if 0 < rlen && rlen <= DECIMAL_DIGITS as usize {
                    // The Lean code uses `toNat` which handles a `-` after the decimal point.
                    // We parse into `u32` to achieve the same effect.
                    match (left.parse::<i128>(), right.parse::<u32>()) {
                        (Ok(l), Ok(r)) => {
                            let l_prime = l * 10_i128.pow(DECIMAL_DIGITS);
                            #[expect(
                                clippy::unwrap_used,
                                reason = "cannot panic as we previously checked that rlen is between 0 and 4."
                            )]
                            let rlen_u32: u32 = rlen.try_into().unwrap();
                            let r: i128 = r.into();
                            let r_prime = r * 10_i128.pow(DECIMAL_DIGITS - rlen_u32);
                            let i = if !left.starts_with("-") {
                                l_prime + r_prime
                            } else {
                                l_prime - r_prime
                            };
                            match i.try_into() {
                                Ok(i) => Ok(Decimal(i)),
                                Err(_) => Err(DecimalError::ParseError(s.to_string())),
                            }
                        }
                        (_, _) => Err(DecimalError::ParseError(s.to_string())),
                    }
                } else {
                    Err(DecimalError::ParseError(s.to_string()))
                }
            }
            _ => Err(DecimalError::ParseError(s.to_string())),
        }
    }
}

impl std::fmt::Display for Decimal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let abs = i128::from(self.0).abs();
        if self.0.is_negative() {
            write!(f, "-")?;
        }
        let pow = i128::pow(10, DECIMAL_DIGITS);
        write!(f, "{}.{:04}", abs / pow, abs % pow)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::symcc::extension_types::decimal::Decimal;

    fn test_valid(str: &str, rep: i64) {
        assert_eq!(Decimal::from_str(str).unwrap(), Decimal(rep));
    }

    fn test_invalid(str: &str, msg: &str) {
        assert!(Decimal::from_str(str).is_err(), "{}", msg);
    }

    #[test]
    fn tests_for_valid_strings() {
        test_valid("0.0", 0);
        test_valid("0.0000", 0);
        test_valid("-0.0001", -1);
        test_valid("-0.9999", -9999);
        test_valid("-0.23", -2300);
        test_valid("-0.0023", -23);
        test_valid("12.34", 123400);
        test_valid("1.2345", 12345);
        test_valid("-1.0", -10000);
        test_valid("-4.2", -42000);
        test_valid("-9.876", -98760);
        test_valid("-922337203685477.5808", -9223372036854775808);
        test_valid("922337203685477.5807", 9223372036854775807);
    }

    #[test]
    fn tests_for_invalid_strings() {
        test_invalid("1.x", "invalid characters");
        test_invalid("1.-2", "invalid use of -");
        test_invalid("12", "no decimal point");
        test_invalid(".12", "no integer part");
        test_invalid("-.12", "no integer part");
        test_invalid("12.", "no fractional part");
        test_invalid("1.23456", "too many fractional digits");
        test_invalid("922337203685477.5808", "overflow");
        test_invalid("-922337203685477.5809", "overflow");
    }
}
