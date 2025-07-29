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

static DECIMAL_DIGITS: u32 = 4;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]

// In Lean `Decimal` is just a type-def for `Int64`
pub struct Decimal(pub i64);

// ----- Definitions -----

pub fn parse(s: &str) -> Option<Decimal> {
    match s.split(".").collect::<Vec<&str>>() {
        // PANIC SAFETY
        #[allow(
            clippy::indexing_slicing,
            reason = "List of length 2 can be indexed by 0"
        )]
        list if list.len() == 2 && list[0] == "-" => None,
        // PANIC SAFETY
        #[allow(
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
                        // PANIC SAFETY
                        #[allow(
                            clippy::unwrap_used,
                            reason = "cannot panic as we previously checked that rlen is between 0 and 4."
                        )]
                        let rlen_u32: u32 = rlen.try_into().unwrap();
                        let r: i128 = r.into();
                        let r_prime = r * 10_i128.pow(DECIMAL_DIGITS - rlen_u32);
                        let i = if l >= 0 {
                            l_prime + r_prime
                        } else {
                            l_prime - r_prime
                        };
                        match i.try_into() {
                            Ok(i) => Some(Decimal(i)),
                            Err(_) => None,
                        }
                    }
                    (_, _) => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

impl std::fmt::Display for Decimal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}",
            self.0 / i64::pow(10, DECIMAL_DIGITS),
            (self.0 % i64::pow(10, DECIMAL_DIGITS)).abs()
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::symcc::extension_types::decimal::{parse, Decimal};

    fn decimal(i: i64) -> Option<Decimal> {
        Some(Decimal(i))
    }

    fn test_valid(str: &str, rep: i64) {
        assert_eq!(parse(str), decimal(rep));
    }

    fn test_invalid(str: &str, msg: &str) {
        assert_eq!(parse(str), None, "{}", msg);
    }

    #[test]
    fn tests_for_valid_strings() {
        test_valid("0.0", 0);
        test_valid("0.0000", 0);
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
