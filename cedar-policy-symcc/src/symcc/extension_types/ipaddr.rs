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

//! This module defines Cedar IpAddr values and functions.
//! It is based on
//! <https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/Cedar/Spec/Ext/IPAddr.lean>

// ----- IPv4Addr and IPv6Addr -----

use std::sync::LazyLock;

use miette::Diagnostic;
use num_bigint::BigUint;
use thiserror::Error;

use crate::symcc::{
    bitvec::{BitVec, BitVecError},
    type_abbrevs::{nat, Fin, Nat, Width},
};

/// Errors in [`IPNet`] operations.
#[derive(Debug, Diagnostic, Error)]
pub enum IPError {
    /// Errors in [`BitVec`] operations.
    #[error("bit-vector error when manipulating ip addresses")]
    BitVecError(#[from] BitVecError),
    /// Expected octets when constructing IP addresses.
    #[error("expected octets when constructing IP addresses")]
    ExepectedOctet,
}

type Result<T> = std::result::Result<T, IPError>;

// ----- IPNetPrefix, CIDR, and IPNet -----

pub const V4_WIDTH: Width = 5;
pub const V6_WIDTH: Width = 7;

const fn addr_size(w: Width) -> Width {
    2u32.pow(w)
}

const V4_SIZE: Width = addr_size(V4_WIDTH);
const V6_SIZE: Width = addr_size(V6_WIDTH);

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IPv4Addr {
    pub val: BitVec,
}

impl IPv4Addr {
    pub fn mk(a0: &BitVec, a1: &BitVec, a2: &BitVec, a3: &BitVec) -> Result<Self> {
        if a0.width() == 8 && a1.width() == 8 && a2.width() == 8 && a3.width() == 8 {
            let val = BitVec::concat(a0, &BitVec::concat(a1, &BitVec::concat(a2, a3)?)?)?;
            Ok(Self { val })
        } else {
            Err(IPError::ExepectedOctet)
        }
    }

    // Helper method that does not exist in the corresponding Lean code
    pub fn mk_u8(a0: u8, a1: u8, a2: u8, a3: u8) -> Self {
        #[allow(
            clippy::unwrap_used,
            reason = "Cannot panic because bitwidth is guaranteed to be 8."
        )]
        Self::mk(
            &BitVec::of_u128(8, u128::from(a0)).unwrap(),
            &BitVec::of_u128(8, u128::from(a1)).unwrap(),
            &BitVec::of_u128(8, u128::from(a2)).unwrap(),
            &BitVec::of_u128(8, u128::from(a3)).unwrap(),
        )
        .unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]

pub struct IPv6Addr {
    pub val: BitVec,
}

impl IPv6Addr {
    #[allow(clippy::too_many_arguments)]
    pub fn mk(
        a0: &BitVec,
        a1: &BitVec,
        a2: &BitVec,
        a3: &BitVec,
        a4: &BitVec,
        a5: &BitVec,
        a6: &BitVec,
        a7: &BitVec,
    ) -> Result<Self> {
        if a0.width() == 16
            && a1.width() == 16
            && a2.width() == 16
            && a3.width() == 16
            && a4.width() == 16
            && a5.width() == 16
            && a6.width() == 16
            && a7.width() == 16
        {
            let val = BitVec::concat(
                a0,
                &BitVec::concat(
                    a1,
                    &BitVec::concat(
                        a2,
                        &BitVec::concat(
                            a3,
                            &BitVec::concat(a4, &BitVec::concat(a5, &BitVec::concat(a6, a7)?)?)?,
                        )?,
                    )?,
                )?,
            )?;
            Ok(Self { val })
        } else {
            Err(IPError::ExepectedOctet)
        }
    }

    // Helper method that does not exist in the corresponding Lean code
    #[allow(clippy::too_many_arguments)]
    pub fn mk_u16(a0: u16, a1: u16, a2: u16, a3: u16, a4: u16, a5: u16, a6: u16, a7: u16) -> Self {
        #[allow(
            clippy::unwrap_used,
            reason = "Cannot panic because bitwidth is guaranteed to be 16."
        )]
        Self::mk(
            &BitVec::of_u128(16, u128::from(a0)).unwrap(),
            &BitVec::of_u128(16, u128::from(a1)).unwrap(),
            &BitVec::of_u128(16, u128::from(a2)).unwrap(),
            &BitVec::of_u128(16, u128::from(a3)).unwrap(),
            &BitVec::of_u128(16, u128::from(a4)).unwrap(),
            &BitVec::of_u128(16, u128::from(a5)).unwrap(),
            &BitVec::of_u128(16, u128::from(a6)).unwrap(),
            &BitVec::of_u128(16, u128::from(a7)).unwrap(),
        )
        .unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IPv4Prefix {
    pub val: Option<BitVec>,
}

impl IPv4Prefix {
    pub fn of_nat(pre: Nat) -> Self {
        if pre < nat(V4_SIZE) {
            #[allow(clippy::unwrap_used, reason = "Width passed is greater than 0.")]
            Self {
                val: Some(BitVec::of_nat(V4_WIDTH, pre).unwrap()),
            }
        } else {
            Self { val: None }
        }
    }

    pub fn to_nat(pre: &Self) -> Nat {
        match &pre.val {
            Some(bv) => bv.to_nat(),
            None => nat(V4_SIZE),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IPv6Prefix {
    pub val: Option<BitVec>,
}
impl IPv6Prefix {
    pub fn of_nat(pre: Nat) -> Self {
        if pre < nat(V6_SIZE) {
            #[allow(clippy::unwrap_used, reason = "Width passed is greater than 0.")]
            Self {
                val: Some(BitVec::of_nat(V6_WIDTH, pre).unwrap()),
            }
        } else {
            Self { val: None }
        }
    }

    pub fn to_nat(pre: &Self) -> Nat {
        match &pre.val {
            Some(bv) => bv.to_nat(),
            None => nat(V6_SIZE),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CIDRv4 {
    pub addr: IPv4Addr,
    pub prefix: IPv4Prefix,
}

impl CIDRv4 {
    const SIZE: u32 = V4_SIZE;

    pub fn subnet_width(&self) -> BitVec {
        match &self.prefix.val {
            #[allow(
                clippy::unwrap_used,
                reason = "Width passed is greater than 0 and same for all bv."
            )]
            Some(bv) => {
                let n: BitVec = BitVec::of_nat(Self::SIZE, nat(Self::SIZE)).unwrap();
                let prefix_zero_extend = BitVec::zero_extend(bv, Self::SIZE).unwrap();
                BitVec::sub(&n, &prefix_zero_extend).unwrap()
            }
            #[allow(clippy::unwrap_used, reason = "Width passed is greater than 0.")]
            None => BitVec::of_u128(Self::SIZE, 0).unwrap(),
        }
    }

    pub fn range(&self) -> (IPv4Addr, IPv4Addr) {
        let width = self.subnet_width();
        #[allow(
            clippy::unwrap_used,
            reason = "Shifts cannot panic because subnet_width is guaranteed to fit in u32."
        )]
        let lo = BitVec::shl(&BitVec::lshr(&self.addr.val, &width).unwrap(), &width).unwrap();
        #[allow(clippy::unwrap_used, reason = "Width passed is greater than 0.")]
        let one = BitVec::of_u128(Self::SIZE, 1).unwrap();
        #[allow(
            clippy::unwrap_used,
            reason = "Shifts cannot panic because subnet_width is guaranteed to fit in u32. Add and sub cannot panic because the bit-vectors have the same width."
        )]
        let hi = BitVec::sub(
            &BitVec::add(&lo, &BitVec::shl(&one, &width).unwrap()).unwrap(),
            &one,
        )
        .unwrap();
        (IPv4Addr { val: lo }, IPv4Addr { val: hi })
    }

    #[allow(
        clippy::unwrap_used,
        reason = "Ule cannot panic because range returns bit-vectors of width Self::SIZE which are the same bitwidth."
    )]
    pub fn in_range(&self, other: &CIDRv4) -> bool {
        let (lo, hi) = self.range();
        let (other_lo, other_hi) = other.range();

        BitVec::ule(&hi.val, &other_hi.val).unwrap() && BitVec::ule(&other_lo.val, &lo.val).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CIDRv6 {
    pub addr: IPv6Addr,
    pub prefix: IPv6Prefix,
}

impl CIDRv6 {
    const SIZE: u32 = V6_SIZE;

    pub fn subnet_width(&self) -> BitVec {
        match &self.prefix.val {
            #[allow(
                clippy::unwrap_used,
                reason = "Width passed is greater than 0 and same for all bv."
            )]
            Some(bv) => {
                let n: BitVec = BitVec::of_nat(Self::SIZE, nat(Self::SIZE)).unwrap();
                let prefix_zero_extend = BitVec::zero_extend(bv, Self::SIZE).unwrap();
                BitVec::sub(&n, &prefix_zero_extend).unwrap()
            }
            #[allow(clippy::unwrap_used, reason = "Width passed is greater than 0.")]
            None => BitVec::of_u128(Self::SIZE, 0).unwrap(),
        }
    }

    pub fn range(&self) -> (IPv6Addr, IPv6Addr) {
        let width = self.subnet_width();
        #[allow(
            clippy::unwrap_used,
            reason = "Shifts cannot panic because subnet_width is guaranteed to fit in u32."
        )]
        let lo = BitVec::shl(&BitVec::lshr(&self.addr.val, &width).unwrap(), &width).unwrap();
        #[allow(clippy::unwrap_used, reason = "Width passed is greater than 0.")]
        let one = BitVec::of_u128(Self::SIZE, 1).unwrap();
        #[allow(
            clippy::unwrap_used,
            reason = "Shifts cannot panic because subnet_width is guaranteed to fit in u32. Add and sub cannot panic because the bit-vectors have the same width."
        )]
        let hi = BitVec::sub(
            &BitVec::add(&lo, &BitVec::shl(&one, &width).unwrap()).unwrap(),
            &one,
        )
        .unwrap();
        (IPv6Addr { val: lo }, IPv6Addr { val: hi })
    }

    #[allow(
        clippy::unwrap_used,
        reason = "Ule cannot panic because range returns bit-vectors of width Self::SIZE which are the same bitwidth."
    )]
    pub fn in_range(&self, other: &CIDRv6) -> bool {
        let (lo, hi) = self.range();
        let (other_lo, other_hi) = other.range();
        BitVec::ule(&hi.val, &other_hi.val).unwrap() && BitVec::ule(&other_lo.val, &lo.val).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IPNet {
    V4(CIDRv4),
    V6(CIDRv6),
}

static LOOP_BACK_ADDRESS_V4: LazyLock<IPv4Addr> = LazyLock::new(|| IPv4Addr::mk_u8(127, 0, 0, 0));
static LOOP_BACK_ADDRESS_V6: LazyLock<IPv6Addr> =
    LazyLock::new(|| IPv6Addr::mk_u16(0, 0, 0, 0, 0, 0, 0, 1));
pub static LOOP_BACK_CIDR_V4: LazyLock<IPNet> = LazyLock::new(|| {
    IPNet::V4(CIDRv4 {
        addr: (*LOOP_BACK_ADDRESS_V4).clone(),
        prefix: IPv4Prefix::of_nat(nat(8)),
    })
});
pub static LOOP_BACK_CIDR_V6: LazyLock<IPNet> = LazyLock::new(|| {
    IPNet::V6(CIDRv6 {
        addr: (*LOOP_BACK_ADDRESS_V6).clone(),
        prefix: IPv6Prefix::of_nat(nat(128)),
    })
});

static MULTICAST_ADDRESS_V4: LazyLock<IPv4Addr> = LazyLock::new(|| IPv4Addr::mk_u8(224, 0, 0, 0));
static MULTICAST_ADDRESS_V6: LazyLock<IPv6Addr> =
    LazyLock::new(|| IPv6Addr::mk_u16(65280, 0, 0, 0, 0, 0, 0, 0));
pub static MULTICAST_CIDR_V4: LazyLock<IPNet> = LazyLock::new(|| {
    IPNet::V4(CIDRv4 {
        addr: (*MULTICAST_ADDRESS_V4).clone(),
        prefix: IPv4Prefix::of_nat(nat(4)),
    })
});
pub static MULTICAST_CIDR_V6: LazyLock<IPNet> = LazyLock::new(|| {
    IPNet::V6(CIDRv6 {
        addr: (*MULTICAST_ADDRESS_V6).clone(),
        prefix: IPv6Prefix::of_nat(nat(4)),
    })
});

impl IPNet {
    pub fn is_v4(&self) -> bool {
        matches!(self, IPNet::V4 { .. })
    }

    pub fn is_v6(&self) -> bool {
        matches!(self, IPNet::V6 { .. })
    }

    pub fn in_range(&self, other: &IPNet) -> bool {
        match (self, other) {
            (IPNet::V4(v4), IPNet::V4(other_v4)) => v4.in_range(other_v4),
            (IPNet::V6(v6), IPNet::V6(other_v6)) => v6.in_range(other_v6),
            _ => false,
        }
    }

    pub fn is_loopback(&self) -> bool {
        self.in_range(match self {
            IPNet::V4(_) => &LOOP_BACK_CIDR_V4,
            IPNet::V6(_) => &LOOP_BACK_CIDR_V6,
        })
    }

    pub fn is_multicast(&self) -> bool {
        self.in_range(match self {
            IPNet::V4(_) => &MULTICAST_CIDR_V4,
            IPNet::V6(_) => &MULTICAST_CIDR_V6,
        })
    }
}

impl Default for IPNet {
    fn default() -> Self {
        IPNet::V4(CIDRv4 {
            addr: IPv4Addr::mk_u8(0, 0, 0, 0),
            prefix: IPv4Prefix { val: None },
        })
    }
}

fn parse_prefix_nat(s: &str, digits: &Nat, size: &Nat) -> Option<Fin> {
    let len = s.len();
    // Check length and leading zero constraints
    if &BigUint::from(len) <= digits && (!s.starts_with('0') || s == "0") {
        // Parse to number and validate range
        match s.parse::<Nat>() {
            Ok(n) if &n <= size => Fin::try_new(size + nat(1), n),
            _ => None,
        }
    } else {
        None
    }
}

fn parse_num_v4(s: &str) -> Option<BitVec> {
    let len = s.len();
    // Check length and leading zero constraints
    if len <= 3 && (!s.starts_with('0') || s == "0") {
        // Parse to number and validate range
        match s.parse::<Nat>() {
            Ok(n) => {
                if n <= nat(255) {
                    #[allow(clippy::unwrap_used, reason = "Width passed is greater than 0.")]
                    return Some(BitVec::of_nat(8, n).unwrap());
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}

fn parse_segs_v4(s: &str) -> Option<IPv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }

    // PANIC SAFETY: if condition ensures accesses are within bounds
    #[allow(clippy::indexing_slicing)]
    let a0 = parse_num_v4(parts[0])?;
    // PANIC SAFETY: if condition ensures accesses are within bounds
    #[allow(clippy::indexing_slicing)]
    let a1 = parse_num_v4(parts[1])?;
    // PANIC SAFETY: if condition ensures accesses are within bounds
    #[allow(clippy::indexing_slicing)]
    let a2 = parse_num_v4(parts[2])?;
    // PANIC SAFETY: if condition ensures accesses are within bounds
    #[allow(clippy::indexing_slicing)]
    let a3 = parse_num_v4(parts[3])?;
    #[allow(
        clippy::unwrap_used,
        reason = "parse_num_v4 returns bit-vectors of size 8 so mk cannot panic."
    )]
    Some(IPv4Addr::mk(&a0, &a1, &a2, &a3).unwrap())
}

fn parse_ipv4_net(s: &str) -> Option<IPNet> {
    let parts: Vec<&str> = s.split('/').collect();
    match parts.as_slice() {
        [addr] => {
            let v4 = parse_segs_v4(addr)?;
            Some(IPNet::V4(CIDRv4 {
                addr: v4,
                prefix: IPv4Prefix::of_nat(nat(V4_SIZE)),
            }))
        }
        [addr, prefix] => {
            let v4 = parse_segs_v4(addr)?;
            let pre = parse_prefix_nat(prefix, &nat(2), &nat(V4_SIZE))?;
            Some(IPNet::V4(CIDRv4 {
                addr: v4,
                prefix: IPv4Prefix::of_nat(pre.to_nat()),
            }))
        }
        _ => None,
    }
}

fn is_hex_digit(c: char) -> bool {
    c.is_ascii_digit() || ('a'..='f').contains(&c) || ('A'..='F').contains(&c)
}

fn to_hex_nat(c: char) -> Nat {
    nat(if c.is_ascii_digit() {
        (c as u32) - ('0' as u32)
    } else if ('a'..='f').contains(&c) {
        (c as u32) - ('a' as u32) + 10
    } else if ('A'..='F').contains(&c) {
        (c as u32) - ('A' as u32) + 10
    } else {
        c as u32
    })
}

// Attempts to parse v6 segments into a 16 bit BitVec
fn parse_num_v6(s: &str) -> Option<BitVec> {
    let len = s.len();
    if 0 < len && len <= 4 && s.chars().all(is_hex_digit) {
        let n = s
            .chars()
            .fold(BigUint::ZERO, |acc, c| acc * nat(16) + to_hex_nat(c));
        if n <= nat(0xffff) {
            #[allow(clippy::unwrap_used, reason = "Width passed is greater than 0.")]
            Some(BitVec::of_nat(16, n).unwrap())
        } else {
            None
        }
    } else {
        None
    }
}

fn parse_num_segs_v6(s: &str) -> Option<Vec<BitVec>> {
    if s.is_empty() {
        return Some(vec![]);
    }
    s.split(':').map(parse_num_v6).collect()
}

fn parse_segs_v6(s: &str) -> Option<IPv6Addr> {
    // :: is for compressed notation indicating consecutive groups of 0
    let parts: Vec<&str> = s.split("::").collect();
    let segs = match parts.as_slice() {
        [s1] => parse_num_segs_v6(s1),
        [s1, s2] => {
            let ns1 = parse_num_segs_v6(s1)?;
            let ns2 = parse_num_segs_v6(s2)?;
            let len = ns1.len() + ns2.len();
            if len < 8 {
                let mut result = ns1;
                #[allow(clippy::unwrap_used, reason = "Width passed is greater than 0.")]
                let bv_zero = BitVec::of_u128(16, 0).unwrap();
                result.extend(std::iter::repeat_n(bv_zero, 8 - len));
                result.extend(ns2);
                Some(result)
            } else {
                None
            }
        }
        _ => None,
    };
    match segs.as_deref() {
        // This is guaranteed to have length 8 because we expand the compressed notation.
        Some([s0, s1, s2, s3, s4, s5, s6, s7]) =>
        {
            #[allow(
                clippy::unwrap_used,
                reason = "parse_num_segs_v6 calls parse_num_v6 which creates bit-vectors of size 16."
            )]
            Some(IPv6Addr::mk(s0, s1, s2, s3, s4, s5, s6, s7).unwrap())
        }
        _ => None,
    }
}

fn parse_ipv6_net(s: &str) -> Option<IPNet> {
    let parts: Vec<&str> = s.split('/').collect();
    match parts.as_slice() {
        [addr] => {
            let v6 = parse_segs_v6(addr)?;
            Some(IPNet::V6(CIDRv6 {
                addr: v6,
                prefix: IPv6Prefix::of_nat(nat(V6_SIZE)),
            }))
        }
        [addr, prefix] => {
            let v6 = parse_segs_v6(addr)?;
            let pre = parse_prefix_nat(prefix, &nat(3), &nat(V6_SIZE))?;
            Some(IPNet::V6(CIDRv6 {
                addr: v6,
                prefix: IPv6Prefix::of_nat(pre.to_nat()),
            }))
        }
        _ => None,
    }
}

pub fn parse(s: &str) -> Option<IPNet> {
    parse_ipv4_net(s).or_else(|| parse_ipv6_net(s))
}

impl std::fmt::Display for IPNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IPNet::V4(CIDRv4 { addr, prefix }) => {
                let v = addr.val.to_nat();
                let a0 = (v.clone() >> 24) & nat(0xFF);
                let a1 = (v.clone() >> 16) & nat(0xFF);
                let a2 = (v.clone() >> 8) & nat(0xFF);
                let a3 = v & nat(0xFF);
                write!(
                    f,
                    "{}.{}.{}.{}/{}",
                    a0,
                    a1,
                    a2,
                    a3,
                    IPv4Prefix::to_nat(prefix)
                )
            }
            IPNet::V6(CIDRv6 { addr, prefix }) => {
                let v = addr.val.to_nat();
                let a0 = (v.clone() >> 112) & nat(0xFFFF);
                let a1 = (v.clone() >> 96) & nat(0xFFFF);
                let a2 = (v.clone() >> 80) & nat(0xFFFF);
                let a3 = (v.clone() >> 64) & nat(0xFFFF);
                let a4 = (v.clone() >> 48) & nat(0xFFFF);
                let a5 = (v.clone() >> 32) & nat(0xFFFF);
                let a6 = (v.clone() >> 16) & nat(0xFFFF);
                let a7 = v & nat(0xFFFF);
                write!(
                    f,
                    "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}/{}",
                    a0,
                    a1,
                    a2,
                    a3,
                    a4,
                    a5,
                    a6,
                    a7,
                    IPv6Prefix::to_nat(prefix)
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::symcc::type_abbrevs::Width;

    use super::*;

    fn test_valid(str: &str, expected: IPNet) {
        assert_eq!(parse(str), Some(expected));
    }

    fn test_invalid(str: &str, _msg: &str) {
        assert_eq!(parse(str), None);
    }

    fn ipv4(a0: u8, a1: u8, a2: u8, a3: u8, pre: Width) -> IPNet {
        IPNet::V4(CIDRv4 {
            addr: IPv4Addr::mk_u8(a0, a1, a2, a3),
            prefix: IPv4Prefix::of_nat(pre.into()),
        })
    }

    fn ipv6(
        a0: u16,
        a1: u16,
        a2: u16,
        a3: u16,
        a4: u16,
        a5: u16,
        a6: u16,
        a7: u16,
        pre: Width,
    ) -> IPNet {
        IPNet::V6(CIDRv6 {
            addr: IPv6Addr::mk_u16(a0, a1, a2, a3, a4, a5, a6, a7),
            prefix: IPv6Prefix::of_nat(pre.into()),
        })
    }

    #[test]
    fn tests_for_valid_strings() {
        test_valid("127.0.0.1", ipv4(127, 0, 0, 1, V4_SIZE));
        test_valid("127.3.4.1/2", ipv4(127, 3, 4, 1, 2));
        test_valid("::", ipv6(0, 0, 0, 0, 0, 0, 0, 0, V6_SIZE));
        test_valid("::/5", ipv6(0, 0, 0, 0, 0, 0, 0, 0, 5));
        test_valid("a::", ipv6(0xa, 0, 0, 0, 0, 0, 0, 0, V6_SIZE));
        test_valid("::f", ipv6(0, 0, 0, 0, 0, 0, 0, 0xf, V6_SIZE));
        test_valid(
            "F:AE::F:5:F:F:0",
            ipv6(0xf, 0xae, 0, 0xf, 0x5, 0xf, 0xf, 0, V6_SIZE),
        );
        test_valid("a::f/120", ipv6(0xa, 0, 0, 0, 0, 0, 0, 0xf, 120));
    }

    #[test]
    fn tests_for_invalid_strings() {
        test_invalid("127.0.0.1.", "trailing dot");
        test_invalid(".127.0.0.1", "leading dot");
        test_invalid("127.0..0.1", "double dot");
        test_invalid("256.0.0.1", "group out of range");
        test_invalid("127.0.a.1", "no hex in IPv4");
        test_invalid("127.3.4.1/33", "prefix out of range");
        test_invalid("::::", "too many double colons");
        test_invalid("::f::", "too many double colons");
        test_invalid("F:AE::F:5:F:F:0:0", "too many groups");
        test_invalid("F:A:F:5:F:F:0:0:1", "too many groups");
        test_invalid("F:A", "too few groups");
        test_invalid("::ffff1", "group out of range");
        test_invalid("F:AE::F:5:F:F:0/129", "prefix out of range");
        test_invalid("::ffff:127.0.0.1", "no IPv4 embedded in IPv6");
        test_invalid("::/00", "no leading zeros");
        test_invalid("::/01", "no leading zeros");
        test_invalid("::/001", "no leading zeros");
        test_invalid("127.0.0.1/01", "no leading zeros");
        test_invalid("F:AE::F:5:F:F:0/01", "no leading zeros");
    }

    fn parse_unwrap(s: &str) -> IPNet {
        parse(s).unwrap()
    }

    #[test]
    fn tests_for_is_loopback() {
        assert!(parse_unwrap("127.0.0.1").is_loopback());
        assert!(!parse_unwrap("::B").is_loopback());
        assert!(parse_unwrap("::1").is_loopback());
        assert!(!parse_unwrap("::ffff:ff00:0001").is_loopback());
    }

    #[test]
    fn tests_for_in_range() {
        assert!(parse_unwrap("238.238.238.238").in_range(&parse_unwrap("238.238.238.41/12")));
        assert!(parse_unwrap("238.238.238.238").in_range(&parse_unwrap("238.238.238.238")));
        assert!(parse_unwrap("F:AE::F:5:F:F:0").in_range(&parse_unwrap("F:AE::F:5:F:F:0")));
        assert!(parse_unwrap("F:AE::F:5:F:F:1").in_range(&parse_unwrap("F:AE::F:5:F:F:0/127")));
        assert!(!parse_unwrap("F:AE::F:5:F:F:2").in_range(&parse_unwrap("F:AE::F:5:F:F:0/127")));
        assert!(!parse_unwrap("0.0.0.0").in_range(&parse_unwrap("::")));
        assert!(!parse_unwrap("::").in_range(&parse_unwrap("0.0.0.0")));
        assert!(parse_unwrap("10.0.0.0").in_range(&parse_unwrap("10.0.0.0/24")));
        assert!(parse_unwrap("10.0.0.0").in_range(&parse_unwrap("10.0.0.0/32")));
        assert!(parse_unwrap("10.0.0.0").in_range(&parse_unwrap("10.0.0.1/24")));
        assert!(!parse_unwrap("10.0.0.0").in_range(&parse_unwrap("10.0.0.1/32")));
        assert!(parse_unwrap("10.0.0.1").in_range(&parse_unwrap("10.0.0.0/24")));
        assert!(parse_unwrap("10.0.0.1").in_range(&parse_unwrap("10.0.0.1/24")));
        assert!(!parse_unwrap("10.0.0.0/24").in_range(&parse_unwrap("10.0.0.0/32")));
        assert!(parse_unwrap("10.0.0.0/32").in_range(&parse_unwrap("10.0.0.0/24")));
        assert!(parse_unwrap("10.0.0.1/24").in_range(&parse_unwrap("10.0.0.0/24")));
        assert!(parse_unwrap("10.0.0.1/24").in_range(&parse_unwrap("10.0.0.1/24")));
        assert!(parse_unwrap("10.0.0.0/24").in_range(&parse_unwrap("10.0.0.1/24")));
        assert!(!parse_unwrap("10.0.0.0/24").in_range(&parse_unwrap("10.0.0.0/29")));
        assert!(parse_unwrap("10.0.0.0/29").in_range(&parse_unwrap("10.0.0.0/24")));
        assert!(!parse_unwrap("10.0.0.0/24").in_range(&parse_unwrap("10.0.0.1/29")));
        assert!(parse_unwrap("10.0.0.0/29").in_range(&parse_unwrap("10.0.0.1/24")));
        assert!(!parse_unwrap("10.0.0.1/24").in_range(&parse_unwrap("10.0.0.0/29")));
        assert!(parse_unwrap("10.0.0.1/29").in_range(&parse_unwrap("10.0.0.0/24")));
        assert!(parse_unwrap("10.0.0.0/32").in_range(&parse_unwrap("10.0.0.0/32")));
        assert!(parse_unwrap("10.0.0.0/32").in_range(&parse_unwrap("10.0.0.0")));
        assert!(parse_unwrap("0.0.0.0/31").in_range(&parse_unwrap("0.0.0.1/31")));
        assert!(parse_unwrap("0.0.0.1/31").in_range(&parse_unwrap("0.0.0.0/31")));
    }

    #[test]
    fn tests_for_ipnet_equality() {
        assert_eq!(parse("10.0.0.0"), parse("10.0.0.0"));
        assert_ne!(parse("10.0.0.0"), parse("10.0.0.1"));
        assert_eq!(parse("10.0.0.0/32"), parse("10.0.0.0"));
        assert_ne!(parse("10.0.0.0/24"), parse("10.0.0.0"));
        assert_eq!(parse("10.0.0.0/24"), parse("10.0.0.0/24"));
        assert_ne!(parse("10.0.0.0/24"), parse("10.0.0.0/29"));
    }

    #[test]
    fn tests_for_string_formatting() {
        // Test cases from Lean code
        assert_eq!(parse_unwrap("192.168.0.1/32").to_string(), "192.168.0.1/32");
        assert_eq!(parse_unwrap("0.0.0.0/1").to_string(), "0.0.0.0/1");
        assert_eq!(parse_unwrap("8.8.8.8/24").to_string(), "8.8.8.8/24");
        assert_eq!(
            parse_unwrap("1:2:3:4:a:b:c:d/128").to_string(),
            "0001:0002:0003:0004:000a:000b:000c:000d/128"
        );
        assert_eq!(
            parse_unwrap("1:22:333:4444:a:bb:ccc:dddd/128").to_string(),
            "0001:0022:0333:4444:000a:00bb:0ccc:dddd/128"
        );
        assert_eq!(
            parse_unwrap("7:70:700:7000::a00/128").to_string(),
            "0007:0070:0700:7000:0000:0000:0000:0a00/128"
        );
        assert_eq!(
            parse_unwrap("::ffff/128").to_string(),
            "0000:0000:0000:0000:0000:0000:0000:ffff/128"
        );
        assert_eq!(
            parse_unwrap("ffff::/4").to_string(),
            "ffff:0000:0000:0000:0000:0000:0000:0000/4"
        );
    }
}
