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
//! https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/Cedar/Spec/Ext/IPAddr.lean

// ----- IPv4Addr and IPv6Addr -----

use crate::symcc::type_abbrevs::{Fin, Nat};

/// IPv4 address: a 32 bit number
type IPv4Addr = u32;

/// `a0` is most significant and `a3` is least significant
#[allow(non_snake_case)]
pub const fn IPv4Addr_mk(a0: u8, a1: u8, a2: u8, a3: u8) -> IPv4Addr {
    IPv4Addr::from_be_bytes([a0, a1, a2, a3])
}

/// IPv6 address: a 128 bit number
type IPv6Addr = u128;

/// `a0` is most significant and `a15` is least significant
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
pub const fn IPv6Addr_mk(
    a0: u8,
    a1: u8,
    a2: u8,
    a3: u8,
    a4: u8,
    a5: u8,
    a6: u8,
    a7: u8,
    a8: u8,
    a9: u8,
    a10: u8,
    a11: u8,
    a12: u8,
    a13: u8,
    a14: u8,
    a15: u8,
) -> IPv6Addr {
    IPv6Addr::from_be_bytes([
        a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15,
    ])
}

// ----- IPNetPrefix, CIDR, and IPNet -----

const V4_SIZE: u32 = 32;
pub type IPv4Prefix = Option<Fin<33>>; // V4_SIZE+1

const V6_SIZE: u32 = 128;
pub type IPv6Prefix = Option<Fin<129>>; // V6_SIZE+1

#[allow(non_snake_case)]
pub const fn IPv4Prefix_ofNat(pre: Nat) -> IPv4Prefix {
    Fin::try_new(pre as u128)
}
#[allow(non_snake_case)]
pub const fn IPv6Prefix_ofNat(pre: Nat) -> IPv6Prefix {
    Fin::try_new(pre as u128)
}

#[allow(non_snake_case)]
#[expect(unused, reason = "IP not fully implemented yet")]
pub const fn IPv4Prefix_toNat(pre: &IPv4Prefix) -> Nat {
    match pre {
        None => 32,
        Some(Fin { v }) => *v as Nat,
    }
}

#[allow(non_snake_case)]
#[expect(unused, reason = "IP not fully implemented yet")]
pub const fn IPv6Prefix_toNat(pre: &IPv6Prefix) -> Nat {
    match pre {
        None => 128,
        Some(Fin { v }) => *v as Nat,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cidrv4 {
    pub addr: IPv4Addr,
    pub prefix: IPv4Prefix,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cidrv6 {
    pub addr: IPv6Addr,
    pub prefix: IPv6Prefix,
}

impl Cidrv4 {
    pub fn subnet_width(&self) -> u32 {
        match self.prefix {
            Some(Fin { v }) => V4_SIZE - v as u32,
            None => 0,
        }
    }

    pub fn range(&self) -> (IPv4Addr, IPv4Addr) {
        let width = self.subnet_width();
        let lo = (self.addr >> width) << width;
        let hi = lo + (1 << width) - 1;
        (lo, hi)
    }

    pub fn in_range(&self, other: &Cidrv4) -> bool {
        let (lo, hi) = self.range();
        let (other_lo, other_hi) = other.range();
        other_hi >= hi && lo >= other_lo
    }
}

impl Cidrv6 {
    pub fn subnet_width(&self) -> u32 {
        match self.prefix {
            Some(Fin { v }) => V6_SIZE - v as u32,
            None => 0,
        }
    }

    pub fn range(&self) -> (IPv6Addr, IPv6Addr) {
        let width = self.subnet_width();
        let lo = (self.addr >> width) << width;
        let hi = lo + (1 << width) - 1;
        (lo, hi)
    }

    pub fn in_range(&self, other: &Cidrv6) -> bool {
        let (lo, hi) = self.range();
        let (other_lo, other_hi) = other.range();
        other_hi >= hi && lo >= other_lo
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IPNet {
    V4(Cidrv4),
    V6(Cidrv6),
}

const LOOP_BACK_ADDRESS_V4: IPv4Addr = IPv4Addr_mk(127, 0, 0, 0);
const LOOP_BACK_ADDRESS_V6: IPv6Addr = IPv6Addr_mk(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1);
pub const LOOP_BACK_CIDR_V4: IPNet = IPNet::V4(Cidrv4 {
    addr: LOOP_BACK_ADDRESS_V4,
    prefix: IPv4Prefix_ofNat(8),
});
pub const LOOP_BACK_CIDR_V6: IPNet = IPNet::V6(Cidrv6 {
    addr: LOOP_BACK_ADDRESS_V6,
    prefix: IPv6Prefix_ofNat(128),
});

const MULTICAST_ADDRESS_V4: IPv4Addr = IPv4Addr::from_be_bytes([224, 0, 0, 0]);
const MULTICAST_ADDRESS_V6: IPv6Addr =
    IPv6Addr::from_be_bytes([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
pub const MULTICAST_CIDR_V4: IPNet = IPNet::V4(Cidrv4 {
    addr: MULTICAST_ADDRESS_V4,
    prefix: IPv4Prefix_ofNat(4),
});
pub const MULTICAST_CIDR_V6: IPNet = IPNet::V6(Cidrv6 {
    addr: MULTICAST_ADDRESS_V6,
    prefix: IPv6Prefix_ofNat(4),
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
        IPNet::V4(Cidrv4 {
            addr: IPv4Addr_mk(0, 0, 0, 0),
            prefix: None,
        })
    }
}

/*
private def parsePrefixNat (str : String) (digits : Nat) (size : Nat) : Option (Fin (size + 1)) :=
  let len := str.length
  if 0 < len && len ≤ digits && (str.startsWith "0" → str = "0")
  then do
    let n ← str.toNat?
    if n ≤ size then .some (Fin.ofNat' (size+1) n) else .none
  else .none

private def parseNumV4 (str : String) : Option (BitVec 8) :=
  let len := str.length
  if 0 < len && len ≤ 3 && (str.startsWith "0" → str = "0")
  then do
    let n ← str.toNat?
    if n ≤ 0xff then .some n else .none
  else .none

private def parseSegsV4 (str : String) : Option IPv4Addr :=
  match str.split (· = '.') with
  | [s₀, s₁, s₂, s₃] => do
    let a₀ ← parseNumV4 s₀
    let a₁ ← parseNumV4 s₁
    let a₂ ← parseNumV4 s₂
    let a₃ ← parseNumV4 s₃
    .some (IPv4Addr.mk a₀ a₁ a₂ a₃)
  | _ => .none

private def parseIPv4Net (str : String) : Option IPNet :=
  match str.split (· = '/') with
  | strV4 :: rest => do
    let pre ←
      match rest with
      | []       => .some (ADDR_SIZE V4_WIDTH)
      | [strPre] => parsePrefixNat strPre 2 (ADDR_SIZE V4_WIDTH)
      | _        => .none
    let v4 ← parseSegsV4 strV4
    .some (IPNet.V4 ⟨v4, pre⟩)
  | _ => .none

private def isHexDigit (c : Char) : Bool :=
  c.isDigit || ('a' ≤ c && c ≤ 'f') || ('A' ≤ c && c ≤ 'F')

private def toHexNat (c : Char) : Nat :=
  if c.isDigit
  then c.toNat - '0'.toNat
  else if 'a' ≤ c && c ≤ 'f'
  then c.toNat - 'a'.toNat + 10
  else if 'A' ≤ c && c ≤ 'F'
  then c.toNat - 'A'.toNat + 10
  else c.toNat

private def parseNumV6 (str : String) : Option (BitVec 16) :=
  let len := str.length
  if 0 < len && len ≤ 4 && str.all isHexDigit
  then
    let n := str.foldl (fun n c => n * 16 + toHexNat c) 0
    if n ≤ 0xffff then .some n else .none
  else .none

private def parseNumSegsV6 (str : String) : Option (List (BitVec 16)) :=
  if str.isEmpty
  then .some []
  else (str.split (· = ':')).mapM parseNumV6

private def parseSegsV6 (str : String) : Option IPv6Addr := do
  let segs ←
    match str.splitOn "::" with
    | [s₁] => parseNumSegsV6 s₁
    | [s₁, s₂] => do
      let ns₁ ← parseNumSegsV6 s₁
      let ns₂ ← parseNumSegsV6 s₂
      let len := ns₁.length + ns₂.length
      if len < 8
      then .some (ns₁ ++ (List.replicate (8 - len) 0) ++ ns₂)
      else .none
    | _ => .none
  match segs with
  | [a₀, a₁, a₂, a₃, a₄, a₅, a₆, a₇] =>
    .some (IPv6Addr.mk a₀ a₁ a₂ a₃ a₄ a₅ a₆ a₇)
  | _ => .none

private def parseIPv6Net (str : String) : Option IPNet :=
  match str.split (· = '/') with
  | strV6 :: rest => do
    let pre ←
      match rest with
      | []       => .some (ADDR_SIZE V6_WIDTH)
      | [strPre] => parsePrefixNat strPre 3 (ADDR_SIZE V6_WIDTH)
      | _        => .none
    let v6 ← parseSegsV6 strV6
    .some (IPNet.V6 ⟨v6, pre⟩)
  | _ => .none

def parse (str : String) : Option IPNet :=
  let ip := parseIPv4Net str
  if ip.isSome then ip else parseIPv6Net str

def ip (str : String) : Option IPNet := parse str
*/
