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
use super::result::Error;
use super::type_abbrevs::Nat;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct BitVec {
    pub width: Nat,
    pub v: i128,
}

// Functions from SymCC/Data.lean
impl BitVec {
    pub fn width(&self) -> u32 {
        self.width as u32
    }
}

fn signed_min(n: u32) -> i128 {
    -(2_i128.pow(n - 1))
}

fn signed_max(n: u32) -> i128 {
    2_i128.pow(n - 1) - 1
}

pub fn overflows(n: u32, i: i128) -> bool {
    i < signed_min(n) || i > signed_max(n)
}

// Functions from Lean Std Lib
impl BitVec {
    pub fn neg(&self) -> Self {
        BitVec {
            width: self.width,
            v: -self.v,
        }
    }

    pub fn to_nat(&self) -> Nat {
        self.v as Nat //TODO: make sure this is always safe
    }

    pub fn of_nat(width: Nat, v: Nat) -> Self {
        BitVec {
            width,
            v: (v as i128),
        }
    }

    pub fn of_int(width: Nat, v: i128) -> Self {
        BitVec { width, v }
    }

    pub fn int_min(width: Nat) -> Self {
        BitVec::of_int(width, signed_min(width as u32))
    }

    pub fn slt(lhs: &Self, rhs: &Self) -> bool {
        assert!(lhs.width == rhs.width);
        lhs.v < rhs.v
    }

    pub fn sle(lhs: &Self, rhs: &Self) -> bool {
        assert!(lhs.width == rhs.width);
        lhs.v <= rhs.v
    }

    pub fn ult(lhs: &Self, rhs: &Self) -> bool {
        assert!(lhs.width == rhs.width);
        (lhs.v as u128) < (rhs.v as u128)
    }

    pub fn ule(lhs: &Self, rhs: &Self) -> bool {
        assert!(lhs.width == rhs.width);
        (lhs.v as u128) <= (rhs.v as u128)
    }

    pub fn add(lhs: &Self, rhs: &Self) -> Self {
        assert!(lhs.width == rhs.width);
        BitVec {
            width: lhs.width,
            v: lhs.v + rhs.v,
        }
    }

    pub fn sub(lhs: &Self, rhs: &Self) -> Self {
        assert!(lhs.width == rhs.width);
        BitVec {
            width: lhs.width,
            v: lhs.v - rhs.v,
        }
    }

    pub fn mul(lhs: &Self, rhs: &Self) -> Self {
        assert!(lhs.width == rhs.width);
        BitVec {
            width: lhs.width,
            v: lhs.v * rhs.v,
        }
    }

    // semantics to match https://leanprover-community.github.io/mathlib4_docs/Init/Data/BitVec/Basic.html#BitVec.smtSDiv
    pub fn sdiv(lhs: &Self, rhs: &Self) -> Self {
        assert!(lhs.width == rhs.width);
        BitVec {
            width: lhs.width,
            v: if rhs.v == 0 {
                if lhs.v >= 0 {
                    -1
                } else {
                    1
                }
            } else {
                lhs.v / rhs.v
            },
        }
    }

    // semantics to match https://leanprover-community.github.io/mathlib4_docs/Init/Data/BitVec/Basic.html#BitVec.smtUDiv
    pub fn udiv(lhs: &Self, rhs: &Self) -> Self {
        assert!(lhs.width == rhs.width);
        BitVec {
            width: lhs.width,
            v: if rhs.v == 0 {
                -1 // all-ones
            } else {
                (lhs.v as u128 / rhs.v as u128) as i128
            },
        }
    }

    // semantics to match https://leanprover-community.github.io/mathlib4_docs/Init/Data/BitVec/Basic.html#BitVec.srem
    pub fn srem(_lhs: &Self, _rhs: &Self) -> Self {
        let unimplemented = Err(Error::UnsupportedError);
        // PANIC SAFETY (not really panic safe, hack until BitVec refactor)
        #[allow(
            clippy::expect_used,
            reason = "TODO, but can't use todo! or unimplemented!"
        )]
        unimplemented.expect("BitVec::srem not implemented. Waiting for BitVec refactor")
    }

    // semantics to match https://leanprover-community.github.io/mathlib4_docs/Init/Data/BitVec/Basic.html#BitVec.smod
    pub fn smod(_lhs: &Self, _rhs: &Self) -> Self {
        let unimplemented = Err(Error::UnsupportedError);
        // PANIC SAFETY (not really panic safe, hack until BitVec refactor)
        #[allow(
            clippy::expect_used,
            reason = "TODO, but can't use todo! or unimplemented!"
        )]
        unimplemented.expect("BitVec::smod not implemented. Waiting for BitVec refactor")
    }

    // semantics to match https://leanprover-community.github.io/mathlib4_docs/Init/Data/BitVec/Basic.html#BitVec.umod
    pub fn umod(_lhs: &Self, _rhs: &Self) -> Self {
        let unimplemented = Err(Error::UnsupportedError);
        // PANIC SAFETY (not really panic safe, hack until BitVec refactor)
        #[allow(
            clippy::expect_used,
            reason = "TODO, but can't use todo! or unimplemented!"
        )]
        unimplemented.expect("BitVec::umod not implemented. Waiting for BitVec refactor")
    }

    pub fn shl(lhs: &Self, rhs: &Self) -> Self {
        assert!(lhs.width == rhs.width);
        BitVec {
            width: lhs.width,
            v: lhs.v << rhs.v,
        }
    }

    pub fn lshr(lhs: &Self, rhs: &Self) -> Self {
        assert!(lhs.width == rhs.width);
        BitVec {
            width: lhs.width,
            v: lhs.v >> rhs.v,
        }
    }
}
