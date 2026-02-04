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

//! Implementation of [`BitVec`].

use std::sync::LazyLock;

use crate::symcc::type_abbrevs::{Int, Nat, Width};
use miette::Diagnostic;
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::cast::ToPrimitive;
use thiserror::Error;

/// Implementation of the Lean BitVec in Rust. The Lean version is a wrapper around a `Fin`,
/// a finite natural number that is guaranteed to be less than 2^width. In our implementation
/// we use a BigUint and enforce the invariant that it is less than 2^width. Trying to
/// create a bit-vector from a value greater than 2^width will truncate the value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BitVec {
    width: Width,
    v: BigUint,
}

static TWO: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(2u128));

/// Errors in [`BitVec`] operations.
#[derive(Debug, Diagnostic, Error)]
pub enum BitVecError {
    /// Extract out of bounds.
    #[error("extract out of bounds")]
    ExtractOutOfBounds,
    /// Mismatched bit-vector widths in various operations.
    #[error("mismatched bit-vector widths in {0}")]
    MismatchedWidths(String),
    /// Shift amount too large to fit in u32.
    #[error("shift amount too large to fit in u32")]
    ShiftAmountTooLarge,
}

type Result<T> = std::result::Result<T, BitVecError>;

impl BitVec {
    /// Converts an (unsigned) [`Nat`] into a [`BitVec`] of the given width.
    ///
    /// Silently wraps if `v` does not fit.
    pub fn of_nat(width: Width, v: Nat) -> Self {
        BitVec::new(width, v)
    }

    /// Converts a (signed) [`Int`] into a [`BitVec`] of the given width.
    ///
    /// Silently wraps if `v` does not fit.
    pub fn of_int(width: Width, v: Int) -> Self {
        if v >= BigInt::ZERO {
            #[expect(
                clippy::unwrap_used,
                reason = "already checked that `v` is nonnegative, so `to_biguint()` will return `Some`."
            )]
            BitVec::new(width, v.to_biguint().unwrap())
        } else {
            // Do 2's complement encoding for the given bit-width.
            #[expect(
                clippy::unwrap_used,
                reason = "Safe because -v is guaranteed to be positive now."
            )]
            let pos = BitVec::new(width, (-v).to_biguint().unwrap());
            #[expect(
                clippy::expect_used,
                reason = "Both arguments have width equal to `width`"
            )]
            BitVec::add(&pos.not(), &BitVec::of_nat(width, BigUint::from(1u128)))
                .expect("both arguments have width equal to `width`")
        }
    }

    /// Converts a [`u128`] into a [`BitVec`] of the given width.
    ///
    /// Silently wraps if `val` does not fit.
    pub fn of_u128(width: Width, val: u128) -> Self {
        BitVec::of_nat(width, BigUint::from(val))
    }

    /// Converts an [`i128`] into a [`BitVec`] of the given width.
    ///
    /// Silently wraps if `val` does not fit.
    pub fn of_i128(width: Width, val: i128) -> Self {
        BitVec::of_int(width, BigInt::from(val))
    }

    /// Interprets a [`BitVec`] as a [`Nat`].
    pub fn to_nat(&self) -> Nat {
        self.v.clone()
    }

    /// Interprets a [`BitVec`] as a [`Nat`].
    pub fn as_nat(&self) -> &Nat {
        &self.v
    }

    /// Interprets a [`BitVec`] as an [`Int`].
    pub fn to_int(&self) -> Int {
        let sign_bit = self.msb();
        if self.width.get() < 2 {
            if sign_bit {
                BigInt::from(-1)
            } else {
                BigInt::ZERO
            }
        } else {
            // extract_bits follows the SMT-LIB semantics of returning bits from [i:j].
            // Val returns the 2's complement value without the sign bit.
            #[expect(clippy::unwrap_used, reason = "Already checked that width is not < 2")]
            let val = self.extract_bits(0, self.width.get() - 2).unwrap();
            #[expect(
                clippy::unwrap_used,
                reason = "The implementation of BigUint::to_bigint always returns Some"
            )]
            let val_bigint = BigUint::to_bigint(&val.v).unwrap();
            if !sign_bit {
                val_bigint
            } else {
                #[expect(
                    clippy::unwrap_used,
                    reason = "The implementation of BigUint::to_bigint always returns Some"
                )]
                let res =
                    -1 * BigUint::to_bigint(&TWO.pow(self.width.get() - 1)).unwrap() + val_bigint;
                res
            }
        }
    }

    /// Returns an integer representing the extracted bits from low to high, inclusive.
    ///
    /// `low` and/or `high` may be 0 without causing errors. However, we must
    /// have `low <= high < self.width`, else we'll get `Err` (not panic).
    pub fn extract_bits(&self, low: u32, high: u32) -> Result<Self> {
        if low <= high && high < self.width.get() {
            let rem = &self.v % TWO.pow(high + 1);
            let quotient = rem / TWO.pow(low);
            #[expect(
                clippy::expect_used,
                reason = "Because we add 1, the value cannot be 0"
            )]
            Ok(BitVec::of_nat(
                Width::new(high - low + 1).expect("because we add 1, the value cannot be 0"),
                quotient,
            ))
        } else {
            Err(BitVecError::ExtractOutOfBounds)
        }
    }

    //// Helper functions

    /// Synonym for `of_nat()`
    fn new(width: Width, val: Nat) -> Self {
        // Unlike in Lean, we do not need to check if `width` is 0 because `width` is a `NonZeroU32` and thus cannot be 0 by construction
        let v = val % TWO.pow(width.get());
        BitVec { width, v }
    }

    /// Returns a bit-vector with all bits set to 1 of the given width
    fn all_ones(width: Width) -> Self {
        let all_ones = TWO.pow(width.get() + 1) - 1u32;
        BitVec::of_nat(width, all_ones)
    }

    /// Returns whether the most significant bit is set
    fn msb(&self) -> bool {
        #[expect(
            clippy::unwrap_used,
            reason = "these arguments to extract_bits must always satisfy low <= high < self.width. note that self.width is a NonZeroU32 and thus cannot be 0"
        )]
        let bit = self
            .extract_bits(self.width.get() - 1, self.width.get() - 1)
            .unwrap()
            .v;
        bit != BigUint::ZERO
    }

    /// Returns whether the bit-vector is zero.
    fn is_zero(&self) -> bool {
        self.v == BigUint::ZERO
    }

    ////
    // Functions from SymCC/Data.lean
    ////

    /// Returns the bit-width of the bit-vector.
    pub const fn width(&self) -> Width {
        self.width
    }

    /// Returns (as Int) the minimum signed value that fits in the given bit-width.
    ///
    /// Compare to `int_min()`, which returns the minimum signed value as a `BitVec`.
    pub fn signed_min(n: Width) -> Int {
        // Unlike in Lean, we do not need to check if `width` is 0 because `width` is a `NonZeroU32` and thus cannot be 0 by construction
        #[expect(
            clippy::unwrap_used,
            reason = "The implementation of BigUint::to_bigint always returns Some"
        )]
        let two_to_n_minus_1 = BigUint::to_bigint(&TWO.pow(n.get() - 1)).unwrap();
        -two_to_n_minus_1
    }

    /// Returns the maximum signed value that fits in the given bit-width.
    pub fn signed_max(n: Width) -> Int {
        // Unlike in Lean, we do not need to check if `width` is 0 because `width` is a `NonZeroU32` and thus cannot be 0 by construction
        #[expect(
            clippy::unwrap_used,
            reason = "The implementation of BigUint::to_bigint always returns Some"
        )]
        let two_to_n_minus_1 = BigUint::to_bigint(&TWO.pow(n.get() - 1)).unwrap();
        two_to_n_minus_1 - 1
    }

    /// Checks if the given [`Int`] fits in the bit-width.
    pub fn overflows(n: Width, i: &Int) -> bool {
        i < &BitVec::signed_min(n) || i > &BitVec::signed_max(n)
    }

    ////
    // Functions from Lean BitVec standard library
    ////

    /// Bitwise not.
    pub fn not(&self) -> Self {
        BitVec::of_nat(self.width, &self.v ^ BitVec::all_ones(self.width).v)
    }

    /// Bit-vector negation.
    pub fn neg(&self) -> Self {
        let one = BitVec::of_u128(self.width, 1);
        #[expect(
            clippy::unwrap_used,
            reason = "`self.not()` and `one` have width equal to `self.width`"
        )]
        BitVec::add(&self.not(), &one).unwrap()
    }

    /// Minimum signed value of the given bit-width, encoded as a [`BitVec`].
    ///
    /// Compare to `signed_min()`, which returns the minimum signed value as an `Int`.
    pub fn int_min(width: Width) -> Self {
        BitVec::of_nat(width, TWO.pow(width.get() - 1))
    }

    /// Bit-vector signed less-than.
    pub fn slt(lhs: &Self, rhs: &Self) -> Result<bool> {
        if lhs.width != rhs.width {
            Err(BitVecError::MismatchedWidths("slt".into()))
        } else {
            Ok(lhs.to_int() < rhs.to_int())
        }
    }

    /// Bit-vector signed less-than-or-equal.
    pub fn sle(lhs: &Self, rhs: &Self) -> Result<bool> {
        if lhs.width != rhs.width {
            Err(BitVecError::MismatchedWidths("sle".into()))
        } else {
            Ok(lhs.to_int() <= rhs.to_int())
        }
    }

    /// Bit-vector unsigned less-than-or-equal.
    pub fn ule(lhs: &Self, rhs: &Self) -> Result<bool> {
        if lhs.width != rhs.width {
            Err(BitVecError::MismatchedWidths("ule".into()))
        } else {
            Ok(lhs.v <= rhs.v)
        }
    }

    /// Bit-vector unsigned less-than.
    pub fn ult(lhs: &Self, rhs: &Self) -> Result<bool> {
        if lhs.width != rhs.width {
            Err(BitVecError::MismatchedWidths("ult".into()))
        } else {
            Ok(lhs.v < rhs.v)
        }
    }

    /// Bit-vector addition.
    ///
    /// Only returns `Err` if the `lhs` and `rhs` widths mismatch.
    /// In particular, overflow is not an `Err`.
    pub fn add(lhs: &Self, rhs: &Self) -> Result<Self> {
        if lhs.width != rhs.width {
            Err(BitVecError::MismatchedWidths("add".into()))
        } else {
            Ok(BitVec::of_nat(lhs.width, &lhs.v + &rhs.v))
        }
    }

    /// Bit-vector subtraction.
    ///
    /// Only returns `Err` if the `lhs` and `rhs` widths mismatch.
    /// In particular, overflow is not an `Err`.
    pub fn sub(lhs: &Self, rhs: &Self) -> Result<Self> {
        if lhs.width != rhs.width {
            Err(BitVecError::MismatchedWidths("sub".into()))
        } else {
            BitVec::add(lhs, &rhs.neg())
        }
    }

    /// Bit-vector multiplication.
    ///
    /// Only returns `Err` if the `lhs` and `rhs` widths mismatch.
    /// In particular, overflow is not an `Err`.
    pub fn mul(lhs: &Self, rhs: &Self) -> Result<Self> {
        if lhs.width != rhs.width {
            Err(BitVecError::MismatchedWidths("mul".into()))
        } else {
            Ok(BitVec::of_nat(lhs.width, &lhs.v * &rhs.v))
        }
    }

    /// Bit-vector unsigned division.
    ///
    /// Semantics to match SMT bit-vector theory here: <https://smt-lib.org/theories-FixedSizeBitVectors.shtml>
    ///
    /// Only returns `Err` if the `lhs` and `rhs` widths mismatch.
    /// In particular, overflow is not an `Err`.
    pub fn udiv(lhs: &Self, rhs: &Self) -> Result<Self> {
        if lhs.width != rhs.width {
            return Err(BitVecError::MismatchedWidths("udiv".into()));
        };
        if rhs.v == BigUint::ZERO {
            Ok(BitVec::all_ones(lhs.width))
        } else {
            Ok(BitVec::of_nat(lhs.width, &lhs.v / &rhs.v))
        }
    }

    /// Bit-vector unsigned remainder.
    ///
    /// Semantics to match SMT bit-vector theory here: <https://smt-lib.org/theories-FixedSizeBitVectors.shtml>
    ///
    /// Only returns `Err` if the `lhs` and `rhs` widths mismatch.
    /// In particular, overflow is not an `Err`.
    pub fn urem(lhs: &Self, rhs: &Self) -> Result<Self> {
        if lhs.width != rhs.width {
            return Err(BitVecError::MismatchedWidths("urem".into()));
        };
        if rhs.v == BigUint::ZERO {
            Ok(lhs.clone())
        } else {
            Ok(BitVec::of_nat(lhs.width, &lhs.v % &rhs.v))
        }
    }

    /// Bit-vector signed division.
    ///
    /// Semantics to match SMT bit-vector logic here: <https://smt-lib.org/logics-all.shtml>
    ///
    /// Only returns `Err` if the `lhs` and `rhs` widths mismatch.
    /// In particular, overflow is not an `Err`.
    pub fn sdiv(lhs: &Self, rhs: &Self) -> Result<Self> {
        if lhs.width != rhs.width {
            return Err(BitVecError::MismatchedWidths("sdiv".into()));
        };
        let lhs_msb = lhs.msb();
        let rhs_msb = rhs.msb();

        if !lhs_msb && !rhs_msb {
            BitVec::udiv(lhs, rhs)
        } else if lhs_msb && !rhs_msb {
            Ok(BitVec::neg(&BitVec::udiv(&BitVec::neg(lhs), rhs)?))
        } else if !lhs_msb && rhs_msb {
            Ok(BitVec::neg(&BitVec::udiv(lhs, &BitVec::neg(rhs))?))
        } else {
            BitVec::udiv(&BitVec::neg(lhs), &BitVec::neg(rhs))
        }
    }

    /// Bit-vector signed remainder.
    ///
    /// Semantics to match SMT bit-vector logic here: <https://smt-lib.org/logics-all.shtml>
    ///
    /// Only returns `Err` if the `lhs` and `rhs` widths mismatch.
    /// In particular, overflow is not an `Err`.
    pub fn srem(lhs: &Self, rhs: &Self) -> Result<Self> {
        if lhs.width != rhs.width {
            return Err(BitVecError::MismatchedWidths("srem".into()));
        };
        let lhs_msb = lhs.msb();
        let rhs_msb = rhs.msb();

        if !lhs_msb && !rhs_msb {
            BitVec::urem(lhs, rhs)
        } else if lhs_msb && !rhs_msb {
            Ok(BitVec::neg(&BitVec::urem(&BitVec::neg(lhs), rhs)?))
        } else if !lhs_msb && rhs_msb {
            BitVec::urem(lhs, &BitVec::neg(rhs))
        } else {
            Ok(BitVec::neg(&BitVec::urem(
                &BitVec::neg(lhs),
                &BitVec::neg(rhs),
            )?))
        }
    }

    /// Bit-vector signed modulus.
    ///
    /// Semantics to match SMT bit-vector logic here: <https://smt-lib.org/logics-all.shtml>
    ///
    /// Only returns `Err` if the `lhs` and `rhs` widths mismatch.
    /// In particular, overflow is not an `Err`.
    pub fn smod(lhs: &Self, rhs: &Self) -> Result<Self> {
        if lhs.width != rhs.width {
            return Err(BitVecError::MismatchedWidths("smod".into()));
        };
        let lhs_msb = lhs.msb();
        let rhs_msb = rhs.msb();

        let abs_lhs = if !lhs_msb { lhs } else { &BitVec::neg(lhs) };

        let abs_rhs = if !rhs_msb { rhs } else { &BitVec::neg(rhs) };

        let u = BitVec::urem(abs_lhs, abs_rhs)?;
        if u.is_zero() || (!lhs_msb && !rhs_msb) {
            Ok(u)
        } else if lhs_msb && !rhs_msb {
            BitVec::add(&BitVec::neg(&u), rhs)
        } else if !lhs_msb && rhs_msb {
            BitVec::add(&u, rhs)
        } else {
            Ok(BitVec::neg(&u))
        }
    }

    /// Bit-vector left shift.
    ///
    /// Returns `Err` if the `lhs` and `rhs` widths mismatch, or if the shift
    /// amount does not fit in a `u32`.
    pub fn shl(lhs: &Self, rhs: &Self) -> Result<Self> {
        if lhs.width != rhs.width {
            return Err(BitVecError::MismatchedWidths("shl".into()));
        };
        let shift_amount = rhs.v.to_u32().ok_or(BitVecError::ShiftAmountTooLarge)?;
        let val = &lhs.v * TWO.pow(shift_amount);
        Ok(BitVec::of_nat(lhs.width, val))
    }

    /// Bit-vector logical right shift.
    ///
    /// Returns `Err` if the `lhs` and `rhs` widths mismatch, or if the shift
    /// amount does not fit in a `u32`.
    pub fn lshr(lhs: &Self, rhs: &Self) -> Result<Self> {
        if lhs.width != rhs.width {
            return Err(BitVecError::MismatchedWidths("lshr".into()));
        };
        let shift_amount = rhs.v.to_u32().ok_or(BitVecError::ShiftAmountTooLarge)?;
        let val = &lhs.v / TWO.pow(shift_amount);
        Ok(BitVec::of_nat(lhs.width, val))
    }

    /// Bit-vector concatenation.
    ///
    /// Panics if the total width exceeds u32::MAX.
    /// As of this writing, we shouldn't ever construct any bitvector longer than 128,
    /// which is an extremely long way from u32::MAX.
    pub fn concat(lhs: &Self, rhs: &Self) -> Result<Self> {
        #[expect(
            clippy::expect_used,
            reason = "Function is documented to panic if total width exceeds u32::MAX"
        )]
        let width = lhs
            .width
            .checked_add(rhs.width.get())
            .expect("width will not overflow u32");
        let new_val = (&lhs.v << rhs.width().get()) + &rhs.v;
        Ok(BitVec::of_nat(width, new_val))
    }

    /// Bit-vector unsigned (zero) extension.
    ///
    /// This matches the Lean implementation that just adjusts the length of the
    /// bit-vector to match n (and not the SMT-LIB implementation that zero extends
    /// the bit-vector by n bits). If n is less than the current bit-width it will
    /// truncate
    pub fn zero_extend(bv: &Self, n: Width) -> Self {
        BitVec::of_nat(n, bv.to_nat())
    }
}

impl std::fmt::Display for BitVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(bv{} {})", self.width(), self.as_nat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a BitVec from a binary string of '0's and '1's
    /// e.g. "0010" creates a bit vector of width 4 with value 2
    fn from_bin_str(s: &str) -> BitVec {
        assert!(!s.is_empty(), "Cannot create bitvector from empty string.");
        // Validate that the string only contains '0' and '1'
        for c in s.chars() {
            assert!(
                c == '0' || c == '1',
                "Binary string must only contain '0' or '1'"
            );
        }

        // Parse the binary string into a BigInt
        let val = BigUint::parse_bytes(s.as_bytes(), 2).unwrap();
        BitVec::of_nat(
            Width::new(s.len().try_into().unwrap())
                .expect("already checked that the string length is not 0"),
            val,
        )
    }

    /// Panics if `width` is 0
    #[track_caller]
    fn bitvec(width: u32, val: u128) -> BitVec {
        BitVec::of_u128(Width::new(width).unwrap(), val)
    }

    /// Panics if `width` is 0
    #[track_caller]
    fn bitvec_i(width: u32, val: i128) -> BitVec {
        BitVec::of_i128(Width::new(width).unwrap(), val)
    }

    #[track_caller]
    fn assert_eq_int(rhs: BigInt, lhs: i32) {
        assert_eq!(rhs, BigInt::from(lhs));
    }

    #[track_caller]
    fn assert_eq_nat(rhs: BigUint, lhs: u32) {
        assert_eq!(rhs, BigUint::from(lhs));
    }

    #[test]
    fn test_from_bin_str() {
        // Test basic binary string conversion
        let bv = from_bin_str("0010");
        assert_eq!(bv.width().get(), 4);
        assert_eq_nat(bv.to_nat(), 2);

        // Test different values
        assert_eq_nat(from_bin_str("101").to_nat(), 5);
        assert_eq_nat(from_bin_str("1111").to_nat(), 15);
        assert_eq_nat(from_bin_str("10000").to_nat(), 16);
        assert_eq_nat(from_bin_str("00000").to_nat(), 0);
    }

    #[test]
    fn test_constructors() {
        // Test regular constructor
        let bv1 = bitvec(4, 2);
        assert_eq!(bv1.width().get(), 4);
        assert_eq_nat(bv1.to_nat(), 2);

        // Test value overflow wrapping
        let bv2 = bitvec(3, 10); // 10 in binary is 1010, truncated to 3 bits: 010
        assert_eq!(bv2.width().get(), 3);
        assert_eq_nat(bv2.to_nat(), 2);

        // Test of_nat
        let bv3 = bitvec(5, 10);
        assert_eq!(bv3.width().get(), 5);
        assert_eq_nat(bv3.to_nat(), 10);

        // Test of_int
        let bv4 = bitvec_i(6, -1); // -1 in two's complement 6-bit is 111111
        assert_eq!(bv4.width().get(), 6);
        // A negative number will be represented as its two's complement form
        assert_eq_nat(bv4.to_nat(), 63); // 111111 in binary is 63 as a natural number
        assert_eq_int(bv4.to_int(), -1); // 111111 in binary is -1 as a signed number

        assert_eq!(bv4, BitVec::all_ones(bv4.width()));
    }

    #[test]
    fn test_extract_bits() {
        let bv = from_bin_str("110101");

        // Extract middle bits
        let extracted = bv.extract_bits(1, 3).unwrap(); // Extract bits 1,2,3 (010)
        assert_eq!(extracted.width().get(), 3);
        assert_eq_nat(extracted.to_nat(), 2);

        // Extract single bit
        let bit = bv.extract_bits(5, 5).unwrap(); // Extract the most significant bit
        assert_eq!(bit.width().get(), 1);
        assert_eq_nat(bit.to_nat(), 1);

        // Extract all bits
        let all = bv.extract_bits(0, 5).unwrap(); // Extract all bits
        assert_eq!(all.width().get(), 6);
        assert_eq_nat(all.to_nat(), 53); // 110101 = 53
    }

    #[test]
    fn test_bitwise_ops() {
        // Test NOT operation
        let bv = from_bin_str("1010");
        let not_bv = bv.not();
        // In a 4-bit representation, NOT 1010 = 0101
        assert_eq_nat(not_bv.to_nat(), 5);
        assert_eq!(not_bv.not(), bv);
    }

    #[test]
    fn test_arithmetic_ops() {
        let bv = from_bin_str("1010");
        assert_eq_int(bv.to_int(), -6);
        // Test negation (two's complement)
        let neg_bv = bv.neg();
        // NEG 1010 = NOT 1010 + 1 = 0101 + 1 = 0110 = 6
        assert_eq_nat(neg_bv.to_nat(), 6);

        let bv_min = from_bin_str("1000");
        assert_eq!(bv_min, bv_min.neg());

        let bv1 = from_bin_str("0101"); // 5
        let bv2: BitVec = from_bin_str("0011"); // 3
        let bv3: BitVec = from_bin_str("1011"); // 11

        // Test addition without overflow
        let sum = BitVec::add(&bv1, &bv2).unwrap();
        assert_eq_nat(sum.to_nat(), 8); // 5 + 3 = 8

        // Test addition with overflow
        let sum = BitVec::add(&bv1, &bv3).unwrap();
        assert_eq_nat(sum.to_nat(), 0); // 5 + 11 = 16 mod 2^4 = 0

        // Test subtraction
        let diff = BitVec::sub(&bv1, &bv2).unwrap();
        assert_eq_nat(diff.to_nat(), 2); // 5 - 3 = 2

        // Test subtraction negative value
        let diff = BitVec::sub(&bv2, &bv1).unwrap();
        assert_eq_int(diff.to_int(), -2); // 3 - 5 = -2

        // Test multiplication no overflow
        let prod = BitVec::mul(&bv1, &bv2).unwrap();
        assert_eq_nat(prod.to_nat(), 15); // 5 * 3 = 15

        // Test multiplication overflow
        let prod = BitVec::mul(&bv2, &bv3).unwrap();
        assert_eq_nat(prod.to_nat(), 1); // 3 * 11 mod 2^4 = 33 mod 2^4 = 1
    }

    #[test]
    fn test_division() {
        let bv1 = from_bin_str("0101"); // 5
        let bv2: BitVec = from_bin_str("0011"); // 3

        // Test division unsigned
        let quot = BitVec::udiv(&bv1, &bv2).unwrap();
        assert_eq_nat(quot.to_nat(), 1); // 5 / 3 = 1

        let rem = BitVec::urem(&bv1, &bv2).unwrap();
        assert_eq_nat(rem.to_nat(), 2); // 5 mod 3 = 2

        // Test division by zero unsigned
        let zero = bitvec(4, 0);
        let div_by_zero = BitVec::udiv(&bv1, &zero).unwrap();
        assert_eq_nat(div_by_zero.to_nat(), 15); // All ones for division by 0

        let rem_by_zero = BitVec::urem(&bv1, &zero).unwrap();
        assert_eq!(rem_by_zero.to_nat(), bv1.to_nat());

        // Test division signed

        // Both values positive
        let quot = BitVec::sdiv(&bv1, &bv2).unwrap();
        assert_eq_nat(quot.to_nat(), 1); // 5 / 3 = 1
        let srem = BitVec::srem(&bv1, &bv2).unwrap();
        assert_eq_int(srem.to_int(), 2);
        let smod = BitVec::smod(&bv1, &bv2).unwrap();
        assert_eq_int(smod.to_int(), 2);

        // Divident is negative, divisor positive
        let neg_bv1 = from_bin_str("1011"); // -5 in 4-bit two's complement
        let pos_bv2 = from_bin_str("0011"); // 3

        // -5 / 3 = -1 (truncated towards zero)
        let quot_neg_pos = BitVec::sdiv(&neg_bv1, &pos_bv2).unwrap();
        assert_eq_int(quot_neg_pos.to_int(), -1);

        // -5 srem 3 = -2 (remainder has same sign as dividend)
        let srem_neg_pos = BitVec::srem(&neg_bv1, &pos_bv2).unwrap();
        assert_eq_int(srem_neg_pos.to_int(), -2);

        // -5 smod 3 = 1 (result has same sign as divisor when non-zero)
        let smod_neg_pos = BitVec::smod(&neg_bv1, &pos_bv2).unwrap();
        assert_eq_int(smod_neg_pos.to_int(), 1);

        // Test with -8 (INT_MIN) / 3
        let int_min = from_bin_str("1000"); // -8 in 4-bit two's complement
        let quot_min_pos = BitVec::sdiv(&int_min, &pos_bv2).unwrap();
        assert_eq_int(quot_min_pos.to_int(), -2); // -8 / 3 = -2

        let srem_min_pos = BitVec::srem(&int_min, &pos_bv2).unwrap();
        assert_eq_int(srem_min_pos.to_int(), -2); // -8 srem 3 = -2

        let smod_min_pos = BitVec::smod(&int_min, &pos_bv2).unwrap();
        assert_eq_int(smod_min_pos.to_int(), 1); // -8 smod 3 = 1

        // Divident is positive, divisor negative
        let pos_bv1 = from_bin_str("0101"); // 5
        let neg_bv2 = from_bin_str("1101"); // -3 in 4-bit two's complement

        // 5 / (-3) = -1 (truncated towards zero)
        let quot_pos_neg = BitVec::sdiv(&pos_bv1, &neg_bv2).unwrap();
        assert_eq_int(quot_pos_neg.to_int(), -1);

        // 5 srem (-3) = 2 (remainder has same sign as dividend)
        let srem_pos_neg = BitVec::srem(&pos_bv1, &neg_bv2).unwrap();
        assert_eq_int(srem_pos_neg.to_int(), 2);

        // 5 smod (-3) = -1 (result has same sign as divisor when non-zero)
        let smod_pos_neg = BitVec::smod(&pos_bv1, &neg_bv2).unwrap();
        assert_eq_int(smod_pos_neg.to_int(), -1);

        // Test with 7 / (-3)
        let pos_bv7 = from_bin_str("0111"); // 7
        let quot_7_neg3 = BitVec::sdiv(&pos_bv7, &neg_bv2).unwrap();
        assert_eq_int(quot_7_neg3.to_int(), -2); // 7 / (-3) = -2

        let srem_7_neg3 = BitVec::srem(&pos_bv7, &neg_bv2).unwrap();
        assert_eq_int(srem_7_neg3.to_int(), 1); // 7 srem (-3) = 1

        let smod_7_neg3 = BitVec::smod(&pos_bv7, &neg_bv2).unwrap();
        assert_eq_int(smod_7_neg3.to_int(), -2); // 7 smod (-3) = -2

        // Divident and divisor negative
        let neg_bv5 = from_bin_str("1011"); // -5 in 4-bit two's complement
        let neg_bv3 = from_bin_str("1101"); // -3 in 4-bit two's complement

        // (-5) / (-3) = 1 (positive result)
        let quot_neg_neg = BitVec::sdiv(&neg_bv5, &neg_bv3).unwrap();
        assert_eq_int(quot_neg_neg.to_int(), 1);

        // (-5) srem (-3) = -2 (remainder has same sign as dividend)
        let srem_neg_neg = BitVec::srem(&neg_bv5, &neg_bv3).unwrap();
        assert_eq_int(srem_neg_neg.to_int(), -2);

        // (-5) smod (-3) = -2 (result has same sign as divisor)
        let smod_neg_neg = BitVec::smod(&neg_bv5, &neg_bv3).unwrap();
        assert_eq_int(smod_neg_neg.to_int(), -2);

        // Test with (-8) / (-3)
        let quot_min_neg = BitVec::sdiv(&int_min, &neg_bv3).unwrap();
        assert_eq_int(quot_min_neg.to_int(), 2); // (-8) / (-3) = 2

        let srem_min_neg = BitVec::srem(&int_min, &neg_bv3).unwrap();
        assert_eq_int(srem_min_neg.to_int(), -2); // (-8) srem (-3) = -2

        let smod_min_neg = BitVec::smod(&int_min, &neg_bv3).unwrap();
        assert_eq_int(smod_min_neg.to_int(), -2); // (-8) smod (-3) = -2

        // Test edge case: (-8) / (-1) - potential overflow case
        let neg_one = from_bin_str("1111"); // -1 in 4-bit two's complement
        let quot_min_neg1 = BitVec::sdiv(&int_min, &neg_one).unwrap();
        assert_eq_int(quot_min_neg1.to_int(), -8); // (-8) / (-1) = 8, but wraps to -8 in 4-bit

        let srem_min_neg1 = BitVec::srem(&int_min, &neg_one).unwrap();
        assert_eq_int(srem_min_neg1.to_int(), 0); // (-8) srem (-1) = 0

        let smod_min_neg1 = BitVec::smod(&int_min, &neg_one).unwrap();
        assert_eq_int(smod_min_neg1.to_int(), 0); // (-8) smod (-1) = 0

        // Test division by zero signed
        let div_by_zero = BitVec::sdiv(&bv1, &zero).unwrap();
        // Should follow SMT-LIB semantics
        assert_eq_nat(div_by_zero.to_nat(), 15); // All ones for positive dividend

        let div_by_zero_neg = BitVec::sdiv(&neg_bv1, &zero).unwrap();
        assert_eq_nat(div_by_zero_neg.to_nat(), 1); // If the divident is negative, then division by 0 is one

        let srem_by_zero = BitVec::srem(&bv1, &zero).unwrap();
        assert_eq!(srem_by_zero.to_nat(), bv1.to_nat()); // Return dividend for srem by zero

        let smod_by_zero = BitVec::smod(&bv1, &zero).unwrap();
        assert_eq!(smod_by_zero.to_nat(), bv1.to_nat()); // Return dividend for smod by zero
    }

    #[test]
    fn test_comparison_ops() {
        let bv1 = from_bin_str("0101"); // 5
        let bv2 = from_bin_str("0011"); // 3

        // Test less than
        assert!(!BitVec::slt(&bv1, &bv2).unwrap()); // 5 < 3 is false
        assert!(BitVec::slt(&bv2, &bv1).unwrap()); // 3 < 5 is true

        // Test less than or equal
        assert!(!BitVec::sle(&bv1, &bv2).unwrap()); // 5 <= 3 is false
        assert!(BitVec::sle(&bv2, &bv1).unwrap()); // 3 <= 5 is true
        assert!(BitVec::sle(&bv1, &bv1).unwrap()); // 5 <= 5 is true

        // Test for negative numbers
        let zero = from_bin_str("0000"); // -5 in 4-bit two's complement
        let neg_5 = from_bin_str("1011"); // -5 in 4-bit two's complement
        let neg_3: BitVec = from_bin_str("1101"); // -3 in 4-bit two's complement
        let neg_8: BitVec = from_bin_str("1000"); // -8 in 4-bit two's complement
        let one: BitVec = from_bin_str("0001"); // 1 in 4-bit two's complement

        assert!(BitVec::ult(&neg_5, &neg_3).unwrap());
        assert!(BitVec::ult(&one, &neg_8).unwrap());
        assert!(BitVec::slt(&neg_5, &neg_3).unwrap());
        assert!(BitVec::slt(&neg_5, &zero).unwrap());
    }

    #[test]
    fn test_shift_ops() {
        let bv1 = from_bin_str("0101"); // 5
        let shift1 = from_bin_str("0001"); // shift by 1
        let shift2 = from_bin_str("0010"); // shift by 2

        // Test left shift
        let left_shift1 = BitVec::shl(&bv1, &shift1).unwrap(); // 5 << 1 = 10 (1010)
        assert_eq_nat(left_shift1.to_nat(), 10);

        let left_shift2 = BitVec::shl(&bv1, &shift2).unwrap(); // 5 << 2 = 20 (modulo 16 = 4)
        assert_eq_nat(left_shift2.to_nat(), 4);

        // Test logical right shift
        let bv2 = from_bin_str("1100"); // 12
        let right_shift1 = BitVec::lshr(&bv2, &shift1).unwrap(); // 12 >> 1 = 6
        assert_eq_nat(right_shift1.to_nat(), 6);

        let right_shift2 = BitVec::lshr(&bv2, &shift2).unwrap(); // 12 >> 2 = 3
        assert_eq_nat(right_shift2.to_nat(), 3);
    }

    #[test]
    fn test_concat() {
        let bv1 = from_bin_str("101"); // 5
        let bv2 = from_bin_str("11"); // 3

        let concat1 = BitVec::concat(&bv1, &bv2).unwrap(); // 10111 (binary) = 23
        assert_eq!(concat1.width().get(), 5); // 3 + 2 = 5 bits
        assert_eq_nat(concat1.to_nat(), 23);

        let concat2 = BitVec::concat(&bv2, &bv1).unwrap(); // 11101 (binary) = 29
        assert_eq!(concat2.width().get(), 5); // 2 + 3 = 5 bits
        assert_eq_nat(concat2.to_nat(), 29);
    }

    #[test]
    fn test_zero_extend() {
        let bv = from_bin_str("101"); // 5

        // Extending to the same width should return the same value
        let extended1 = BitVec::zero_extend(&bv, Width::new(3).unwrap());
        assert_eq!(extended1.width().get(), 3);
        assert_eq_nat(extended1.to_nat(), 5);

        // Testing with a smaller width (allowed by implementation)
        let extended2 = BitVec::zero_extend(&bv, Width::new(2).unwrap());
        assert_eq!(extended2.width().get(), 2);
        assert_eq_nat(extended2.to_nat(), 1); // 101 truncated to 2 bits is 01 = 1
    }

    #[test]
    fn test_overflow() {
        // Test signed_min and signed_max
        assert_eq!(BitVec::signed_min(Width::new(4).unwrap()), BigInt::from(-8)); // -2^(4-1)
        assert_eq!(BitVec::signed_max(Width::new(4).unwrap()), BigInt::from(7)); // 2^(4-1) - 1

        // Test overflow detection
        assert!(BitVec::overflows(Width::new(4).unwrap(), &BigInt::from(8))); // 8 overflows 4-bit signed
        assert!(BitVec::overflows(Width::new(4).unwrap(), &BigInt::from(-9))); // -9 overflows 4-bit signed
        assert!(!BitVec::overflows(Width::new(4).unwrap(), &BigInt::from(7))); // 7 doesn't overflow
        assert!(!BitVec::overflows(
            Width::new(4).unwrap(),
            &BigInt::from(-8)
        )); // -8 doesn't overflow

        // Test int_min
        let min = BitVec::int_min(Width::new(4).unwrap());
        assert_eq!(min.width().get(), 4);
        assert_eq_nat(min.to_nat(), 8); // -8 in 4-bit two's complement is 1000 (8)
    }
}
