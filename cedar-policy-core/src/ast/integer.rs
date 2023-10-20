use ibig::IBig;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fmt::Formatter;
use std::ops::Neg;

/// The integer type. Currently i64, but we may change to an unbounded Integer type
// pub type Integer = i64;

/// Wrapper type so we can impl the (De)Serialize Traits
#[derive(Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Debug)]
pub struct BigInt(IBig);

/// The integer type we use internally
pub type Integer = BigInt;

/// The integer type we use when parsing input
pub type InputInteger = i64;

impl From<IBig> for BigInt {
    fn from(value: IBig) -> Self {
        BigInt(value)
    }
}

impl From<i64> for BigInt {
    fn from(value: i64) -> Self {
        BigInt(value.into())
    }
}

impl From<i32> for BigInt {
    fn from(value: i32) -> Self {
        BigInt(value.into())
    }
}

impl From<u64> for BigInt {
    fn from(value: u64) -> Self {
        BigInt(value.into())
    }
}

//TODO: deal with out of bounds values
impl From<BigInt> for i64 {
    fn from(value: BigInt) -> Self {
        value.into()
    }
}

impl fmt::Display for BigInt {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Neg for BigInt {
    type Output = BigInt;

    fn neg(self) -> Self::Output {
        BigInt(-self.0.clone())
    }
}

impl BigInt {
    pub fn checked_neg(&self) -> Option<Self> {
        Some(BigInt(-self.0.clone()))
    }

    pub fn checked_add(&self, other: BigInt) -> Option<Self> {
        Some(BigInt(self.0.clone() + other.0))
    }

    pub fn checked_sub(&self, other: BigInt) -> Option<Self> {
        Some(BigInt(self.0.clone() - other.0))
    }

    pub fn checked_mul(&self, other: BigInt) -> Option<Self> {
        Some(BigInt(self.0.clone() * other.0))
    }
}

// /// `Copy` may be expensive but is usually cheap so we use it
// impl Copy for BigInt {
//
// }

//TODO: write correct (de)serializers

impl Serialize for Integer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i32(0)
    }
}

impl<'de> Deserialize<'de> for Integer {
    fn deserialize<D>(deserializer: D) -> Result<Integer, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Integer::from(0))
    }
}
