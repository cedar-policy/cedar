// This is a part of Chrono.
// See README.md and LICENSE.txt for details.
//
// This file is `src/offset/mod.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples removed; code behind chrono's Cargo features (not enabled in Cedar) removed; code not
//   used by Cedar removed.

//! The time zone, which calculates offsets from the local time to UTC.
//!
//! There are four operations provided by the `TimeZone` trait:
//!
//! 1. Converting the local `NaiveDateTime` to `DateTime<Tz>`
//! 2. Converting the UTC `NaiveDateTime` to `DateTime<Tz>`
//! 3. Converting `DateTime<Tz>` to the local `NaiveDateTime`
//! 4. Constructing `DateTime<Tz>` objects from various offsets
//!
//! 1 is used for constructors. 2 is used for the `with_timezone` method of date and time types.
//! 3 is used for other methods, e.g. `year()` or `format()`, and provided by an associated type
//! which implements `Offset` (which then passed to `TimeZone` for actual implementations).
//! Technically speaking `TimeZone` has a total knowledge about given timescale,
//! but `Offset` is used as a cache to avoid the repeated conversion
//! and provides implementations for 1 and 3.
//! An `TimeZone` instance can be reconstructed from the corresponding `Offset` instance.

use core::fmt;

use crate::extensions::chrono::naive::NaiveDateTime;
#[allow(deprecated)]
use crate::extensions::chrono::DateTime;

pub(crate) mod fixed;
pub use self::fixed::FixedOffset;

pub(crate) mod utc;
pub use self::utc::Utc;

/// The result of mapping a local time to a concrete instant in a given time zone.
///
/// The calculation to go from a local time (wall clock time) to an instant in UTC can end up in
/// three cases:
/// * A single, simple result.
/// * An ambiguous result when the clock is turned backwards during a transition due to for example
///   DST.
/// * No result when the clock is turned forwards during a transition due to for example DST.
///
/// When the clock is turned backwards it creates a _fold_ in local time, during which the local
/// time is _ambiguous_. When the clock is turned forwards it creates a _gap_ in local time, during
/// which the local time is _missing_, or does not exist.
///
/// Chrono does not return a default choice or invalid data during time zone transitions, but has
/// the `MappedLocalTime` type to help deal with the result correctly.
///
/// The type of `T` is usually a [`DateTime`] but may also be only an offset.
pub type MappedLocalTime<T> = LocalResult<T>;
#[derive(Clone, PartialEq, Debug, Copy, Eq, Hash)]
/// Old name of [`MappedLocalTime`]. See that type for more documentation.
pub enum LocalResult<T> {
    /// The local time maps to a single unique result.
    Single(T),

    /// The local time is _ambiguous_ because there is a _fold_ in the local time.
    ///
    /// This variant contains the two possible results, in the order `(earliest, latest)`.
    Ambiguous(T, T),

    /// The local time does not exist because there is a _gap_ in the local time.
    ///
    /// This variant may also be returned if there was an error while resolving the local time,
    /// caused by for example missing time zone data files, an error in an OS API, or overflow.
    None,
}

impl<T> MappedLocalTime<T> {
    /// Maps a `MappedLocalTime<T>` into `MappedLocalTime<U>` with given function.
    ///
    /// Returns `MappedLocalTime::None` if the function returns `None`.
    #[must_use]
    pub(crate) fn and_then<U, F: FnMut(T) -> Option<U>>(self, mut f: F) -> MappedLocalTime<U> {
        match self {
            MappedLocalTime::None => MappedLocalTime::None,
            MappedLocalTime::Single(v) => match f(v) {
                Some(new) => MappedLocalTime::Single(new),
                None => MappedLocalTime::None,
            },
            MappedLocalTime::Ambiguous(min, max) => match (f(min), f(max)) {
                (Some(min), Some(max)) => MappedLocalTime::Ambiguous(min, max),
                _ => MappedLocalTime::None,
            },
        }
    }
}

impl<T: fmt::Debug> MappedLocalTime<T> {}

/// The offset from the local time to UTC.
pub trait Offset: Sized + Clone + fmt::Debug {
    /// Returns the fixed offset from UTC to the local time stored.
    fn fix(&self) -> FixedOffset;
}

/// The time zone.
///
/// The methods here are the primary constructors for the [`DateTime`] type.
pub trait TimeZone: Sized + Clone {
    /// An associated offset type.
    /// This type is used to store the actual offset in date and time types.
    /// The original `TimeZone` value can be recovered via `TimeZone::from_offset`.
    type Offset: Offset;

    /// Reconstructs the time zone from the offset.
    fn from_offset(offset: &Self::Offset) -> Self;

    /// Creates the offset(s) for given local `NaiveDateTime` if possible.
    fn offset_from_local_datetime(&self, local: &NaiveDateTime) -> MappedLocalTime<Self::Offset>;

    /// Converts the local `NaiveDateTime` to the timezone-aware `DateTime` if possible.
    #[allow(clippy::wrong_self_convention)]
    fn from_local_datetime(&self, local: &NaiveDateTime) -> MappedLocalTime<DateTime<Self>> {
        self.offset_from_local_datetime(local).and_then(|off| {
            local
                .checked_sub_offset(off.fix())
                .map(|dt| DateTime::from_naive_utc_and_offset(dt, off))
        })
    }

    /// Creates the offset for given UTC `NaiveDateTime`. This cannot fail.
    fn offset_from_utc_datetime(&self, utc: &NaiveDateTime) -> Self::Offset;

    /// Converts the UTC `NaiveDateTime` to the local time.
    /// The UTC is continuous and thus this cannot fail (but can give the duplicate local time).
    #[allow(clippy::wrong_self_convention)]
    fn from_utc_datetime(&self, utc: &NaiveDateTime) -> DateTime<Self> {
        DateTime::from_naive_utc_and_offset(*utc, self.offset_from_utc_datetime(utc))
    }
}
