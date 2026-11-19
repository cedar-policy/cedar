// This is a part of Chrono.
// See README.md and LICENSE.txt for details.
//
// This file is `src/format/formatting.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples marked `ignore`; code behind chrono's Cargo features (not enabled in Cedar) removed.

//! Date and time formatting routines.

use core::fmt::{self, Write};

/// Specific formatting options for seconds. This may be extended in the
/// future, so exhaustive matching in external code is not recommended.
///
/// See the `TimeZone::to_rfc3339_opts` function for usage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[allow(clippy::manual_non_exhaustive)]
pub enum SecondsFormat {
    /// Format whole seconds only, with no decimal point nor subseconds.
    Secs,

    /// Use fixed 3 subsecond digits. This corresponds to [Fixed::Nanosecond3].
    Millis,

    /// Use fixed 6 subsecond digits. This corresponds to [Fixed::Nanosecond6].
    Micros,

    /// Use fixed 9 subsecond digits. This corresponds to [Fixed::Nanosecond9].
    Nanos,

    /// Automatically select one of `Secs`, `Millis`, `Micros`, or `Nanos` to display all available
    /// non-zero sub-second digits.  This corresponds to [Fixed::Nanosecond].
    AutoSi,

    // Do not match against this.
    #[doc(hidden)]
    __NonExhaustive,
}

/// Equivalent to `{:02}` formatting for n < 100.
pub(crate) fn write_hundreds(w: &mut (impl Write + ?Sized), n: u8) -> fmt::Result {
    if n >= 100 {
        return Err(fmt::Error);
    }

    let tens = b'0' + n / 10;
    let ones = b'0' + n % 10;
    w.write_char(tens as char)?;
    w.write_char(ones as char)
}

