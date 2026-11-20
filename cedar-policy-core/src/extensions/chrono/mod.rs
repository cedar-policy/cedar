// This file is `src/lib.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: moved from `src/lib.rs`; `crate::` paths rewritten to
//   `crate::extensions::chrono::`; doc examples removed; other changes marked with `Cedar:`
//   comments; code behind chrono's Cargo features (not enabled in Cedar) removed; code not used by
//   Cedar removed.
//! # Chrono: Date and Time for Rust
//!
//! This module contains the parts of chrono 0.4.45 that Cedar uses, for dates and times in the
//! [proleptic Gregorian calendar]:
//!
//! * The [`DateTime`] type is timezone-aware by default, with separate timezone-naive types.
//! * Operations that may produce an invalid date and time return `Option`.
//! * Parsing uses a `strftime` inspired date and time formatting syntax.
//!
//! [proleptic Gregorian calendar]: https://en.wikipedia.org/wiki/Proleptic_Gregorian_calendar
//!
//! ## Limitations
//!
//! * Only the proleptic Gregorian calendar (i.e. extended to support older dates) is supported.
//! * Date types are limited to about +/- 262,000 years from the common epoch.
//! * Time types are limited to nanosecond accuracy.
//! * Leap seconds can be represented, but Chrono does not fully support them.
//!   See "Leap Second Handling" in the `NaiveTime` documentation.

// Cedar: chrono's crate-level attributes (`doc(html_root_url)`, `warn(unreachable_pub)`,
// `cfg_attr(.., no_std)`, `cfg_attr(docsrs, feature(doc_cfg))`) are removed because they are only
// valid at a crate root. The lint overrides below keep Cedar's lint configuration from applying to
// this vendored code.
#![allow(
    clippy::all,
    clippy::nursery,
    clippy::pedantic,
    clippy::restriction,
    reason = "vendored chrono code is kept as close to upstream as possible"
)]
#![allow(
    rust_2018_idioms,
    missing_debug_implementations,
    private_interfaces,
    private_bounds,
    reason = "vendored chrono code is kept close to upstream"
)]

mod time_delta;
pub(super) use time_delta::TimeDelta;

mod datetime;
pub use datetime::DateTime;

mod format;
pub use format::ParseError;

mod naive;
use naive::IsoWeek;
pub(super) use naive::NaiveTime;
pub use naive::{NaiveDate, NaiveDateTime};

mod offset;
#[doc(inline)]
use offset::FixedOffset;
pub use offset::Utc;

mod weekday;
use weekday::Weekday;

mod traits;
use traits::{Datelike, Timelike};

/// Workaround because `?` is not (yet) available in const context.
// Cedar: `#[macro_export]` replaced by a crate-local re-export so the macro is not exported from
// `cedar-policy-core`.
macro_rules! try_opt {
    ($e:expr) => {
        match $e {
            Some(v) => v,
            None => return None,
        }
    };
}
use try_opt;

/// Workaround because `.expect()` is not (yet) available in const context.
const fn expect<T: Copy>(opt: Option<T>, msg: &str) -> T {
    match opt {
        Some(val) => val,
        None => panic!("{}", msg),
    }
}
