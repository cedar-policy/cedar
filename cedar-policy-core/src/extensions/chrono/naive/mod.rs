// This file is `src/naive/mod.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples removed; code behind chrono's Cargo features (not enabled in Cedar) removed; code not
//   used by Cedar removed.
//! Date and time types unconcerned with timezones.
//!
//! They are primarily building blocks for other types
//! (e.g. [`TimeZone`](crate::extensions::chrono::offset::TimeZone)),
//! but can be also used for the simpler date and time handling.

mod date;
mod datetime;
mod internals;
mod isoweek;
mod time;

pub use self::date::NaiveDate;
#[allow(deprecated)]
pub use self::datetime::NaiveDateTime;
pub(super) use self::isoweek::IsoWeek;
pub(crate) use self::time::NaiveTime;
