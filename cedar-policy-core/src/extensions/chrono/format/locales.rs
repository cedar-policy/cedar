// This file is `src/format/locales.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: code behind chrono's Cargo features (not enabled in Cedar) removed.

mod unlocalized {
    #[derive(Copy, Clone, Debug)]
    pub(crate) struct Locale;

    pub(crate) const fn default_locale() -> Locale {
        Locale
    }

    pub(crate) const fn short_months(_locale: Locale) -> &'static [&'static str] {
        &["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    }

    pub(crate) const fn long_months(_locale: Locale) -> &'static [&'static str] {
        &[
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ]
    }

    pub(crate) const fn short_weekdays(_locale: Locale) -> &'static [&'static str] {
        &["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    }

    pub(crate) const fn long_weekdays(_locale: Locale) -> &'static [&'static str] {
        &["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
    }

    pub(crate) const fn am_pm(_locale: Locale) -> &'static [&'static str] {
        &["AM", "PM"]
    }

    pub(crate) const fn decimal_point(_locale: Locale) -> &'static str {
        "."
    }
}

pub(crate) use unlocalized::*;
