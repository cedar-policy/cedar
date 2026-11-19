// This is a part of Chrono.
// See README.md and LICENSE.txt for details.
//
// This file is `src/format/formatting.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples marked `ignore`; code behind chrono's Cargo features (not enabled in Cedar) removed;
//   code not used by Cedar removed.

//! Date and time formatting routines.

use core::fmt::{self, Write};

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
