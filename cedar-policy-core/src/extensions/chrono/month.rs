// This file is `src/month.rs` from chrono 0.4.45 (https://github.com/chronotope/chrono),
// Copyright (c) 2014--2026, Kang Seonghoon and contributors, used under the
// Apache License, Version 2.0 (see the LICENSE file at the root of the Cedar repository).
// Modified by Cedar Contributors: `crate::` paths rewritten to `crate::extensions::chrono::`; doc
//   examples marked `ignore`; other changes marked with `Cedar:` comments; code behind chrono's
//   Cargo features (not enabled in Cedar) removed; code not used by Cedar removed.

/// A duration in calendar months
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Months(pub(crate) u32);

