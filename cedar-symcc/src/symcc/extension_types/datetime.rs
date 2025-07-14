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

//! This module defines Cedar datetime and duration values and functions.
//! It is based on
//! https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/Cedar/Spec/Ext/Datetime.lean

/// A datetime value is measured in milliseconds and constructed from a datetime string.
/// A datetime string must be of one of the forms:
///   - `YYYY-MM-DD` (date only)
///   - `YYYY-MM-DDThh:mm:ssZ` (UTC)
///   - `YYYY-MM-DDThh:mm:ss.SSSZ` (UTC with millisecond precision)
///   - `YYYY-MM-DDThh:mm:ss(+|-)hhmm` (With timezone offset in hours and minutes)
///   - `YYYY-MM-DDThh:mm:ss.SSS(+|-)hhmm` (With timezone offset in hours and minutes and millisecond precision)
///
/// Regardless of the timezone, offset is always normalized to UTC.
///
/// The datetime type does not provide a way to create a datetime from a Unix timestamp.
/// One of the readable formats listed above must be used instead.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Datetime {
    val: i64,
}

const MILLISECONDS_PER_SECOND: i64 = 1000;
const MILLISECONDS_PER_DAY: i64 = 86400000;

impl Datetime {
    pub fn offset(&self, duration: Duration) -> Option<Datetime> {
        Some(Self {
            val: self.val.checked_add(duration.val)?,
        })
    }

    pub fn duration_since(&self, other: &Self) -> Option<Duration> {
        Some(Duration {
            val: self.val.checked_sub(other.val)?,
        })
    }

    pub fn to_date(&self) -> Option<Datetime> {
        if self.val >= 0 {
            Some(Self {
                val: MILLISECONDS_PER_DAY * (self.val / MILLISECONDS_PER_DAY),
            })
        } else if self.val % MILLISECONDS_PER_DAY == 0 {
            Some(self.clone())
        } else {
            Some(Self {
                val: ((self.val / MILLISECONDS_PER_DAY) - 1) * MILLISECONDS_PER_DAY,
            })
        }
    }

    pub fn to_time(&self) -> Option<Datetime> {
        if self.val >= 0 {
            Some(Self {
                val: self.val % MILLISECONDS_PER_DAY,
            })
        } else {
            let rem = self.val % MILLISECONDS_PER_DAY;
            if rem == 0 {
                Some(Self { val: rem })
            } else {
                Some(Self {
                    val: rem + MILLISECONDS_PER_DAY,
                })
            }
        }
    }
}

impl Default for Datetime {
    fn default() -> Self {
        Self { val: 0 }
    }
}

/// A duration value is measured in milliseconds and constructed from a duration string.
/// A duration string is a concatenated sequence of quantity-unit pairs where the quantity
/// is a natural number and unit is one of the following:
///   - `d` (for days)
///   - `h` (for hours)
///   - `m` (for minutes)
///   - `s` (for seconds)
///   - `ms` (for milliseconds)
///
/// Duration strings are required to be ordered from largest unit to smallest
/// unit, and contain one quantity per unit. Units with zero quantity may be
/// omitted.
///
/// A duration may be negative. Negative duration strings must begin with `-`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration {
    val: i64,
}

impl Duration {
    pub fn to_milliseconds(&self) -> i64 {
        self.val
    }

    pub fn to_seconds(&self) -> i64 {
        self.val / MILLISECONDS_PER_SECOND
    }

    pub fn to_minutes(&self) -> i64 {
        self.to_seconds() / 60
    }

    pub fn to_hours(&self) -> i64 {
        self.to_minutes() / 60
    }

    pub fn to_days(&self) -> i64 {
        self.to_hours() / 24
    }
}

impl Default for Duration {
    fn default() -> Self {
        Self { val: 0 }
    }
}
