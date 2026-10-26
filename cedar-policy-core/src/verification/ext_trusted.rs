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

//! TRUSTED: the assumptions of the proofs about the extension functions
//! (`extensions/{decimal,ipaddr,datetime}.rs`), justified in
//! `cedar-rust-model/TRUSTED.md`.
//!
//! 1. Extension values: `ext_of` models the `dyn InternalExtensionValue` that
//!    Verus cannot see into.
//! 2. Regexes, used through small `external_body` helpers (`decimal_parts`, ...).
//!    Each is anchored, so its captures are determined by the input; the model's
//!    matchers transcribe them.
//! 3. The standard library (`FromStr`, `std::net`, integer operations).
//! 4. `chrono`, through `nd_days`, `nt_ms`, `ndt_ms` and `td_ms`.

#![allow(unused_imports)]

use vstd::prelude::*;

use super::abs::seq_to_list;
use super::model as m;
use super::model::ext as mext;
use crate::ast::*;
use chrono::{NaiveDate, NaiveDateTime, NaiveTime, TimeDelta};

verus! {

// ---------------------------------------------------------------------------
// 1. Extension values
// ---------------------------------------------------------------------------

pub uninterp spec fn ext_of(ev: RepresentableExtensionValue) -> mext::Ext;

/// Production only builds IP networks with `IPAddr::from_str`, which bounds
/// the prefix by the address width.
pub broadcast axiom fn axiom_ext_of_wf(ev: RepresentableExtensionValue)
    ensures
        #[trigger] mext::ext_wf(&ext_of(ev)),
;

/// The type of an extension value: decimal, ipaddr, datetime or duration
pub open spec fn ext_kind(e: mext::Ext) -> int {
    match e {
        mext::Ext::Decimal(_) => 0,
        mext::Ext::IPAddr(_) => 1,
        mext::Ext::Datetime(_) => 2,
        mext::Ext::Duration(_) => 3,
    }
}

/// The type name of an extension value (`RepresentableExtensionValue::typename`)
pub uninterp spec fn ext_typename(e: mext::Ext) -> Name;

/// The type names of the four extension types are distinct (`decimal`,
/// `ipaddr`, `datetime`, `duration`).
pub broadcast axiom fn axiom_ext_typename(a: mext::Ext, b: mext::Ext)
    ensures
        #![trigger ext_typename(a), ext_typename(b)]
        (super::abs::abs_name(ext_typename(a)) == super::abs::abs_name(ext_typename(b))) == (ext_kind(a) == ext_kind(b)),
;

/// `x < y` (`is_less`) or `x <= y` on two `datetime`s or two `duration`s, as
/// their derived `Ord` (on the `i64`)
pub open spec fn ext_cmp(is_less: bool, a: mext::Ext, b: mext::Ext) -> bool {
    match (a, b) {
        (mext::Ext::Datetime(x), mext::Ext::Datetime(y)) => if is_less { x < y } else { x <= y },
        (mext::Ext::Duration(x), mext::Ext::Duration(y)) => if is_less { x < y } else { x <= y },
        _ => false,
    }
}


// ---------------------------------------------------------------------------
// 2. Regular expressions
// ---------------------------------------------------------------------------

/// `seq_to_list` of an optional string
pub open spec fn opt_str_list(o: Option<&str>) -> Option<m::value::Str> {
    match o {
        Some(s) => Some(seq_to_list(s@)),
        None => None,
    }
}

/// Unicode decimal digits (the class `\d` of the `regex` crate)
pub uninterp spec fn is_unicode_digit(c: char) -> bool;

/// The ASCII digits are Unicode decimal digits; `.` and `-` are not.
pub broadcast axiom fn axiom_unicode_digit(c: char)
    ensures
        #[trigger] is_unicode_digit(c) ==> c != '.' && c != '-' && c != '+',
        ('0' <= c && c <= '9') ==> is_unicode_digit(c),
;

/// `\d+`
pub open spec fn unicode_digits(s: Seq<char>) -> bool {
    s.len() > 0 && forall|i: int| 0 <= i < s.len() ==> is_unicode_digit(#[trigger] s[i])
}

/// `-?\d+`
pub open spec fn signed_unicode_digits(s: Seq<char>) -> bool {
    unicode_digits(s) || (s.len() > 0 && s[0] == '-' && unicode_digits(s.drop_first()))
}

/// `DECIMAL_REGEX` (`^(-?\d+)\.(\d+)$`) and its captures 1 and 2. Neither
/// capture contains a `.`, so they are determined; `decimal_split` is the
/// ASCII-digit restriction.
pub open spec fn decimal_regex_spec(s: &str, r: Option<(&str, &str)>) -> bool {
    &&& r matches Some((l, rr)) ==> s@ == l@ + seq!['.'] + rr@ && signed_unicode_digits(l@)
        && unicode_digits(rr@)
    &&& r is None ==> mext::decimal_split(&seq_to_list(s@)) is None
    &&& mext::decimal_split(&seq_to_list(s@)) matches Some((l, rr)) ==>
        r matches Some((l2, rr2)) && seq_to_list(l2@) == l && seq_to_list(rr2@) == rr
}

/// `DURATION_PATTERN`
/// (`^-?(([0-9]+)d)?(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?$`)
/// and its captures 2, 4, 6, 8 and 10. Decompositions are unique, so these
/// are those of the greedy `duration_regex`.
pub open spec fn duration_regex_spec(s: &str, r: Option<[Option<&str>; 5]>) -> bool {
    match (r, mext::duration_regex(&seq_to_list(s@))) {
        (Some(a), Some(p)) => opt_str_list(a@[0]) == p.d && opt_str_list(a@[1]) == p.h
            && opt_str_list(a@[2]) == p.m && opt_str_list(a@[3]) == p.s
            && opt_str_list(a@[4]) == p.ms,
        (None, None) => true,
        _ => false,
    }
}

/// `DATE_PATTERN` (`^([0-9]{4})-([0-9]{2})-([0-9]{2})`): the year, month,
/// day and the rest of the string are those of the model's `match_date`.
pub open spec fn date_regex_spec(s: &str, r: Option<(&str, [&str; 3], &str)>) -> bool {
    match (r, mext::match_date(&seq_to_list(s@))) {
        (Some((_, a, rest)), Some((y, mo, d, rest2))) => seq_to_list(a@[0]@) == y
            && seq_to_list(a@[1]@) == mo && seq_to_list(a@[2]@) == d
            && seq_to_list(rest@) == rest2,
        (None, None) => true,
        _ => false,
    }
}

/// `HMS_PATTERN` (`^T([0-9]{2}):([0-9]{2}):([0-9]{2})`): as the model's
/// `match_hms`
pub open spec fn hms_regex_spec(s: &str, r: Option<(&str, [&str; 3], &str)>) -> bool {
    match (r, mext::match_hms(&seq_to_list(s@))) {
        (Some((_, a, rest)), Some((h, mi, sec, rest2))) => seq_to_list(a@[0]@) == h
            && seq_to_list(a@[1]@) == mi && seq_to_list(a@[2]@) == sec
            && seq_to_list(rest@) == rest2,
        (None, None) => true,
        _ => false,
    }
}

/// `MS_AND_OFFSET_PATTERN` (`^(\.([0-9]{3}))?(Z|((\+|-)([0-9]{2})([0-9]{2})))$`)
/// and its captures 2, 5 (`+`?), 6 and 7: as the model's `match_ms_offset`
pub open spec fn ms_offset_regex_spec(
    s: &str,
    r: Option<(Option<&str>, Option<(bool, &str, &str)>)>,
) -> bool {
    match (r, mext::match_ms_offset(&seq_to_list(s@))) {
        (Some((ms, off)), Some((ms2, off2))) => opt_str_list(ms) == ms2 && match (off, off2) {
            (Some((pos, hh, mm)), Some((pos2, hh2, mm2))) => pos == pos2
                && seq_to_list(hh@) == hh2 && seq_to_list(mm@) == mm2,
            (None, None) => true,
            _ => false,
        },
        (None, None) => true,
        _ => false,
    }
}

/// A string of 1 to 4 ASCII digits (a capture of the datetime regexes)
pub open spec fn small_digits(s: Seq<char>) -> bool {
    0 < s.len() <= 4 && forall|i: int| 0 <= i < s.len() ==> '0' <= #[trigger] s[i] && s[i] <= '9'
}

// ---------------------------------------------------------------------------
// 3. The standard library
// ---------------------------------------------------------------------------

/// A string fits in memory: its UTF-8 encoding is at most `isize::MAX` bytes
/// long (a guarantee of Rust's `str`).
pub axiom fn axiom_str_len_bound(s: &str)
    ensures
        vstd::utf8::encode_utf8(s@).len() <= isize::MAX,
;

/// `s.split_once(c)`: the parts before and after the first `c`
pub open spec fn split_once_spec(s: &str, c: char, r: Option<(&str, &str)>) -> bool {
    match r {
        Some((a, b)) => s@ == a@ + seq![c] + b@ && !a@.contains(c),
        None => !s@.contains(c),
    }
}

/// `s.starts_with(c)`
pub open spec fn starts_with_spec(s: &str, c: char) -> bool {
    s@.len() > 0 && s@[0] == c
}

/// `FromStr` for `i64`: an optional sign and one or more ASCII digits, in
/// range (the model's `parse_i64`)
pub assume_specification[ <i64 as core::str::FromStr>::from_str ](s: &str) -> (r: Result<i64, core::num::ParseIntError>)
    ensures
        match r {
            Ok(n) => mext::parse_i64(&seq_to_list(s@)) == Some(n),
            Err(_) => mext::parse_i64(&seq_to_list(s@)) is None,
        },
;

/// `FromStr` for `u64`: an optional `+` and one or more ASCII digits, in range
/// (the model's `parse_u64`)
pub assume_specification[ <u64 as core::str::FromStr>::from_str ](s: &str) -> (r: Result<u64, core::num::ParseIntError>)
    ensures
        match r {
            Ok(n) => mext::parse_u64(&seq_to_list(s@)) == Some(n),
            Err(_) => mext::parse_u64(&seq_to_list(s@)) is None,
        },
;

/// `FromStr` for `u8` (the model's `parse_u8`)
pub assume_specification[ <u8 as core::str::FromStr>::from_str ](s: &str) -> (r: Result<u8, core::num::ParseIntError>)
    ensures
        match r {
            Ok(n) => mext::parse_u8(&seq_to_list(s@)) == Some(n),
            Err(_) => mext::parse_u8(&seq_to_list(s@)) is None,
        },
;

/// `FromStr` for `u32`, on 1 to 4 ASCII digits
pub assume_specification[ <u32 as core::str::FromStr>::from_str ](s: &str) -> (r: Result<u32, core::num::ParseIntError>)
    ensures
        small_digits(s@) ==> (r matches Ok(n) && n as i64 == mext::small_nat(&seq_to_list(s@))),
;

/// `FromStr` for `i32`, on 1 to 4 ASCII digits
pub assume_specification[ <i32 as core::str::FromStr>::from_str ](s: &str) -> (r: Result<i32, core::num::ParseIntError>)
    ensures
        small_digits(s@) ==> (r matches Ok(n) && n as i64 == mext::small_nat(&seq_to_list(s@))),
;

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExParseIntError(core::num::ParseIntError);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExAddrParseError(std::net::AddrParseError);

#[verifier::external_type_specification]
pub struct ExIpAddr(std::net::IpAddr);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExIpv4Addr(std::net::Ipv4Addr);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExIpv6Addr(std::net::Ipv6Addr);

/// The 32 bits of an IPv4 address (`u32::from`)
pub uninterp spec fn v4_bits(a: std::net::Ipv4Addr) -> u32;

/// The 128 bits of an IPv6 address (`u128::from`)
pub uninterp spec fn v6_bits(a: std::net::Ipv6Addr) -> u128;

pub assume_specification[ <u32 as core::convert::From<std::net::Ipv4Addr>>::from ](a: std::net::Ipv4Addr) -> (r: u32)
    ensures
        r == v4_bits(a),
;

pub assume_specification[ <u128 as core::convert::From<std::net::Ipv6Addr>>::from ](a: std::net::Ipv6Addr) -> (r: u128)
    ensures
        r == v6_bits(a),
;

pub assume_specification[ std::net::IpAddr::is_ipv4 ](a: &std::net::IpAddr) -> (r: bool)
    ensures
        r == (*a is V4),
;

pub assume_specification[ std::net::IpAddr::is_ipv6 ](a: &std::net::IpAddr) -> (r: bool)
    ensures
        r == (*a is V6),
;

/// `Ipv4Addr::is_loopback` is `octets()[0] == 127`, and `Ipv6Addr::is_loopback`
/// is `*self == Ipv6Addr::LOCALHOST` (`::1`).
pub assume_specification[ std::net::IpAddr::is_loopback ](a: &std::net::IpAddr) -> (r: bool)
    ensures
        r == match *a {
            std::net::IpAddr::V4(x) => (v4_bits(x) >> 24u32) == 127,
            std::net::IpAddr::V6(x) => v6_bits(x) == 1,
        },
;

/// `Ipv4Addr::is_multicast` is `224 <= octets()[0] <= 239` (the top four bits
/// are `1110`), and `Ipv6Addr::is_multicast` is
/// `(segments()[0] & 0xff00) == 0xff00` (the top byte is `0xff`).
pub assume_specification[ std::net::IpAddr::is_multicast ](a: &std::net::IpAddr) -> (r: bool)
    ensures
        r == match *a {
            std::net::IpAddr::V4(x) => (v4_bits(x) >> 28u32) == 14,
            std::net::IpAddr::V6(x) => (v6_bits(x) >> 120u32) == 255,
        },
;

/// `IpAddr::from_str` is the model's `parse_ip_addr` on strings without both
/// two `:` and two `.` (production rejects those first), which excludes
/// IPv6 with an embedded IPv4 address.
pub assume_specification[ <std::net::IpAddr as core::str::FromStr>::from_str ](s: &str) -> (r: Result<std::net::IpAddr, std::net::AddrParseError>)
    ensures
        !(mext::has_two(&seq_to_list(s@), ':') && mext::has_two(&seq_to_list(s@), '.')) ==>
            match r {
                Ok(a) => mext::parse_ip_addr(&seq_to_list(s@)) == Some(crate::extensions::ipaddr::abs_addr(a)),
                Err(_) => mext::parse_ip_addr(&seq_to_list(s@)) is None,
            },
;

pub assume_specification[ i64::is_negative ](x: i64) -> (r: bool)
    ensures
        r == (x < 0),
;

pub assume_specification[ i64::checked_pow ](x: i64, e: u32) -> (r: Option<i64>)
    ensures
        match r {
            Some(z) => z as int == vstd::arithmetic::power::pow(x as int, e as nat),
            None => !(i64::MIN <= vstd::arithmetic::power::pow(x as int, e as nat) <= i64::MAX),
        },
;

pub assume_specification[ u32::checked_shl ](x: u32, n: u32) -> (r: Option<u32>)
    ensures
        r == if n < 32 { Some(x << n) } else { None },
;

pub assume_specification[ u32::checked_shr ](x: u32, n: u32) -> (r: Option<u32>)
    ensures
        r == if n < 32 { Some(x >> n) } else { None },
;

pub assume_specification[ u128::checked_shl ](x: u128, n: u32) -> (r: Option<u128>)
    ensures
        r == if n < 128 { Some(x << n) } else { None },
;

pub assume_specification[ u128::checked_shr ](x: u128, n: u32) -> (r: Option<u128>)
    ensures
        r == if n < 128 { Some(x >> n) } else { None },
;

pub assume_specification[ char::is_ascii_digit ](c: &char) -> (r: bool)
    ensures
        r == ('0' <= *c && *c <= '9'),
;

// ---------------------------------------------------------------------------
// 4. chrono
// ---------------------------------------------------------------------------

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExNaiveDate(NaiveDate);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExNaiveTime(NaiveTime);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExNaiveDateTime(NaiveDateTime);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExTimeDelta(TimeDelta);

/// The number of days from 1970-01-01 to a date
pub uninterp spec fn nd_days(d: NaiveDate) -> int;

/// The number of milliseconds since midnight of a time (without leap seconds)
pub uninterp spec fn nt_ms(t: NaiveTime) -> int;

/// The number of milliseconds since the Unix epoch of a date and time, taken
/// as UTC (the definition of `DateTime::from`)
pub uninterp spec fn ndt_ms(t: NaiveDateTime) -> int;

/// The length of a duration, in milliseconds
pub uninterp spec fn td_ms(t: TimeDelta) -> int;

/// `NaiveDate::from_ymd_opt` (proleptic Gregorian), for years of four digits
pub assume_specification[ NaiveDate::from_ymd_opt ](year: i32, month: u32, day: u32) -> (r: Option<NaiveDate>)
    requires
        0 <= year <= 9999,
        month <= 9999,
        day <= 9999,
    ensures
        r is Some == mext::valid_date(year as i64, month as i64, day as i64),
        r matches Some(d) ==> nd_days(d) == mext::days_from_civil(year as i64, month as i64, day as i64) as int,
;

pub assume_specification[ NaiveTime::from_hms_opt ](hour: u32, min: u32, sec: u32) -> (r: Option<NaiveTime>)
    ensures
        r is Some == (hour < 24 && min < 60 && sec < 60),
        r matches Some(t) ==> nt_ms(t) == (hour * 3600 + min * 60 + sec) * 1000,
;

/// `NaiveTime::from_hms_milli_opt`, without leap seconds (`milli < 1000`)
pub assume_specification[ NaiveTime::from_hms_milli_opt ](hour: u32, min: u32, sec: u32, milli: u32) -> (r: Option<NaiveTime>)
    requires
        milli < 1000,
    ensures
        r is Some == (hour < 24 && min < 60 && sec < 60),
        r matches Some(t) ==> nt_ms(t) == (hour * 3600 + min * 60 + sec) * 1000 + milli,
;

pub assume_specification[ NaiveDateTime::new ](date: NaiveDate, time: NaiveTime) -> (r: NaiveDateTime)
    ensures
        ndt_ms(r) == nd_days(date) * 86_400_000 + nt_ms(time),
;

/// `TimeDelta::new(secs, 0)`, for durations of less than a day
pub assume_specification[ TimeDelta::new ](secs: i64, nanos: u32) -> (r: Option<TimeDelta>)
    requires
        -86_400 < secs < 86_400,
        nanos == 0,
    ensures
        r matches Some(d) && td_ms(d) == secs * 1000,
;

pub assume_specification[ <TimeDelta as core::default::Default>::default ]() -> (r: TimeDelta)
    ensures
        td_ms(r) == 0,
;

pub broadcast group group_ext_trusted {
    axiom_ext_of_wf,
    axiom_unicode_digit,
}

// ---------------------------------------------------------------------------
// The extensions of the evaluator
// ---------------------------------------------------------------------------

/// All the extensions are active.
pub uninterp spec fn extensions_all(e: crate::extensions::Extensions) -> bool;

pub assume_specification[ crate::extensions::Extensions::all_available ]() -> (r: &'static crate::extensions::Extensions<'static>)
    ensures
        extensions_all(*r),
;

} // verus!
