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

//! This file contains the symbolic encoding (factory functions) for extension
//! operators.
//!
//! The extension functions are total. If given well-formed and type-correct
//! arguments, an extension function will return a well-formed and type-correct
//! output. Otherwise, the output is an arbitrary term.
//!
//! This design lets us minimize the number of error paths in the overall
//! specification of symbolic compilation, which makes for nicer code and proofs, and
//! it more closely tracks the specification of the concrete evaluator.
//!
//! See `compiler.rs` to see how the symbolic compiler uses this API. See also
//! `factory.rs`.

use crate::symcc::{
    factory::{
        bvmul, bvsaddo, bvsmulo, bvsrem, bvssubo, eq, ext_datetime_of_bitvec, ext_datetime_val,
        ext_duration_of_bitvec, if_false, some_of,
    },
    type_abbrevs::{nat, Width},
};

use super::{
    bitvec::BitVec,
    ext::Ext,
    extension_types::ipaddr::{
        IPNet, LOOP_BACK_CIDR_V4, LOOP_BACK_CIDR_V6, MULTICAST_CIDR_V4, MULTICAST_CIDR_V6,
    },
    factory::{
        and, bvadd, bvlshr, bvsdiv, bvshl, bvsle, bvslt, bvsub, bvule, ext_decimal_val,
        ext_duration_val, ext_ipaddr_addr_v4, ext_ipaddr_addr_v6, ext_ipaddr_is_v4,
        ext_ipaddr_prefix_v4, ext_ipaddr_prefix_v6, is_none, ite, not, option_get, or, zero_extend,
    },
    term::{Term, TermPrim},
    term_type::TermTypeInner,
};
use hashconsing::{HConsign, HashConsign};

pub fn less_than(t1: Term, t2: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    bvslt(ext_decimal_val(t1, h), ext_decimal_val(t2, h), h)
}

pub fn less_than_or_equal(t1: Term, t2: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    bvsle(ext_decimal_val(t1, h), ext_decimal_val(t2, h), h)
}

pub fn greater_than(t1: Term, t2: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    less_than(t2, t1, h)
}

pub fn greater_than_or_equal(t1: Term, t2: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    less_than_or_equal(t2, t1, h)
}

pub fn is_ipv4(t: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    ext_ipaddr_is_v4(t, h)
}

pub fn is_ipv6(t: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    not(is_ipv4(t, h), h)
}

pub fn subnet_width(w: Width, prefix: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    let n = 2_u32.pow(w);
    ite(
        is_none(prefix.clone(), h),
        #[allow(
            clippy::unwrap_used,
            reason = "Cannot panic because bitwidth is guaranteed to be non-zero."
        )]
        BitVec::of_nat(n, nat(0)).unwrap().into(),
        bvsub(
            #[allow(
                clippy::unwrap_used,
                reason = "Cannot panic because bitwidth is guaranteed to be non-zero."
            )]
            BitVec::of_nat(n, nat(n)).unwrap().into(),
            zero_extend(n - w, option_get(prefix, h), h),
            h,
        ),
        h,
    )
}

pub fn range(
    w: Width,
    ip_addr: Term,
    prefix: Term,
    h: &mut HConsign<TermTypeInner>,
) -> (Term, Term) {
    let n = 2_u32.pow(w);
    let width = subnet_width(w, prefix, h);
    #[allow(
        clippy::unwrap_used,
        reason = "Cannot panic because bitwidth is guaranteed to be non-zero."
    )]
    let one: Term = BitVec::of_nat(n, nat(1)).unwrap().into();
    let lo = bvshl(bvlshr(ip_addr, width.clone(), h), width.clone(), h);
    let hi = bvsub(bvadd(lo.clone(), bvshl(one.clone(), width, h), h), one, h);
    (lo, hi)
}

pub fn range_v4(t: Term, h: &mut HConsign<TermTypeInner>) -> (Term, Term) {
    range(
        5,
        ext_ipaddr_addr_v4(t.clone(), h),
        ext_ipaddr_prefix_v4(t, h),
        h,
    )
}

pub fn range_v6(t: Term, h: &mut HConsign<TermTypeInner>) -> (Term, Term) {
    range(
        7,
        ext_ipaddr_addr_v6(t.clone(), h),
        ext_ipaddr_prefix_v6(t, h),
        h,
    )
}

pub fn in_range(
    range: impl Fn(Term, &mut HConsign<TermTypeInner>) -> (Term, Term),
    t1: Term,
    t2: Term,
    h: &mut HConsign<TermTypeInner>,
) -> Term {
    let (lo1, hi1) = range(t1, h);
    let (lo2, hi2) = range(t2, h);
    and(bvule(hi1, hi2, h), bvule(lo2, lo1, h), h)
}

pub fn in_range_v(
    is_ip: impl Fn(Term, &mut HConsign<TermTypeInner>) -> Term,
    range: impl Fn(Term, &mut HConsign<TermTypeInner>) -> (Term, Term),
    t1: Term,
    t2: Term,
    h: &mut HConsign<TermTypeInner>,
) -> Term {
    and(
        and(is_ip(t1.clone(), h), is_ip(t2.clone(), h), h),
        in_range(range, t1, t2, h),
        h,
    )
}

pub fn is_in_range(t1: Term, t2: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    or(
        in_range_v(is_ipv4, range_v4, t1.clone(), t2.clone(), h),
        in_range_v(is_ipv6, range_v6, t1, t2, h),
        h,
    )
}

pub fn ip_term(ip: IPNet) -> Term {
    Term::Prim(TermPrim::Ext(Ext::Ipaddr { ip }))
}

pub fn in_range_lit(t: Term, cidr4: IPNet, cidr6: IPNet, h: &mut HConsign<TermTypeInner>) -> Term {
    ite(
        is_ipv4(t.clone(), h),
        in_range(range_v4, t.clone(), ip_term(cidr4), h),
        in_range(range_v6, t, ip_term(cidr6), h),
        h,
    )
}

pub fn is_loopback(t: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    in_range_lit(t, LOOP_BACK_CIDR_V4.clone(), LOOP_BACK_CIDR_V6.clone(), h)
}

pub fn is_multicast(t: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    in_range_lit(t, MULTICAST_CIDR_V4.clone(), MULTICAST_CIDR_V6.clone(), h)
}

pub fn to_milliseconds(t: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    ext_duration_val(t, h)
}

pub fn to_seconds(t: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    bvsdiv(to_milliseconds(t, h), 1000.into(), h)
}

pub fn to_minutes(t: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    bvsdiv(to_seconds(t, h), 60.into(), h)
}

pub fn to_hours(t: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    bvsdiv(to_minutes(t, h), 60.into(), h)
}

pub fn to_days(t: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    bvsdiv(to_hours(t, h), 24.into(), h)
}

pub fn offset(dt: Term, dur: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    let dt_val = ext_datetime_val(dt, h);
    let dur_val = ext_duration_val(dur, h);
    if_false(
        bvsaddo(dt_val.clone(), dur_val.clone(), h),
        ext_datetime_of_bitvec(bvadd(dt_val, dur_val, h), h),
        h,
    )
}

pub fn duration_since(dt1: Term, dt2: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    let dt1_val = ext_datetime_val(dt1, h);
    let dt2_val = ext_datetime_val(dt2, h);
    if_false(
        bvssubo(dt1_val.clone(), dt2_val.clone(), h),
        ext_duration_of_bitvec(bvsub(dt1_val, dt2_val, h), h),
        h,
    )
}

pub fn to_date(dt: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    #[allow(
        clippy::unwrap_used,
        reason = "Cannot panic because bitwidth is guaranteed to be non-zero."
    )]
    let zero = Term::Prim(TermPrim::Bitvec(BitVec::of_u128(64, 0).unwrap()));
    #[allow(
        clippy::unwrap_used,
        reason = "Cannot panic because bitwidth is guaranteed to be non-zero."
    )]
    let one = Term::Prim(TermPrim::Bitvec(BitVec::of_u128(64, 1).unwrap()));
    #[allow(
        clippy::unwrap_used,
        reason = "Cannot panic because bitwidth is guaranteed to be non-zero."
    )]
    let ms_per_day = Term::Prim(TermPrim::Bitvec(BitVec::of_u128(64, 86400000).unwrap()));
    let dt_val = ext_datetime_val(dt.clone(), h);
    ite(
        bvsle(zero.clone(), dt_val.clone(), h),
        some_of(ext_datetime_of_bitvec(
            bvmul(
                ms_per_day.clone(),
                bvsdiv(dt_val.clone(), ms_per_day.clone(), h),
                h,
            ),
            h,
        )),
        ite(
            eq(bvsrem(dt_val.clone(), ms_per_day.clone(), h), zero, h),
            some_of(dt),
            if_false(
                bvsmulo(
                    bvsub(
                        bvsdiv(dt_val.clone(), ms_per_day.clone(), h),
                        one.clone(),
                        h,
                    ),
                    ms_per_day.clone(),
                    h,
                ),
                ext_datetime_of_bitvec(
                    bvmul(
                        bvsub(bvsdiv(dt_val, ms_per_day.clone(), h), one, h),
                        ms_per_day,
                        h,
                    ),
                    h,
                ),
                h,
            ),
            h,
        ),
        h,
    )
}

pub fn to_time(dt: Term, h: &mut HConsign<TermTypeInner>) -> Term {
    #[allow(
        clippy::unwrap_used,
        reason = "Cannot panic because bitwidth is guaranteed to be non-zero."
    )]
    let zero = Term::Prim(TermPrim::Bitvec(BitVec::of_u128(64, 0).unwrap()));
    #[allow(
        clippy::unwrap_used,
        reason = "Cannot panic because bitwidth is guaranteed to be non-zero."
    )]
    let ms_per_day = Term::Prim(TermPrim::Bitvec(BitVec::of_u128(64, 86400000).unwrap()));
    let dt_val = ext_datetime_val(dt, h);
    ext_duration_of_bitvec(
        ite(
            bvsle(zero.clone(), dt_val.clone(), h),
            bvsrem(dt_val.clone(), ms_per_day.clone(), h),
            ite(
                eq(
                    bvsrem(dt_val.clone(), ms_per_day.clone(), h),
                    zero.clone(),
                    h,
                ),
                zero,
                bvadd(bvsrem(dt_val, ms_per_day.clone(), h), ms_per_day, h),
                h,
            ),
            h,
        ),
        h,
    )
}
