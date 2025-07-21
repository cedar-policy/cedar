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

use super::{
    bitvec::BitVec,
    ext::Ext,
    extension_types::ipaddr::{
        IPNet, LOOP_BACK_CIDR_V4, LOOP_BACK_CIDR_V6, MULTICAST_CIDR_V4, MULTICAST_CIDR_V6,
    },
    factory::{
        and, bvadd, bvlshr, bvmul, bvsaddo, bvsdiv, bvshl, bvsle, bvslt, bvsmulo, bvsrem, bvssubo,
        bvsub, bvule, eq, ext_datetime_of_bitvec, ext_datetime_val, ext_decimal_val,
        ext_duration_of_bitvec, ext_duration_val, ext_ipaddr_addr_v4, ext_ipaddr_addr_v6,
        ext_ipaddr_is_v4, ext_ipaddr_prefix_v4, ext_ipaddr_prefix_v6, if_false, is_none, ite, not,
        option_get, or, some_of, zero_extend,
    },
    term::{Term, TermPrim},
    type_abbrevs::Nat,
};

pub fn less_than(t1: Term, t2: Term) -> Term {
    bvslt(ext_decimal_val(t1), ext_decimal_val(t2))
}

pub fn less_than_or_equal(t1: Term, t2: Term) -> Term {
    bvsle(ext_decimal_val(t1), ext_decimal_val(t2))
}

pub fn greater_than(t1: Term, t2: Term) -> Term {
    less_than(t2, t1)
}

pub fn greater_than_or_equal(t1: Term, t2: Term) -> Term {
    less_than_or_equal(t2, t1)
}

pub fn is_ipv4(t: Term) -> Term {
    ext_ipaddr_is_v4(t)
}

pub fn is_ipv6(t: Term) -> Term {
    not(is_ipv4(t))
}

pub fn subnet_width(w: Nat, prefix: Term) -> Term {
    let n = 2_usize.pow(w as u32);
    ite(
        is_none(prefix.clone()),
        0.into(),
        bvsub(
            BitVec {
                width: n,
                v: n as i128,
            }
            .into(),
            zero_extend(n - w, option_get(prefix)),
        ),
    )
}

pub fn range(w: Nat, ip_addr: Term, prefix: Term) -> (Term, Term) {
    let width = subnet_width(w, prefix);
    let lo = bvshl(bvlshr(ip_addr, width.clone()), width.clone());
    let hi = bvsub(bvadd(lo.clone(), bvshl(1.into(), width)), 1.into());
    (lo, hi)
}

pub fn range_v4(t: Term) -> (Term, Term) {
    range(5, ext_ipaddr_addr_v4(t.clone()), ext_ipaddr_prefix_v4(t))
}

pub fn range_v6(t: Term) -> (Term, Term) {
    range(7, ext_ipaddr_addr_v6(t.clone()), ext_ipaddr_prefix_v6(t))
}

pub fn in_range(range: impl Fn(Term) -> (Term, Term), t1: Term, t2: Term) -> Term {
    let (lo1, hi1) = range(t1);
    let (lo2, hi2) = range(t2);
    and(bvule(hi1, hi2), bvule(lo2, lo1))
}

pub fn in_range_v(
    is_ip: impl Fn(Term) -> Term,
    range: impl Fn(Term) -> (Term, Term),
    t1: Term,
    t2: Term,
) -> Term {
    and(
        and(is_ip(t1.clone()), is_ip(t2.clone())),
        in_range(range, t1, t2),
    )
}

pub fn is_in_range(t1: Term, t2: Term) -> Term {
    or(
        in_range_v(is_ipv4, range_v4, t1.clone(), t2.clone()),
        in_range_v(is_ipv6, range_v6, t1, t2),
    )
}

pub fn ip_term(ip: IPNet) -> Term {
    Term::Prim(TermPrim::Ext(Ext::Ipaddr { ip }))
}

pub fn in_range_lit(t: Term, cidr4: IPNet, cidr6: IPNet) -> Term {
    ite(
        is_ipv4(t.clone()),
        in_range(range_v4, t.clone(), ip_term(cidr4)),
        in_range(range_v6, t, ip_term(cidr6)),
    )
}

pub fn is_loopback(t: Term) -> Term {
    in_range_lit(t, LOOP_BACK_CIDR_V4, LOOP_BACK_CIDR_V6)
}

pub fn is_multicast(t: Term) -> Term {
    in_range_lit(t, MULTICAST_CIDR_V4, MULTICAST_CIDR_V6)
}

pub fn to_milliseconds(t: Term) -> Term {
    ext_duration_val(t)
}

pub fn to_seconds(t: Term) -> Term {
    bvsdiv(to_milliseconds(t), 1000.into())
}

pub fn to_minutes(t: Term) -> Term {
    bvsdiv(to_seconds(t), 60.into())
}

pub fn to_hours(t: Term) -> Term {
    bvsdiv(to_minutes(t), 60.into())
}

pub fn to_days(t: Term) -> Term {
    bvsdiv(to_hours(t), 24.into())
}

pub fn offset(dt: Term, dur: Term) -> Term {
    let dt_val = ext_datetime_val(dt);
    let dur_val = ext_duration_val(dur);
    if_false(
        bvsaddo(dt_val.clone(), dur_val.clone()),
        ext_datetime_of_bitvec(bvadd(dt_val, dur_val)),
    )
}

pub fn duration_since(dt1: Term, dt2: Term) -> Term {
    let dt1_val = ext_datetime_val(dt1);
    let dt2_val = ext_datetime_val(dt2);
    if_false(
        bvssubo(dt1_val.clone(), dt2_val.clone()),
        ext_duration_of_bitvec(bvsub(dt1_val, dt2_val)),
    )
}

pub fn to_date(dt: Term) -> Term {
    let zero = Term::Prim(TermPrim::Bitvec(BitVec { width: 64, v: 0 }));
    let one = Term::Prim(TermPrim::Bitvec(BitVec { width: 64, v: 1 }));
    let ms_per_day = Term::Prim(TermPrim::Bitvec(BitVec {
        width: 64,
        v: 86400000,
    }));
    let dt_val = ext_datetime_val(dt);
    ite(
        bvsle(zero.clone(), dt_val.clone()),
        some_of(ext_datetime_of_bitvec(bvmul(
            ms_per_day.clone(),
            bvsdiv(dt_val.clone(), ms_per_day.clone()),
        ))),
        ite(
            eq(bvsrem(dt_val.clone(), ms_per_day.clone()), zero),
            some_of(dt_val.clone()),
            if_false(
                bvsmulo(
                    bvsub(bvsdiv(dt_val.clone(), ms_per_day.clone()), one.clone()),
                    ms_per_day.clone(),
                ),
                ext_datetime_of_bitvec(bvmul(
                    bvsub(bvsdiv(dt_val, ms_per_day.clone()), one),
                    ms_per_day,
                )),
            ),
        ),
    )
}

pub fn to_time(dt: Term) -> Term {
    let zero = Term::Prim(TermPrim::Bitvec(BitVec { width: 64, v: 0 }));
    let ms_per_day = Term::Prim(TermPrim::Bitvec(BitVec {
        width: 64,
        v: 86400000,
    }));
    let dt_val = ext_datetime_val(dt);
    ext_duration_of_bitvec(ite(
        bvsle(zero.clone(), dt_val.clone()),
        bvsrem(dt_val.clone(), ms_per_day.clone()),
        ite(
            eq(bvsrem(dt_val.clone(), ms_per_day.clone()), zero.clone()),
            zero,
            bvadd(bvsrem(dt_val, ms_per_day.clone()), ms_per_day),
        ),
    ))
}
