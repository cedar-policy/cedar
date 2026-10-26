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

//! String lemmas for the extension parser proofs. Strings are `Seq<char>` in
//! production and `seq_to_list` of it in the model.

#![allow(unused_imports)]

use vstd::prelude::*;
use vstd::utf8::*;

use super::abs::{list_view, seq_to_list};
use super::model as m;
use super::model::ext as mext;
use super::ext_trusted as et;

verus! {

/// `seq_to_list` of a non-empty sequence
pub proof fn lemma_stl_cons<T>(s: Seq<T>)
    requires
        s.len() > 0,
    ensures
        seq_to_list(s) == m::value::List::Cons(s[0], Box::new(seq_to_list(s.drop_first()))),
{
    assert(s.subrange(1, s.len() as int) =~= s.drop_first());
}

pub proof fn lemma_lv_stl<T>(s: Seq<T>)
    ensures
        list_view(seq_to_list(s)) == s,
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_lv_stl(s.subrange(1, s.len() as int));
        assert(s =~= seq![s[0]] + s.subrange(1, s.len() as int));
    }
}

/// `seq_to_list` is injective
pub proof fn lemma_stl_injective<T>(a: Seq<T>, b: Seq<T>)
    requires
        seq_to_list(a) == seq_to_list(b),
    ensures
        a == b,
{
    lemma_lv_stl(a);
    lemma_lv_stl(b);
}

/// An ASCII digit
pub open spec fn is_ascii_digit(c: char) -> bool {
    '0' <= c && c <= '9'
}

pub proof fn lemma_is_digit(c: char)
    ensures
        mext::is_digit(c) == is_ascii_digit(c),
        mext::digit_val(c) matches Some(d) ==> d == (c as u32) - 48,
{
}

/// `all_digits` is "every character is an ASCII digit"
pub proof fn lemma_all_digits(s: Seq<char>)
    ensures
        mext::all_digits(&seq_to_list(s)) == (forall|i: int| 0 <= i < s.len() ==> is_ascii_digit(#[trigger] s[i])),
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_stl_cons(s);
        lemma_all_digits(s.drop_first());
        lemma_is_digit(s[0]);
        if mext::all_digits(&seq_to_list(s)) {
            assert forall|i: int| 0 <= i < s.len() implies is_ascii_digit(#[trigger] s[i]) by {
                if i > 0 {
                    assert(s.drop_first()[i - 1] == s[i]);
                }
            }
        }
        if forall|i: int| 0 <= i < s.len() ==> is_ascii_digit(#[trigger] s[i]) {
            assert(is_ascii_digit(s[0]));
            assert forall|i: int| 0 <= i < s.drop_first().len() implies is_ascii_digit(#[trigger] s.drop_first()[i]) by {
                assert(s.drop_first()[i] == s[i + 1]);
            }
        }
    }
}

pub proof fn lemma_is_empty(s: Seq<char>)
    ensures
        mext::is_empty(&seq_to_list(s)) == (s.len() == 0),
{
    if s.len() > 0 {
        lemma_stl_cons(s);
    }
}

pub proof fn lemma_starts_with(s: Seq<char>, c: char)
    ensures
        mext::starts_with(&seq_to_list(s), c) == (s.len() > 0 && s[0] == c),
{
    if s.len() > 0 {
        lemma_stl_cons(s);
    }
}

pub proof fn lemma_is_char(s: Seq<char>, c: char)
    ensures
        mext::is_char(&seq_to_list(s), c) == (s =~= seq![c]),
{
    if s.len() > 0 {
        lemma_stl_cons(s);
        lemma_is_empty(s.drop_first());
        if s =~= seq![c] {
            assert(s.drop_first().len() == 0);
        }
        if s[0] == c && s.drop_first().len() == 0 {
            assert(s =~= seq![c]);
        }
    }
}

/// The UTF-8 width of a character
pub proof fn lemma_utf8_width(c: char)
    ensures
        encode_scalar(c as u32).len() == mext::utf8_width(c) as int,
{
    char_is_scalar(c);
}

/// `utf8_len_le` is a bound on the UTF-8 length (`str::len`)
pub proof fn lemma_utf8_len_le(s: Seq<char>, n: u32)
    ensures
        mext::utf8_len_le(&seq_to_list(s), n) == (encode_utf8(s).len() <= n),
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_stl_cons(s);
        lemma_utf8_width(s[0]);
        let w = mext::utf8_width(s[0]);
        if w <= n {
            lemma_utf8_len_le(s.drop_first(), (n - w) as u32);
        }
    }
}

/// The UTF-8 length of an ASCII string is its length
pub proof fn lemma_utf8_len_ascii(s: Seq<char>)
    requires
        forall|i: int| 0 <= i < s.len() ==> (#[trigger] s[i] as u32) < 128,
    ensures
        encode_utf8(s).len() == s.len(),
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_utf8_width(s[0]);
        assert forall|i: int| 0 <= i < s.drop_first().len() implies (#[trigger] s.drop_first()[i] as u32) < 128 by {
            assert(s.drop_first()[i] == s[i + 1]);
        }
        lemma_utf8_len_ascii(s.drop_first());
    }
}

pub proof fn lemma_has_one(s: Seq<char>, c: char)
    ensures
        mext::has_one(&seq_to_list(s), c) == s.contains(c),
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_stl_cons(s);
        lemma_has_one(s.drop_first(), c);
        if s.contains(c) && s[0] != c {
            let i = choose|i: int| 0 <= i < s.len() && s[i] == c;
            assert(s.drop_first()[i - 1] == c);
        }
        if s.drop_first().contains(c) {
            let i = choose|i: int| 0 <= i < s.drop_first().len() && s.drop_first()[i] == c;
            assert(s[i + 1] == c);
        }
    }
}

/// `has_two` of a prefix implies `has_two` of the whole
pub proof fn lemma_has_two_prefix(a: Seq<char>, b: Seq<char>, c: char)
    requires
        mext::has_two(&seq_to_list(a), c),
    ensures
        mext::has_two(&seq_to_list(a + b), c),
    decreases a.len(),
{
    if a.len() > 0 {
        lemma_stl_cons(a);
        lemma_stl_cons(a + b);
        assert((a + b).drop_first() =~= a.drop_first() + b);
        if a[0] == c {
            lemma_has_one(a.drop_first(), c);
            lemma_has_one(a.drop_first() + b, c);
            let i = choose|i: int| 0 <= i < a.drop_first().len() && a.drop_first()[i] == c;
            assert((a.drop_first() + b)[i] == c);
        } else {
            lemma_has_two_prefix(a.drop_first(), b, c);
        }
    }
}

/// Splitting at the first `c`
pub proof fn lemma_split_at_char(a: Seq<char>, b: Seq<char>, c: char)
    requires
        !a.contains(c),
    ensures
        mext::split_at_char(&seq_to_list(a + seq![c] + b), c) == Some((seq_to_list(a), seq_to_list(b))),
    decreases a.len(),
{
    let s = a + seq![c] + b;
    lemma_stl_cons(s);
    if a.len() == 0 {
        assert(s.drop_first() =~= b);
        super::model_lemmas::lemma_clone_str(seq_to_list(b));
    } else {
        assert(a[0] != c);
        assert(s.drop_first() =~= a.drop_first() + seq![c] + b);
        assert(!a.drop_first().contains(c)) by {
            if a.drop_first().contains(c) {
                let i = choose|i: int| 0 <= i < a.drop_first().len() && a.drop_first()[i] == c;
                assert(a[i + 1] == c);
            }
        }
        lemma_split_at_char(a.drop_first(), b, c);
        lemma_stl_cons(a);
    }
}

pub proof fn lemma_split_at_char_none(s: Seq<char>, c: char)
    requires
        !s.contains(c),
    ensures
        mext::split_at_char(&seq_to_list(s), c) is None,
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_stl_cons(s);
        assert(s[0] != c);
        assert(!s.drop_first().contains(c)) by {
            if s.drop_first().contains(c) {
                let i = choose|i: int| 0 <= i < s.drop_first().len() && s.drop_first()[i] == c;
                assert(s[i + 1] == c);
            }
        }
        lemma_split_at_char_none(s.drop_first(), c);
    }
}

// ---------------------------------------------------------------------------
// Integers
// ---------------------------------------------------------------------------

/// `digits_i64` only succeeds on ASCII digits
pub proof fn lemma_digits_i64_all(l: m::value::Str, neg: bool, acc: i64)
    requires
        mext::digits_i64(&l, neg, acc) is Some,
    ensures
        mext::all_digits(&l),
    decreases l,
{
    match l {
        m::value::List::Nil => {},
        m::value::List::Cons(c, rest) => {
            lemma_is_digit(c);
            match mext::digit_val(c) {
                None => {},
                Some(d) => match acc.checked_mul(10) {
                    None => {},
                    Some(a) => {
                        let next = if neg { a.checked_sub(d as i64) } else { a.checked_add(d as i64) };
                        if let Some(a2) = next {
                            lemma_digits_i64_all(*rest, neg, a2);
                        }
                    },
                },
            }
        },
    }
}

/// A string `i64::from_str` accepts and that does not start with a sign is
/// made of ASCII digits
pub proof fn lemma_parse_i64_digits(s: Seq<char>)
    requires
        mext::parse_i64(&seq_to_list(s)) is Some,
        s.len() > 0 ==> s[0] != '-' && s[0] != '+',
    ensures
        mext::is_digits(&seq_to_list(s)),
{
    if s.len() > 0 {
        lemma_stl_cons(s);
        lemma_digits_i64_all(seq_to_list(s), false, 0);
    }
}

/// A string `i64::from_str` accepts that starts with `-` is `-` and ASCII digits
pub proof fn lemma_parse_i64_signed_digits(s: Seq<char>)
    requires
        mext::parse_i64(&seq_to_list(s)) is Some,
        s.len() > 0 && s[0] == '-',
    ensures
        mext::is_digits(&seq_to_list(s.drop_first())),
{
    lemma_stl_cons(s);
    lemma_is_empty(s.drop_first());
    lemma_digits_i64_all(seq_to_list(s.drop_first()), true, 0);
}

// ---------------------------------------------------------------------------
// Decimals
// ---------------------------------------------------------------------------

/// `frac_scale` is `10^(4 - len)` for fractional parts of 1 to 4 digits
pub proof fn lemma_frac_scale(r: Seq<char>)
    ensures
        mext::frac_scale(&seq_to_list(r)) == if 1 <= r.len() <= 4 {
            Some(vstd::arithmetic::power::pow(10, (4 - r.len()) as nat) as i64)
        } else {
            None
        },
{
    reveal_with_fuel(vstd::arithmetic::power::pow, 5);
    if r.len() > 0 {
        let r1 = r.drop_first();
        lemma_stl_cons(r);
        if r1.len() > 0 {
            let r2 = r1.drop_first();
            lemma_stl_cons(r1);
            if r2.len() > 0 {
                let r3 = r2.drop_first();
                lemma_stl_cons(r2);
                if r3.len() > 0 {
                    let r4 = r3.drop_first();
                    lemma_stl_cons(r3);
                    if r4.len() > 0 {
                        lemma_stl_cons(r4);
                    }
                }
            }
        }
    }
}

/// The model's decimal regex on `l.r`
pub proof fn lemma_decimal_split(l: Seq<char>, r: Seq<char>)
    requires
        mext::is_signed_digits(&seq_to_list(l)),
        mext::is_digits(&seq_to_list(r)),
    ensures
        mext::decimal_split(&seq_to_list(l + seq!['.'] + r)) == Some((seq_to_list(l), seq_to_list(r))),
{
    assert(!l.contains('.')) by {
        if l.contains('.') {
            let i = choose|i: int| 0 <= i < l.len() && l[i] == '.';
            lemma_stl_cons(l);
            if l[0] == '-' {
                lemma_all_digits(l.drop_first());
                assert(l.drop_first()[i - 1] == '.');
            } else {
                lemma_all_digits(l);
            }
        }
    }
    lemma_split_at_char(l, r, '.');
}

/// ASCII digits are one byte each in UTF-8
pub proof fn lemma_digits_utf8(s: Seq<char>)
    requires
        mext::is_digits(&seq_to_list(s)),
    ensures
        encode_utf8(s).len() == s.len(),
        s.len() >= 1,
{
    lemma_is_empty(s);
    lemma_all_digits(s);
    assert forall|i: int| 0 <= i < s.len() implies (#[trigger] s[i] as u32) < 128 by {
        assert(is_ascii_digit(s[i]));
    }
    lemma_utf8_len_ascii(s);
}

/// `-?\d+` accepted by `i64::from_str` is `-?[0-9]+`
pub proof fn lemma_signed_unicode_parse_i64(s: Seq<char>)
    requires
        et::signed_unicode_digits(s),
        mext::parse_i64(&seq_to_list(s)) is Some,
    ensures
        mext::is_signed_digits(&seq_to_list(s)),
{
    broadcast use et::group_ext_trusted;
    lemma_stl_cons(s);
    if s[0] == '-' {
        lemma_parse_i64_signed_digits(s);
    } else {
        assert(et::is_unicode_digit(s[0]));
        lemma_parse_i64_digits(s);
    }
}

/// `DECIMAL_REGEX` captures agree with the model's `decimal_split`, which
/// succeeds when both parts parse as `i64`.
pub proof fn lemma_decimal_parts(s: &str, l: &str, r: &str)
    requires
        et::decimal_regex_spec(s, Some((l, r))),
    ensures
        mext::decimal_split(&seq_to_list(s@)) is Some ==> {
            &&& mext::decimal_split(&seq_to_list(s@)) == Some((seq_to_list(l@), seq_to_list(r@)))
            &&& encode_utf8(r@).len() == r@.len()
        },
        mext::parse_i64(&seq_to_list(l@)) is Some && mext::parse_i64(&seq_to_list(r@)) is Some
            ==> mext::decimal_split(&seq_to_list(s@)) is Some,
        mext::starts_with(&seq_to_list(l@), '-') == (l@.len() > 0 && l@[0] == '-'),
        mext::frac_scale(&seq_to_list(r@)) == if 1 <= r@.len() <= 4 {
            Some(vstd::arithmetic::power::pow(10, (4 - r@.len()) as nat) as i64)
        } else {
            None
        },
        r@.len() >= 1,
{
    broadcast use et::group_ext_trusted;
    lemma_starts_with(l@, '-');
    lemma_frac_scale(r@);
    if mext::decimal_split(&seq_to_list(s@)) is Some {
        let (_, rr) = mext::decimal_split(&seq_to_list(s@)).unwrap();
        assert(mext::is_digits(&rr));
        lemma_digits_utf8(r@);
    }
    if mext::parse_i64(&seq_to_list(l@)) is Some && mext::parse_i64(&seq_to_list(r@)) is Some {
        lemma_signed_unicode_parse_i64(l@);
        assert(et::signed_unicode_digits(r@));
        lemma_signed_unicode_parse_i64(r@);
        lemma_stl_cons(r@);
        assert(r@[0] != '-');
        lemma_decimal_split(l@, r@);
        assert(s@ == l@ + seq!['.'] + r@);
    }
}

// ---------------------------------------------------------------------------
// Datetimes
// ---------------------------------------------------------------------------

/// `n` ASCII digits
pub open spec fn fixed_digits(x: m::value::Str, n: nat) -> bool {
    &&& list_view(x).len() == n
    &&& forall|i: int| 0 <= i < n ==> is_ascii_digit(#[trigger] list_view(x)[i])
}

pub proof fn lemma_take_digits(l: m::value::Str, n: u32)
    ensures
        mext::take_digits(&l, n) matches Some((x, _)) ==> fixed_digits(x, n as nat),
    decreases l,
{
    if n > 0 {
        match l {
            m::value::List::Nil => {},
            m::value::List::Cons(c, rest) => {
                lemma_is_digit(c);
                lemma_take_digits(*rest, (n - 1) as u32);
                if let Some((x, _)) = mext::take_digits(&l, n) {
                    let (x1, _) = mext::take_digits(&*rest, (n - 1) as u32).unwrap();
                    assert(x == m::value::List::Cons(c, Box::new(x1)));
                    assert(list_view(x) == seq![c] + list_view(x1));
                    assert forall|i: int| 0 <= i < n implies is_ascii_digit(#[trigger] list_view(x)[i]) by {
                        if i > 0 {
                            assert(list_view(x)[i] == list_view(x1)[i - 1]);
                        }
                    }
                }
            },
        }
    }
}

/// A capture with the digits `x` is a string of 1 to 4 ASCII digits
pub proof fn lemma_small_digits(x: m::value::Str, n: nat, s: Seq<char>)
    requires
        fixed_digits(x, n),
        1 <= n <= 4,
        seq_to_list(s) == x,
    ensures
        et::small_digits(s),
{
    lemma_lv_stl(s);
}

pub proof fn lemma_match_date(l: m::value::Str)
    ensures
        mext::match_date(&l) matches Some((y, mo, d, _)) ==>
            fixed_digits(y, 4) && fixed_digits(mo, 2) && fixed_digits(d, 2),
{
    lemma_take_digits(l, 4);
    if let Some((_, r1)) = mext::take_digits(&l, 4) {
        if let Some(r2) = mext::take_char(&r1, '-') {
            lemma_take_digits(r2, 2);
            if let Some((_, r3)) = mext::take_digits(&r2, 2) {
                if let Some(r4) = mext::take_char(&r3, '-') {
                    lemma_take_digits(r4, 2);
                }
            }
        }
    }
}

pub proof fn lemma_match_hms(l: m::value::Str)
    ensures
        mext::match_hms(&l) matches Some((h, mi, sec, _)) ==>
            fixed_digits(h, 2) && fixed_digits(mi, 2) && fixed_digits(sec, 2),
{
    if let Some(r0) = mext::take_char(&l, 'T') {
        lemma_take_digits(r0, 2);
        if let Some((_, r1)) = mext::take_digits(&r0, 2) {
            if let Some(r2) = mext::take_char(&r1, ':') {
                lemma_take_digits(r2, 2);
                if let Some((_, r3)) = mext::take_digits(&r2, 2) {
                    if let Some(r4) = mext::take_char(&r3, ':') {
                        lemma_take_digits(r4, 2);
                    }
                }
            }
        }
    }
}

pub proof fn lemma_match_offset(l: m::value::Str)
    ensures
        mext::match_offset(&l) matches Some(Some((_, hh, mm))) ==>
            fixed_digits(hh, 2) && fixed_digits(mm, 2),
{
    if let m::value::List::Cons(_, rest) = l {
        lemma_take_digits(*rest, 2);
        if let Some((_, r1)) = mext::take_digits(&*rest, 2) {
            lemma_take_digits(r1, 2);
        }
    }
}

pub proof fn lemma_match_ms_offset(l: m::value::Str)
    ensures
        mext::match_ms_offset(&l) matches Some((ms, off)) ==> {
            &&& ms matches Some(ms) ==> fixed_digits(ms, 3)
            &&& off matches Some((_, hh, mm)) ==> fixed_digits(hh, 2) && fixed_digits(mm, 2)
        },
{
    lemma_match_offset(l);
    if let Some(r0) = mext::take_char(&l, '.') {
        lemma_take_digits(r0, 3);
        if let Some((_, r1)) = mext::take_digits(&r0, 3) {
            lemma_match_offset(r1);
        }
    }
}

/// The value of three digits is less than 1000
pub proof fn lemma_small_nat_3(x: m::value::Str)
    requires
        fixed_digits(x, 3),
    ensures
        0 <= mext::small_nat(&x) < 1000,
{
    match x {
        m::value::List::Cons(a, r1) => match *r1 {
            m::value::List::Cons(b, r2) => match *r2 {
                m::value::List::Cons(c, r3) => {
                    assert(list_view(*r2) == seq![c] + list_view(*r3));
                    assert(list_view(*r1) == seq![b] + list_view(*r2));
                    assert(list_view(x) == seq![a] + list_view(*r1));
                    assert(list_view(x) =~= seq![a, b, c] + list_view(*r3));
                    assert(is_ascii_digit(list_view(x)[0]));
                    assert(is_ascii_digit(list_view(x)[1]));
                    assert(is_ascii_digit(list_view(x)[2]));
                    lemma_is_digit(a);
                    lemma_is_digit(b);
                    lemma_is_digit(c);
                    assert(*r3 == m::value::List::<char>::Nil) by {
                        if let m::value::List::Cons(_, _) = *r3 {
                            assert(list_view(x).len() > 3);
                        }
                    }
                    let da = (a as u32 - 48) as u64;
                    let db = (b as u32 - 48) as u64;
                    let dc = (c as u32 - 48) as u64;
                    assert(mext::digits_u64(&x, 0) == mext::digits_u64(&*r1, da));
                    assert(mext::digits_u64(&*r1, da) == mext::digits_u64(&*r2, (da * 10 + db) as u64));
                    assert(mext::digits_u64(&*r2, (da * 10 + db) as u64)
                        == mext::digits_u64(&*r3, ((da * 10 + db) * 10 + dc) as u64));
                },
                m::value::List::Nil => {
                    assert(list_view(*r1) == seq![b] + list_view(*r2));
                    assert(list_view(x).len() == 2);
                },
            },
            m::value::List::Nil => {
                assert(list_view(x) == seq![a] + list_view(*r1));
                assert(list_view(x).len() == 1);
            },
        },
        m::value::List::Nil => {},
    }
}

} // verus!
