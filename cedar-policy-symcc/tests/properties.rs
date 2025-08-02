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

//! This file contains some general properties about
//! the SMT encoding of various Cedar types in SymCC.

use cedar_policy::Validator;
use cedar_policy_symcc::{solver::LocalSolver, CedarSymCompiler};

use crate::utils::{assert_always_allows, assert_does_not_always_deny, Environments};
mod utils;

/// Encodes the property as a policy verification task
macro_rules! encode_prop {
    ($check:ident, $quant:ident, $schema_prelude:expr, $policy_prelude:expr, $effect:ident, $($var:ident : $typ:tt),* { $($prop:tt)+ }) => {
        let schema_src = format!(
            r#"{}entity A; action check appliesTo {{ principal: [A], resource: [A], context: {{ {}}} }};"#,
            $schema_prelude,
            concat!($(stringify!($var), ": ", stringify!($typ), ", "),*)
        );
        let prop_src = stringify!($($prop)+);
        let policy_src = format!("{}{}(principal, action, resource) when {{ {} }};",
            $policy_prelude,
            stringify!($effect),
            prop_src.replace('$', "context."));
        eprintln!("======================");
        eprintln!("checking the validity: {} {}, {}", stringify!($quant), stringify!($($var : $typ),*), stringify!($($prop)+));
        eprintln!("{}", schema_src);
        eprintln!("{}", policy_src);
        eprintln!("======================");
        let schema = utils::schema_from_cedarstr(&schema_src);
        let envs = Environments::new(&schema, "A", "Action::\"check\"", "A");
        let validator = Validator::new(schema.clone());
        let mut compiler = CedarSymCompiler::new(LocalSolver::cvc5().unwrap()).unwrap();
        let pset = utils::pset_from_text(&policy_src, &validator);
        $check(&mut compiler, &pset, &envs).await;
    };
}

/// Encodes the given property as a policy verification task.
/// All variables need to be prefixed with `$`, but otherwise
/// the property can be arbitrary well-typed Cedar expression.
macro_rules! assert_prop_no_enum {
    // For all concrete values of the bound variables,
    // the property does not error and evaluate to true.
    ($schema_prelude:expr, forall |$($var:ident : $typ:tt),*| $($prop:tt)+) => {
        encode_prop!(
            assert_always_allows,
            forall, $schema_prelude, "",
            permit, $($var : $typ),* { $($prop)+ }
        )
    };
    // For all concrete values of the bound variables,
    // the property errors or evaluate to true.
    ($schema_prelude:expr, forall_or_error |$($var:ident : $typ:tt),*| $($prop:tt)+) => {
        encode_prop!(
            assert_always_allows,
            forall_or_error, $schema_prelude, "permit(principal, action, resource); ",
            forbid, $($var : $typ),* { !($($prop)+) }
        )
    };
    // There exists concrete values of the bound variables,
    // such that the property does not error and evaluate to true.
    ($schema_prelude:expr, exists |$($var:ident : $typ:tt),*| $($prop:tt)+) => {
        encode_prop!(
            assert_does_not_always_deny,
            exists, $schema_prelude, "",
            permit, $($var : $typ),* { $($prop)+ }
        )
    };
    // There exists concrete values of the bound variables,
    // such that the property errors.
    ($schema_prelude:expr, exists_error |$($var:ident : $typ:tt),*| $($prop:tt)+) => {
        encode_prop!(
            assert_does_not_always_deny,
            exists, $schema_prelude, "permit(principal, action, resource); ",
            forbid, $($var : $typ),* { ($($prop)+) == ($($prop)+) }
        )
    };
}

macro_rules! gen_enum_variants {
    ($variant:ident) => {
        concat!('"', stringify!($variant), "\"")
    };
    ($variant:ident, $($rest:ident),+) => {
        concat!('"', stringify!($variant), "\", ", gen_enum_variants!($($rest),+))
    };
}

/// Helper macro to generate enum entity declarations.
macro_rules! gen_enum_decls {
    ($(($name:ident, $($variant:ident),+))*) => {
        concat!(
            $(
                "entity ", stringify!($name), " enum [ ",
                    gen_enum_variants!($($variant),+),
                " ]; "
            ),*
        )
    };
}

/// Same as `assert_prop_no_enum`, but the input can be optionally prefixed with enum declarations.
macro_rules! assert_prop {
    ($(enum $name:ident { $($variant:ident),+ $(,)? })* forall $($rest:tt)+) => {
        assert_prop_no_enum!(gen_enum_decls!($(($name, $($variant),+))*), forall $($rest)+)
    };
    ($(enum $name:ident { $($variant:ident),+ $(,)? })* forall_or_error $($rest:tt)+) => {
        assert_prop_no_enum!(gen_enum_decls!($(($name, $($variant),+))*), forall_or_error $($rest)+)
    };
    ($(enum $name:ident { $($variant:ident),+ $(,)? })* exists $($rest:tt)+) => {
        assert_prop_no_enum!(gen_enum_decls!($(($name, $($variant),+))*), exists $($rest)+)
    };
    ($(enum $name:ident { $($variant:ident),+ $(,)? })* exists_error $($rest:tt)+) => {
        assert_prop_no_enum!(gen_enum_decls!($(($name, $($variant),+))*), exists_error $($rest)+)
    };
}

/// Similar to `assert_prop!`, but generates a `#[test]` function instead.
macro_rules! check_prop {
    ($name:ident, $($rest:tt)+) => {
        #[tokio::test]
        async fn $name() {
            assert_prop!($($rest)+);
        }
    };
}

check_prop!(prop_ipaddr_in_range_transitive,
    forall |a : ipaddr, b : ipaddr, c : ipaddr|
        !($a.isInRange($b) && $b.isInRange($c)) || $a.isInRange($c));

check_prop!(prop_ipaddr_in_range_symmetric,
    forall |a : ipaddr| $a.isInRange($a));

check_prop!(prop_exists_ipv4,
    exists |a : ipaddr| $a.isIpv4());

check_prop!(prop_exists_ipv6,
    exists |a : ipaddr| $a.isIpv6());

check_prop!(prop_ipv4_or_ipv6,
    forall |a : ipaddr| $a.isIpv4() || $a.isIpv6());

check_prop!(prop_ipv4_ipv6_disjoint,
    forall |a : ipaddr| !($a.isIpv4() && $a.isIpv6()));

check_prop!(prop_ipv4_loopback_ex,
    exists |a : ipaddr| $a.isLoopback() && $a.isIpv4());

check_prop!(prop_ipv6_loopback_ex,
    exists |a : ipaddr| $a.isLoopback() && $a.isIpv6());

check_prop!(prop_ipv4_multicast_ex,
    exists |a : ipaddr| $a.isMulticast() && $a.isIpv4());

check_prop!(prop_ipv6_multicast_ex,
    exists |a : ipaddr| $a.isMulticast() && $a.isIpv6());

check_prop!(prop_datetime_to_time_nonnegative,
    forall |x : datetime| $x.toTime() >= duration("0ms"));

check_prop!(prop_datetime_to_date_eq,
    forall |x : datetime|
        !($x >= datetime("2025-08-01") && $x < datetime("2025-08-02")) ||
        $x.toDate() == datetime("2025-08-01"));

check_prop!(prop_duration_since_nonnegative,
    forall |x : datetime, y : datetime|
        !($x >= $y && $y >= datetime("1970-01-01")) ||
        $x.durationSince($y) >= duration("0ms"));

check_prop!(prop_duration_since_nonnegative_or_error,
    forall_or_error |x : datetime, y : datetime|
        !($x >= $y) ||
        $x.durationSince($y) >= duration("0ms"));

check_prop!(prop_datetime_offset_commute,
    forall_or_error |x : datetime, y : duration, z : duration|
        $x.offset($y).offset($z) == $x.offset($z).offset($y));

check_prop!(prop_long_add_error,
    exists_error |a : Long, b : Long| $a + $b);

check_prop!(prop_long_add_commute,
    forall_or_error |a : Long, b : Long| $a + $b == $b + $a);

check_prop!(prop_long_add_assoc,
    forall_or_error |a : Long, b : Long, c : Long| $a + ($b + $c) == ($a + $b) + $c);

check_prop!(prop_long_mul_error,
    exists_error |a : Long, b : Long| $a * $b);

check_prop!(prop_long_mul_commute,
    forall_or_error |a : Long, b : Long| $a * $b == $b * $a);

check_prop!(prop_enum_no_junk,
    enum E { A, B, C }
    forall |a : E| $a == E::"A" || $a == E::"B" || $a == E::"C");

check_prop!(prop_enum_set_eq,
    enum E { A, B }
    forall |a : { x: Set<E> }, b : { x: Set<E> }|
        !(
            $a.x.contains(E::"A") &&
            $a.x.contains(E::"B") &&
            $b.x.contains(E::"A") &&
            $b.x.contains(E::"B")
        ) ||
        $a.x == $b.x);

check_prop!(prop_record_optional,
    exists |a : { x?: Long }, b : { x?: Long }| $b has "x" || $a == $b);
