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
macro_rules! assert_prop_no_schema {
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

/// Same as `assert_prop_no_schema`, but the input can be optionally prefixed with additional schema declarations.
macro_rules! assert_prop {
    ($(schema { $($schema:tt)* })? forall $($rest:tt)+) => {
        assert_prop_no_schema!(concat!($(stringify!($($schema)*))?), forall $($rest)+)
    };
    ($(schema { $($schema:tt)* })? forall_or_error $($rest:tt)+) => {
        assert_prop_no_schema!(concat!($(stringify!($($schema)*))?), forall_or_error $($rest)+)
    };
    ($(schema { $($schema:tt)* })? exists $($rest:tt)+) => {
        assert_prop_no_schema!(concat!($(stringify!($($schema)*))?), exists $($rest)+)
    };
    ($(schema { $($schema:tt)* })? exists_error $($rest:tt)+) => {
        assert_prop_no_schema!(concat!($(stringify!($($schema)*))?), exists_error $($rest)+)
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

check_prop!(prop_hierarchy_acyclic1,
    schema {
        entity U1 in [U2];
        entity U2 in [U1];
    }
    forall |a : U1, b : U2| !($a in $b && $b in $a));

check_prop!(prop_hierarchy_acyclic2,
    schema {
        entity U1 in [U1];
    }
    forall |a : U1, b : U1| !($a in $b && $b in $a) || $a == $b);

check_prop!(prop_hierarchy_transitive,
    schema {
        entity U1 in [U2];
        entity U2 in [U3];
        entity U3;
    }
    forall |a : U1, b : U2, c : U3| !($a in $b && $b in $c) || $a in $c);

check_prop!(prop_ipaddr_in_range_transitive,
    forall |a : ipaddr, b : ipaddr, c : ipaddr|
        !($a.isInRange($b) && $b.isInRange($c)) || $a.isInRange($c));

check_prop!(prop_ipaddr_in_range_symmetric,
    forall |a : ipaddr| $a.isInRange($a));

check_prop!(prop_ipaddr_in_range_example_v4,
    exists |a : ipaddr| $a.isInRange(ip("127.0.0.0/24")));

check_prop!(prop_ipaddr_in_range_example_v6,
    exists |a : ipaddr| $a.isInRange(ip("1:2:3:4::/48")));

check_prop!(prop_ipaddr_set_example,
    exists |a : { x: Set<ipaddr> }| $a.x.contains(ip("127.0.0.0/24")) && $a.x.contains(ip("1:2:3:4::/48")));

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

check_prop!(prop_duration_since_zero_eq,
    forall_or_error |x : datetime, y : datetime|
        !($x.durationSince($y) == duration("0ms")) || $x == $y);

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
    schema {
        entity E enum [ "A", "B", "C" ];
    }
    forall |a : E| $a == E::"A" || $a == E::"B" || $a == E::"C");

check_prop!(prop_enum_set_eq,
    schema {
        entity E enum [ "A", "B" ];
    }
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

check_prop!(prop_set_subset_eq,
    forall |a : { x: Set<Long> }, b : { x: Set<Long> }|
        !(
            $a.x.containsAll($b.x) &&
            $b.x.containsAll($a.x)
        ) ||
        $a.x == $b.x);

check_prop!(prop_set_subset_mem,
    forall |a : { x: Set<Long> }, b : { x: Set<Long> }, c : Long|
        !(
            $a.x.containsAll($b.x) &&
            $b.x.contains($c)
        ) ||
        $a.x.contains($c));

check_prop!(prop_set_intersect,
    forall |a : { x: Set<Long> }, b : { x: Set<Long> }, c : Long|
        !(
            $a.x.contains($c) &&
            $b.x.contains($c)
        ) ||
        $a.x.containsAny($b.x));

check_prop!(prop_empty_sets_eq,
    forall |a : { x: Set<Long> }, b : { x: Set<Long> }|
        !(
            $a.x.isEmpty() &&
            $b.x.isEmpty()
        ) ||
        $a.x == $b.x);

check_prop!(prop_enum_no_ancs,
    schema {
        entity E1 enum [ "A" ];
        entity E2;
    }
    forall |a : E1, b : E2|
        !($a in $b));

check_prop!(prop_no_tags,
    schema { entity E1; }
    forall |a : E1, s : String| !$a.hasTag($s));

check_prop!(prop_to_mills_max,
    exists |a : duration| $a.toMilliseconds() == 9223372036854775807);

check_prop!(prop_to_mills_min,
    exists |a : duration| $a.toMilliseconds() == -9223372036854775808);

check_prop!(prop_to_secs_max,
    exists |a : duration| $a.toSeconds() == 9223372036854775);

check_prop!(prop_to_secs_min,
    exists |a : duration| $a.toSeconds() == -9223372036854775);

check_prop!(prop_to_secs_upper,
    forall |a : duration| $a.toSeconds() <= 9223372036854775);

check_prop!(prop_to_secs_lower,
    forall |a : duration| $a.toSeconds() >= -9223372036854775);

check_prop!(prop_to_mins_max,
    exists |a : duration| $a.toMinutes() == 153722867280912);

check_prop!(prop_to_mins_min,
    exists |a : duration| $a.toMinutes() == -153722867280912);

check_prop!(prop_to_mins_upper,
    forall |a : duration| $a.toMinutes() <= 153722867280912);

check_prop!(prop_to_mins_lower,
    forall |a : duration| $a.toMinutes() >= -153722867280912);

check_prop!(prop_to_hours_max,
    exists |a : duration| $a.toHours() == 2562047788015);

check_prop!(prop_to_hours_min,
    exists |a : duration| $a.toHours() == -2562047788015);

check_prop!(prop_to_hours_upper,
    forall |a : duration| $a.toHours() <= 2562047788015);

check_prop!(prop_to_hours_lower,
    forall |a : duration| $a.toHours() >= -2562047788015);

check_prop!(prop_to_days_max,
    exists |a : duration| $a.toDays() == 106751991167);

check_prop!(prop_to_days_min,
    exists |a : duration| $a.toDays() == -106751991167);

check_prop!(prop_to_days_upper,
    forall |a : duration| $a.toDays() <= 106751991167);

check_prop!(prop_to_days_lower,
    forall |a : duration| $a.toDays() >= -106751991167);

check_prop!(prop_str_empty_pattern,
    forall |a : String, b : String| !($a like "" && $b like "") || $a == $b);

check_prop!(prop_str_pattern_unicode,
    forall |a : String, b : String| !($a like "🫠" && $b like "🫠") || $a == $b);

check_prop!(prop_str_pattern_quote,
    forall |a : String, b : String| !($a like "\"" && $b like "\"") || $a == $b);
