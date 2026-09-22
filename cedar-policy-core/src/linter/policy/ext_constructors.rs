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

//! Checks calls to single-argument extension constructors, e.g. `ip(..)` or
//! `decimal(..)`.
//!
//! These are the extension functions that take a string and parse it into some
//! other type, so they are the only ones whose argument can be statically
//! wrong. Two findings come out of this pass:
//!
//! * If the argument is a string literal, we evaluate the call. A literal that
//!   fails to parse is an error: the call is guaranteed to fail at evaluation
//!   time, so the policy is certainly wrong.
//! * If the argument is anything else we can't check it, and neither can strict
//!   validation, which rejects such calls outright. We report a warning to ease
//!   migration.
//!
//! Other extension functions take an already-constructed value rather than a
//! string to parse, so they are not checked here.

use crate::{
    ast::{Expr, ExprKind, Literal, RestrictedExpr},
    evaluator::RestrictedEvaluator,
    extensions::Extensions,
    linter::findings::{ExtConstructorError, Finding, NonLitExtConstructor},
};
use miette::Diagnostic;

use crate::linter::util::scan;

/// Lint `expr`, reporting single-argument extension constructors called with a
/// non-literal argument (which strict validation rejects) or with a literal that
/// fails to parse.
pub(crate) fn lint(expr: &Expr) -> Vec<Finding> {
    scan(expr, |e| {
        let ExprKind::ExtensionFunctionApp { fn_name, args } = e.expr_kind() else {
            return None;
        };
        // Wrong arity and unknown function names are both parse errors, so there's
        // nothing useful for us to add.
        let arg = args.first()?;
        let func = Extensions::all_available().func(fn_name).ok()?;
        if !func.is_single_arg_constructor() {
            return None;
        }
        match arg.expr_kind() {
            ExprKind::Lit(Literal::String(s)) => {
                // Rebuild the call as a restricted expression so it can be
                // evaluated with no request or entity store.
                let call = RestrictedExpr::call_extension_fn(
                    fn_name.clone(),
                    [RestrictedExpr::val(s.clone())],
                );
                let evaluator = RestrictedEvaluator::new(Extensions::all_available());
                evaluator.interpret(call.as_borrowed()).err().map(|err| {
                    ExtConstructorError {
                        loc: e.source_loc().cloned(),
                        fn_name: fn_name.clone(),
                        arg: s.to_string(),
                        err: err.to_string(),
                        err_help: err.help().map(|h| h.to_string()),
                    }
                    .into()
                })
            }
            _ => Some(
                NonLitExtConstructor {
                    loc: e.source_loc().cloned(),
                    fn_name: fn_name.clone(),
                }
                .into(),
            ),
        }
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::linter::test_util::render;
    use crate::parser::parse_expr;

    /// Lint `src` and return the pretty miette rendering of all findings.
    #[track_caller]
    fn lint_report(src: &str) -> String {
        let expr = parse_expr(src).expect("failed to parse");
        render(&lint(&expr))
    }

    /// A constructor whose argument isn't a literal can't be checked, so we warn
    /// that strict validation will reject it.
    #[test]
    #[cfg(feature = "ipaddr")]
    fn non_literal_argument() {
        insta::assert_snapshot!(lint_report(r#"ip(principal.addr)"#), @"
         ⚠ extension constructor `ip` called with a non-literal argument
          ╭────
        1 │ ip(principal.addr)
          · ──────────────────
          ╰────
         help: consider applying extension constructors inside attribute values when constructing entity or context data
        ");
        insta::assert_snapshot!(lint_report(r#"ip(context.a + context.b)"#), @"
         ⚠ extension constructor `ip` called with a non-literal argument
          ╭────
        1 │ ip(context.a + context.b)
          · ─────────────────────────
          ╰────
         help: consider applying extension constructors inside attribute values when constructing entity or context data
        ");
    }

    /// A literal that parses is fine.
    #[test]
    #[cfg(feature = "ipaddr")]
    fn valid_literal() {
        insta::assert_snapshot!(lint_report(r#"ip("1.2.3.4")"#), @"");
        insta::assert_snapshot!(lint_report(r#"ip("1.2.3.0/24")"#), @"");
    }

    /// A literal that fails to parse is an error, since the call is guaranteed
    /// to fail at evaluation time.
    #[test]
    #[cfg(feature = "ipaddr")]
    fn invalid_literal_ipaddr() {
        insta::assert_snapshot!(lint_report(r#"ip("not-an-ip")"#), @r#"
         × `ip` cannot be constructed from `not-an-ip`: error while evaluating `ipaddr` extension function: invalid IP address: not-an-ip
          ╭────
        1 │ ip("not-an-ip")
          · ───────────────
          ╰────
         help: valid IP strings are IPv4/IPv6 addresses or CIDR ranges like `127.0.0.1`, `127.0.0.1/24`, or `ffee::/64`
        "#);
        insta::assert_snapshot!(lint_report(r#"ip("1.2.3.4/99")"#), @r#"
         × `ip` cannot be constructed from `1.2.3.4/99`: error while evaluating `ipaddr` extension function: error parsing prefix: 99 is larger than the limit 32
          ╭────
        1 │ ip("1.2.3.4/99")
          · ────────────────
          ╰────
         help: valid IP strings are IPv4/IPv6 addresses or CIDR ranges like `127.0.0.1`, `127.0.0.1/24`, or `ffee::/64`
        "#);
    }

    #[test]
    #[cfg(feature = "decimal")]
    fn invalid_literal_decimal() {
        insta::assert_snapshot!(lint_report(r#"decimal("1.2.3")"#), @r#"
         × `decimal` cannot be constructed from `1.2.3`: error while evaluating `decimal` extension function: `1.2.3` is not a well-formed decimal value
          ╭────
        1 │ decimal("1.2.3")
          · ────────────────
          ╰────
         help: valid decimal strings look like `12.34`: digits are required on both sides of `.`, up to 4 fractional digits are allowed, and the value must be in range -922337203685477.5808 to
               922337203685477.5807
        "#);
        insta::assert_snapshot!(lint_report(r#"decimal("1.5")"#), @"");
    }

    #[test]
    #[cfg(feature = "datetime")]
    fn invalid_literal_datetime() {
        insta::assert_snapshot!(lint_report(r#"datetime("not-a-date")"#), @r#"
         × `datetime` cannot be constructed from `not-a-date`: error while evaluating `datetime` extension function: invalid date pattern
          ╭────
        1 │ datetime("not-a-date")
          · ──────────────────────
          ╰────
         help: valid datetime strings start with `YYYY-MM-DD` and may optionally include `THH:MM:SS` plus `Z`, `.SSSZ`, or an offset like `+0700`
        "#);
        insta::assert_snapshot!(lint_report(r#"datetime("2026-08-03")"#), @"");
    }

    /// Non-constructor extension functions take an already-constructed value, so
    /// they aren't subject to either finding.
    #[test]
    #[cfg(feature = "ipaddr")]
    fn non_constructor_not_linted() {
        insta::assert_snapshot!(lint_report(r#"ip("1.2.3.4").isInRange(ip("1.2.3.0/24"))"#), @"");
        insta::assert_snapshot!(lint_report(r#"principal.addr.isLoopback()"#), @"");
    }

    /// Constructors nested inside larger expressions are still found, and each
    /// call is reported separately.
    #[test]
    #[cfg(feature = "ipaddr")]
    fn nested_calls() {
        insta::assert_snapshot!(
            lint_report(r#"ip("bad1").isInRange(ip("bad2"))"#), @r#"
         × `ip` cannot be constructed from `bad1`: error while evaluating `ipaddr` extension function: invalid IP address: bad1
          ╭────
        1 │ ip("bad1").isInRange(ip("bad2"))
          · ────────────────────────────────
          ╰────
         help: valid IP strings are IPv4/IPv6 addresses or CIDR ranges like `127.0.0.1`, `127.0.0.1/24`, or `ffee::/64`

         × `ip` cannot be constructed from `bad2`: error while evaluating `ipaddr` extension function: invalid IP address: bad2
          ╭────
        1 │ ip("bad1").isInRange(ip("bad2"))
          ·                      ──────────
          ╰────
         help: valid IP strings are IPv4/IPv6 addresses or CIDR ranges like `127.0.0.1`, `127.0.0.1/24`, or `ffee::/64`
        "#);
        insta::assert_snapshot!(
            lint_report(r#"{addr: ip(principal.a), other: ip("bad")}"#), @r#"
         ⚠ extension constructor `ip` called with a non-literal argument
          ╭────
        1 │ {addr: ip(principal.a), other: ip("bad")}
          ·        ───────────────
          ╰────
         help: consider applying extension constructors inside attribute values when constructing entity or context data

         × `ip` cannot be constructed from `bad`: error while evaluating `ipaddr` extension function: invalid IP address: bad
          ╭────
        1 │ {addr: ip(principal.a), other: ip("bad")}
          ·                                ─────────
          ╰────
         help: valid IP strings are IPv4/IPv6 addresses or CIDR ranges like `127.0.0.1`, `127.0.0.1/24`, or `ffee::/64`
        "#);
    }
}
