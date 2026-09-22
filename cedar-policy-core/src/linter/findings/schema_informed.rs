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

//! Finding types produced by the schema-informed policy lints. Aggregated into
//! [`Finding`](super::Finding).

use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

use crate::parser::Loc;

// Shorthand macro for setting the diagnostic severity to Warning. Used for
// lints that flag constructs which are legal today but rejected by strict
// validation, so they only advise about a future migration.
macro_rules! impl_diagnostic_warning {
    () => {
        fn severity(&self) -> Option<miette::Severity> {
            Some(miette::Severity::Warning)
        }
    };
}

/// A sub-expression that the typechecker proves is a constant `true` or `false`
/// in *every* request environment the policy applies to. Since it never varies,
/// it contributes nothing to the condition. This is the schema-informed
/// generalization of [`ConstantCondition`]: that one recognizes syntactic
/// constants, this one recognizes constants that are only constant given the
/// types (`principal is User` when every principal is a `User`).
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("this sub-expression is always `{value}` given the schema")]
pub struct TypedConstantCondition {
    pub(crate) loc: Option<Loc>,
    pub(crate) value: bool,
}

impl Diagnostic for TypedConstantCondition {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "its type is a singleton in every request environment this policy applies to, so it has the same value for every request; remove it or replace it with the intended condition",
        ))
    }
}

/// A `has` check on an attribute a preceding `has` already established in the
/// same conjunction, e.g. `x has a && x has a`. The second adds nothing. This is
/// purely syntactic and needs no schema.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("this `has` check is redundant")]
pub struct RedundantHas {
    pub(crate) loc: Option<Loc>,
    pub(crate) attr: SmolStr,
}

impl Diagnostic for RedundantHas {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!(
            "`{attr}` was already tested by an earlier `has` in this conjunction, so this repeat has no effect",
            attr = self.attr,
        )))
    }
}

/// A `has` check on an attribute the schema declares *required* on the operand's
/// type in every applicable request environment. The attribute is always present
/// on such an entity, so the check is always true.
///
/// # Tension with the attribute-guard lints
///
/// This is in deliberate tension with [`UnguardedAttrInForbid`] /
/// [`UnguardedAttrInPermit`], which ask you to *add* a `has` guard before every
/// attribute access. Those lints run without a schema, where a guard is always
/// warranted; this one runs with a schema and knows the guard is unnecessary for
/// a required attribute. A defensive author may still want the guard — `has` also
/// proves the *entity* exists, not just the attribute — so this lint is off by
/// default, and enabling it alongside the attribute-guard lints will produce
/// findings that pull in opposite directions on the same code. Choose one policy.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[error("`has {attr}` is always true: the schema declares `{attr}` required")]
pub struct HasOnRequiredAttr {
    pub(crate) loc: Option<Loc>,
    pub(crate) attr: SmolStr,
}

impl Diagnostic for HasOnRequiredAttr {
    impl_diagnostic_from_source_loc_opt_field!(loc);
    impl_diagnostic_warning!();

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(
            "a required attribute is always present, so this test is always true; note that `has` also proves the entity exists, which a defensive policy may still want",
        ))
    }
}
