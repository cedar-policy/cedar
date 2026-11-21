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

//! This module is as straightforward a translation as possible of
//! <https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/Cedar/SymCCOpt/Enforcer.lean>.

use std::collections::BTreeSet;

use itertools::Itertools;

use crate::symcc::{self, term::Term, SymEnv};

use super::{CompiledPolicy, CompiledPolicySet};

/// Transitivity constraints for every ordered pair in `lhs` x `rhs`.
pub(super) fn transitivity_constraints<'a>(
    lhs: &'a BTreeSet<Term>,
    rhs: &'a BTreeSet<Term>,
    symenv: &'a SymEnv,
) -> impl Iterator<Item = Term> + 'a {
    lhs.iter()
        .cartesian_product(rhs)
        .map(|(term1, term2)| symcc::enforcer::transitivity(term1, term2, &symenv.entities))
}

pub fn enforce_compiled_policy(cp: &CompiledPolicy) -> BTreeSet<Term> {
    cp.acyclicity
        .iter()
        .chain(&cp.transitivity)
        .cloned()
        .collect()
}

#[expect(dead_code, reason = "exists in the Lean")]
pub fn enforce_compiled_policyset(cpset: &CompiledPolicySet) -> BTreeSet<Term> {
    let tr = cpset
        .footprint
        .iter()
        .cartesian_product(&cpset.footprint)
        .map(|(term1, term2)| symcc::enforcer::transitivity(term1, term2, &cpset.symenv.entities));
    cpset.acyclicity.iter().cloned().chain(tr).collect()
}

pub fn enforce_pair_compiled_policy(cp1: &CompiledPolicy, cp2: &CompiledPolicy) -> BTreeSet<Term> {
    assert_eq!(&cp1.symenv, &cp2.symenv);
    // The pairs within each footprint are cached on the policies; only the
    // cross pairs between the two footprints remain to be computed.
    let cross = transitivity_constraints(&cp1.footprint, &cp2.footprint, &cp1.symenv).chain(
        transitivity_constraints(&cp2.footprint, &cp1.footprint, &cp1.symenv),
    );
    cp1.acyclicity
        .union(&cp2.acyclicity)
        .chain(&cp1.transitivity)
        .chain(&cp2.transitivity)
        .cloned()
        .chain(cross)
        .collect()
}

pub fn enforce_pair_compiled_policyset(
    cpset1: &CompiledPolicySet,
    cpset2: &CompiledPolicySet,
) -> BTreeSet<Term> {
    assert_eq!(&cpset1.symenv, &cpset2.symenv);
    let footprint: Vec<_> = cpset1.footprint.union(&cpset2.footprint).collect();
    let tr = footprint
        .iter()
        .cartesian_product(&footprint)
        .map(|(term1, term2)| symcc::enforcer::transitivity(term1, term2, &cpset1.symenv.entities));
    cpset1
        .acyclicity
        .union(&cpset2.acyclicity)
        .cloned()
        .chain(tr)
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use cedar_policy::{RequestEnv, Schema};
    use cedar_policy_core::{ast::Policy, parser::parse_policy};

    /// The pair constraints must equal the transitivity constraints over the
    /// union of both footprints, i.e. what was computed before they were cached.
    #[test]
    fn pair_constraints_match_union_footprint() {
        let schema = Schema::from_cedarschema_str(
            "entity G; entity U in [G]; entity R in [G]; action A appliesTo { principal: U, resource: R };",
        )
        .unwrap()
        .0;
        let env = RequestEnv::new(
            "U".parse().unwrap(),
            r#"Action::"A""#.parse().unwrap(),
            "R".parse().unwrap(),
        );
        let compiled_schema = crate::symcc::CompiledSchema::new(&schema).unwrap();
        let compile = |src: &str| {
            let p: Policy = parse_policy(None, src).unwrap().into();
            CompiledPolicy::compile(&p, &env, &compiled_schema).unwrap()
        };
        let cp1 = compile(r#"permit(principal, action, resource) when { principal in G::"a" };"#);
        let cp2 = compile(r#"permit(principal, action, resource) when { resource in G::"b" };"#);
        assert!(!cp1.footprint.is_empty() && !cp2.footprint.is_empty());

        let footprint: Vec<_> = cp1.footprint.union(&cp2.footprint).collect();
        let expected: BTreeSet<Term> = cp1
            .acyclicity
            .union(&cp2.acyclicity)
            .cloned()
            .chain(
                footprint
                    .iter()
                    .cartesian_product(&footprint)
                    .map(|(t1, t2)| symcc::enforcer::transitivity(t1, t2, &cp1.symenv.entities)),
            )
            .collect();
        assert_eq!(enforce_pair_compiled_policy(&cp1, &cp2), expected);
    }
}
