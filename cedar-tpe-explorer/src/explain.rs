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

//! Explaining decisions without a solver.
//!
//! Given facts that already decide a request, find a minimal subset of them
//! that still forces the same decision. This answers "why was this allowed /
//! denied?" with the handful of facts that actually mattered, and works for
//! fully concrete requests as well as partial ones.

use cedar_policy_core::authorizer::Decision;

use crate::eval::{evaluate, Evaluation};
use crate::facts::{Facts, PartialUid};
use crate::project::Project;
use crate::suggest::{minimize, Assignment};

/// A minimal justification for a decision.
#[derive(Debug, Clone)]
pub struct Explanation {
    pub decision: Decision,
    /// Facts that suffice to force `decision`; dropping any one of them
    /// leaves the request undecided.
    pub facts: Vec<Assignment>,
    /// Evaluation with only those facts.
    pub evaluation: Evaluation,
}

/// Facts for the same request shape as `facts`, with nothing known.
pub fn blank_like(project: &Project, facts: &Facts) -> Result<Facts, String> {
    let mut blank = Facts::new(project, &facts.action)?;
    blank.principal = PartialUid {
        ty: facts.principal.ty.clone(),
        eid: None,
    };
    blank.resource = PartialUid {
        ty: facts.resource.ty.clone(),
        eid: None,
    };
    Ok(blank)
}

/// Explain the decision reached under `facts`. Returns `Ok(None)` if the
/// facts do not decide the request.
pub fn explain(project: &Project, facts: &Facts) -> Result<Option<Explanation>, String> {
    let eval = evaluate(project, facts)?;
    let Some(decision) = eval.decision else {
        return Ok(None);
    };
    let blank = blank_like(project, facts)?;
    let known: Vec<Assignment> = facts
        .known_slots(project.vschema())
        .into_iter()
        .map(|(slot, value)| Assignment { slot, value })
        .collect();
    let Some(min) = minimize(project, &blank, known, |e| e.decision == Some(decision)) else {
        return Err("decision is not reproducible from the known facts".into());
    };
    let reduced = crate::suggest::apply(project, &blank, &min)?;
    let evaluation = evaluate(project, &reduced)?;
    Ok(Some(Explanation {
        decision,
        facts: min,
        evaluation,
    }))
}
