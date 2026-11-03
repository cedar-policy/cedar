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

#![expect(clippy::unwrap_used, reason = "test code")]

//! `BatchSolver` (the path the web front end uses) must agree with the
//! interactive local solver. Here each batch runs in a fresh `cvc5` process.
use cedar_tpe_explorer::suggest::suggest_for_policy;
use cedar_tpe_explorer::symcc::{BatchSolver, SmtRunner, SymccModelFinder};
use cedar_tpe_explorer::{evaluate, Facts, Project};
use std::io::Write;

struct ProcessRunner;

impl SmtRunner for ProcessRunner {
    async fn run(&mut self, script: String) -> Result<String, String> {
        let cvc5 = std::env::var("CVC5").unwrap_or_else(|_| "cvc5".into());
        let mut child = std::process::Command::new(cvc5)
            .args(["--lang", "smt2"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .map_err(|e| e.to_string())?;
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn batch_matches_local() {
    let p = Project::new(
        include_str!("../sample-data/photoapp/photoapp.cedarschema"),
        include_str!("../sample-data/photoapp/policies.cedar"),
    )
    .unwrap();
    let f = Facts::initial(&p).unwrap();
    let e = evaluate(&p, &f).unwrap();
    let mut batch = SymccModelFinder::with_solver(BatchSolver::new(ProcessRunner)).unwrap();
    let mut local = SymccModelFinder::new(10_000).unwrap();
    for pol in &e.policies {
        let a = suggest_for_policy(&p, &f, &e, &pol.id, &mut batch)
            .await
            .unwrap();
        let b = suggest_for_policy(&p, &f, &e, &pol.id, &mut local)
            .await
            .unwrap();
        let show = |s: &[cedar_tpe_explorer::Suggestion]| -> Vec<Vec<String>> {
            s.iter()
                .map(|x| x.assignments.iter().map(|a| a.describe()).collect())
                .collect()
        };
        println!("{} → {:?}", pol.id, show(&a));
        assert_eq!(show(&a), show(&b), "policy {}", pol.id);
    }
}
