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

use clap::Subcommand;

mod authorize;
pub use authorize::*;
mod evaluate;
pub use evaluate::*;
mod validate;
pub use validate::*;
mod check_parse;
pub use check_parse::*;
mod symcc;
pub use symcc::*;
mod tpe;
pub use tpe::*;
mod partial_eval;
pub use partial_eval::*;
mod run_test;
pub use run_test::*;
mod link;
pub use link::*;
mod format;
pub use format::*;
mod translate_policy;
pub use translate_policy::*;
mod translate_schema;
pub use translate_schema::*;
mod visualize;
pub use visualize::*;
mod new;
pub use new::*;
mod language_version;
pub use language_version::*;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Evaluate an authorization request
    Authorize(AuthorizeArgs),
    /// Evaluate a Cedar expression
    Evaluate(EvaluateArgs),
    /// Validate a policy set against a schema
    Validate(ValidateArgs),
    /// Check that policies, expressions, schema, and/or entities successfully parse.
    /// (All arguments are optional; this checks that whatever is provided parses)
    ///
    /// If no arguments are provided, reads policies from stdin and checks that they parse.
    CheckParse(CheckParseArgs),
    /// Link a template
    Link(LinkArgs),
    /// Format a policy set
    Format(FormatArgs),
    /// Translate Cedar policy syntax to JSON policy syntax (except comments)
    TranslatePolicy(TranslatePolicyArgs),
    /// Translate Cedar schema syntax to JSON schema syntax and vice versa (except comments)
    TranslateSchema(TranslateSchemaArgs),
    /// Visualize a set of JSON entities to the graphviz format.
    /// Warning: Entity visualization is best-effort and not well tested.
    Visualize(VisualizeArgs),
    /// Create a Cedar project
    New(NewArgs),
    /// Partially evaluate an authorization request
    PartiallyAuthorize(PartiallyAuthorizeArgs),
    /// Partially evaluate an authorization request in a type-aware manner
    Tpe(TpeArgs),
    /// Run test cases on a policy set
    ///
    /// Tests are defined in a JSON array of objects with the following fields:
    ///   - name: optional test name string
    ///   - request: object using the same format as the `--request-json` argument for authorization
    ///   - entities: array of entity JSON objects in the same format expected by `--entities` argument for authorization
    ///   - decision: the string "allow" or "deny"
    ///   - reason: array of policy ID strings expected to contribute to the authorization decision
    ///   - num_errors: expected number of erroring policies
    #[clap(verbatim_doc_comment)] // stops clap from dropping newlines in bulleted list
    RunTests(RunTestsArgs),
    /// Symbolic analysis of Cedar policies using SymCC
    Symcc(SymccArgs),
    /// Print Cedar language version
    LanguageVersion,
}
