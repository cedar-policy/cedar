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

//! The schema-free policy lints — those that inspect a policy's AST (or CST)
//! alone, needing neither a schema nor type-aware evaluation. Each submodule is
//! one lint; the driver in [`Linter`](crate::linter::Linter) selects and runs
//! them.

pub(crate) mod attr_guards;
pub(crate) mod attribute_depth;
pub(crate) mod constant_condition;
pub(crate) mod double_negation;
pub(crate) mod duplicate_policy;
pub(crate) mod empty_set;
pub(crate) mod erroring_forbid;
pub(crate) mod expr_style;
pub(crate) mod ext_constructors;
pub(crate) mod forbid_guard;
pub(crate) mod forbid_without_permit;
pub(crate) mod like_patterns;
pub(crate) mod nonlinear;
pub(crate) mod redundant_boolean;
pub(crate) mod redundant_expr;
pub(crate) mod redundant_has;
pub(crate) mod scope_constraints;
pub(crate) mod scope_literals;
pub(crate) mod scope_required;
pub(crate) mod self_comparison;
pub(crate) mod sugar;
pub(crate) mod syntax_style;
pub(crate) mod tags;
pub(crate) mod universal_policy;
pub(crate) mod yoda_condition;
