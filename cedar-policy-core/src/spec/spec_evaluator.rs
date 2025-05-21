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

//! This module contains a spec of the Cedar evaluator, translated to Verus spec code
//! from the Lean spec in cedar-spec/cedar-lean/Cedar/Spec/Evaluator.lean.

#![allow(missing_debug_implementations)] // vstd types Seq/Set/Map don't impl Debug
#![allow(missing_docs)] // just for now
#![allow(unused_imports)]

pub use crate::spec::spec_ast::*;
pub use crate::verus_utils::*;
#[cfg(verus_keep_ghost)]
pub use vstd::{map::*, prelude::*, seq::*, set::*};

verus! {

// For now, we are leaving the evaluator as an uninterpreted stub
pub uninterp spec fn evaluate(x: Expr, req: Request, es: Entities) -> SpecResult<Value>;

}
