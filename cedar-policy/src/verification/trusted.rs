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
//! Assumptions of the public-API proofs beyond those of
//! `cedar_policy_core::verification` (`cedar-rust-model/TRUSTED.md`).
#![allow(unused_imports)]

use vstd::prelude::*;

use cedar_policy_core::ast;
use linked_hash_map::LinkedHashMap;

verus! {

/// Opaque: only appears in the redundant maps of a public `PolicySet`; the
/// proofs only use its core policy set (`spec_ast`).
#[verifier::external_type_specification]
#[verifier::external_body]
#[verifier::reject_recursive_types(K)]
#[verifier::reject_recursive_types(V)]
#[verifier::reject_recursive_types(S)]
pub struct ExLinkedHashMap<K, V, S>(LinkedHashMap<K, V, S>);

/// Opaque, likewise
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExPolicy(crate::api::Policy);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExTemplate(crate::api::Template);

} // verus!
