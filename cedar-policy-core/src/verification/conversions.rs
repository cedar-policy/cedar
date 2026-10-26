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

//! Specifications of the production `From` impls.

use vstd::prelude::*;
use vstd::std_specs::convert::{FromSpecImpl, IntoSpec};

use crate::ast::*;
use crate::ast::{Integer, Set};
use smol_str::SmolStr;
use std::sync::Arc;

verus! {

impl FromSpecImpl<bool> for Literal {
    open spec fn obeys_from_spec() -> bool {
        true
    }

    open spec fn from_spec(v: bool) -> Literal {
        Literal::Bool(v)
    }
}

impl FromSpecImpl<i64> for Literal {
    open spec fn obeys_from_spec() -> bool {
        true
    }

    open spec fn from_spec(v: i64) -> Literal {
        Literal::Long(v)
    }
}

impl FromSpecImpl<SmolStr> for Literal {
    open spec fn obeys_from_spec() -> bool {
        true
    }

    open spec fn from_spec(v: SmolStr) -> Literal {
        Literal::String(v)
    }
}

impl FromSpecImpl<EntityUID> for Literal {
    open spec fn obeys_from_spec() -> bool {
        true
    }

    open spec fn from_spec(v: EntityUID) -> Literal {
        Literal::EntityUID(Arc::new(v))
    }
}

impl FromSpecImpl<Arc<EntityUID>> for Literal {
    open spec fn obeys_from_spec() -> bool {
        true
    }

    open spec fn from_spec(v: Arc<EntityUID>) -> Literal {
        Literal::EntityUID(v)
    }
}

impl<T: Into<Literal>> FromSpecImpl<T> for ValueKind {
    open spec fn obeys_from_spec() -> bool {
        <T as IntoSpec<Literal>>::obeys_into_spec()
    }

    open spec fn from_spec(v: T) -> ValueKind {
        ValueKind::Lit(v.into_spec())
    }
}

impl<T: Into<Literal>> FromSpecImpl<T> for Value {
    open spec fn obeys_from_spec() -> bool {
        <T as IntoSpec<Literal>>::obeys_into_spec()
    }

    open spec fn from_spec(v: T) -> Value {
        Value { value: ValueKind::Lit(v.into_spec()), loc: None }
    }
}

impl FromSpecImpl<PrincipalOrResource> for Var {
    open spec fn obeys_from_spec() -> bool {
        true
    }

    open spec fn from_spec(v: PrincipalOrResource) -> Var {
        super::policy_abs::var_of(v)
    }
}

impl FromSpecImpl<PrincipalOrResource> for SlotId {
    open spec fn obeys_from_spec() -> bool {
        true
    }

    open spec fn from_spec(v: PrincipalOrResource) -> SlotId {
        super::policy_abs::slot_of(v)
    }
}

// `From<Context>` has its own, more specific, specification.
impl FromSpecImpl<Context> for PartialValue {
    open spec fn obeys_from_spec() -> bool {
        false
    }

    open spec fn from_spec(v: Context) -> PartialValue {
        arbitrary()
    }
}

impl<V: Into<Value>> FromSpecImpl<V> for PartialValue {
    open spec fn obeys_from_spec() -> bool {
        <V as IntoSpec<Value>>::obeys_into_spec()
    }

    open spec fn from_spec(v: V) -> PartialValue {
        PartialValue::Value(v.into_spec())
    }
}

/// `From<PartialResponse> for Response` has its own specification
/// (`authorizer_lemmas::concretized`).
impl FromSpecImpl<crate::authorizer::PartialResponse> for crate::authorizer::Response {
    open spec fn obeys_from_spec() -> bool {
        false
    }

    open spec fn from_spec(v: crate::authorizer::PartialResponse) -> Self {
        arbitrary()
    }
}

/// `v.into()` for `v: impl Into<Literal>` (a type specs cannot name)
pub open spec fn into_literal<V: Into<Literal>>(v: V) -> Literal {
    <V as IntoSpec<Literal>>::into_spec(v)
}

/// The conversion of `v: impl Into<Literal>` obeys its specification
pub open spec fn obeys_into_literal<V: Into<Literal>>(v: V) -> bool {
    <V as IntoSpec<Literal>>::obeys_into_spec()
}

} // verus!
