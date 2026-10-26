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

//! TRUSTED: everything here is assumed, not proved. Each item is justified
//! in `cedar-rust-model/TRUSTED.md`. Specifications without `ensures` claim
//! nothing; they only let verified code call the function.

use vstd::prelude::*;

use super::model as m;
use super::value_abs::*;
use crate::ast::SlotEnv;
use crate::ast::*;
use crate::ast::{Integer, Set};
use crate::authorizer::{AuthorizationError, PartialResponse, Response};
use crate::entities::{Dereference, Entities};
use crate::evaluator::evaluation_errors::*;
use crate::evaluator::EvaluationError;
use crate::parser::Loc;
use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::collections::HashMap;

verus! {

// ---------------------------------------------------------------------------
// Opaque types
// ---------------------------------------------------------------------------

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExSmolStr(SmolStr);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExLoc(Loc);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExRepresentableExtensionValue(RepresentableExtensionValue);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExEvaluationError(EvaluationError);

#[verifier::external_type_specification]
pub struct ExType(Type);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExExtensions<'a>(crate::extensions::Extensions<'a>);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExEntities(Entities);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExPolicySet(PolicySet);

// The error types of the `ExprBuilder` methods that the proofs do not use
// (`record`, `call_extension_fn`, `error`)
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExExpressionConstructionError(crate::ast::ExpressionConstructionError);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExInfallible(crate::ast::Infallible);

#[verifier::external_type_specification]
pub struct ExEither<L, R>(itertools::Either<L, R>);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExAnnotations(Annotations);

#[verifier::external_type_specification]
pub struct ExEffect(Effect);

#[verifier::external_type_specification]
pub struct ExDecision(crate::authorizer::Decision);

#[verifier::external_type_specification]
pub struct ExErrorState(crate::authorizer::ErrorState);

#[verifier::external_type_specification]
pub struct ExAuthorizationError(crate::authorizer::AuthorizationError);

#[verifier::external_type_specification]
pub struct ExResponse(crate::authorizer::Response);

#[verifier::external_type_specification]
pub struct ExDiagnostics(crate::authorizer::Diagnostics);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExEntity(Entity);

#[verifier::external_type_specification]
#[verifier::accept_recursive_types(T)]
pub struct ExDereference<'a, T>(Dereference<'a, T>);

#[verifier::external_type_specification]
#[verifier::reject_recursive_types(T)]
pub struct ExNonEmpty<T>(nonempty::NonEmpty<T>);

// ---------------------------------------------------------------------------
// Standard library and `smol_str`
// ---------------------------------------------------------------------------

/// The characters of a `SmolStr`.
pub uninterp spec fn smol_view(s: SmolStr) -> Seq<char>;

/// Lexicographic comparison of character sequences (the order of `str`)
pub open spec fn lex_cmp(a: Seq<char>, b: Seq<char>) -> std::cmp::Ordering
    decreases a.len(),
{
    if a.len() == 0 {
        if b.len() == 0 { std::cmp::Ordering::Equal } else { std::cmp::Ordering::Less }
    } else if b.len() == 0 {
        std::cmp::Ordering::Greater
    } else if (a[0] as u32) < (b[0] as u32) {
        std::cmp::Ordering::Less
    } else if (a[0] as u32) > (b[0] as u32) {
        std::cmp::Ordering::Greater
    } else {
        lex_cmp(a.subrange(1, a.len() as int), b.subrange(1, b.len() as int))
    }
}

/// A left inverse of `smol_view`
pub uninterp spec fn smol_of_view(s: Seq<char>) -> SmolStr;

/// A `SmolStr` is determined by its characters.
pub broadcast axiom fn axiom_smol_view_injective(a: SmolStr)
    ensures
        smol_of_view(#[trigger] smol_view(a)) == a,
;

/// `SmolStr`'s `Eq` and `Ord` compare the characters lexicographically, and
/// obey the laws `vstd` expects of `BTreeMap` keys.
pub broadcast axiom fn axiom_smol_str_cmp(a: SmolStr, b: SmolStr)
    ensures
        #[trigger] vstd::std_specs::cmp::PartialEqSpec::eq_spec(&a, &b) == (smol_view(a) == smol_view(b)),
        #[trigger] vstd::std_specs::cmp::OrdSpec::cmp_spec(&a, &b) == lex_cmp(smol_view(a), smol_view(b)),
;

pub broadcast axiom fn axiom_smol_str_obeys_cmp()
    ensures
        #[trigger] vstd::laws_cmp::obeys_cmp::<SmolStr>(),
;

pub assume_specification[i64::checked_neg](x: i64) -> (r: Option<i64>)
    ensures
        r == (if x == i64::MIN { None } else { Some((0 - x) as i64) }),
;

pub assume_specification<T: core::marker::MetaSized, A: std::alloc::Allocator>[ <std::sync::Arc<T, A> as AsRef<T>>::as_ref ](a: &std::sync::Arc<T, A>) -> (r: &T)
    ensures
        r == &**a,
;

// ---------------------------------------------------------------------------
// `Value`s. Sets and records are abstracted in iteration order, which is the
// model's canonical order (they are `BTreeSet`s/`BTreeMap`s, and the derived
// `Ord` on values agrees with the model's `value_lt`).
// ---------------------------------------------------------------------------

/// The elements of `s.authoritative`, in iteration order.
pub uninterp spec fn set_elems(s: Set) -> Seq<Value>;

/// The elements of a set are those of its `BTreeSet`.
pub axiom fn axiom_set_elems(s: Set)
    ensures
        forall|i: int| 0 <= i < set_elems(s).len() ==> (*s.authoritative)@.contains(#[trigger] set_elems(s)[i]),
;

/// `Value`'s `PartialEq` (derived by `educe`, ignoring source locations)
pub uninterp spec fn value_peq(a: Value, b: Value) -> bool;

/// On modeled values, equality is equality of the abstractions.
pub broadcast axiom fn axiom_value_peq(a: Value, b: Value)
    requires
        modeled(a),
        modeled(b),
    ensures
        #[trigger] value_peq(a, b) == (abs_value(a) == abs_value(b)),
;

impl vstd::std_specs::cmp::PartialEqSpecImpl for Value {
    open spec fn obeys_eq_spec() -> bool {
        true
    }

    open spec fn eq_spec(&self, other: &Value) -> bool {
        value_peq(*self, *other)
    }
}


pub assume_specification[ Set::is_empty ](s: &Set) -> (r: bool)
    ensures
        r == (abs_set(*s) is Nil),
;

pub assume_specification[ Set::is_subset ](a: &Set, b: &Set) -> (r: bool)
    ensures
        r == m::value::values_sub(&abs_set(*a), &abs_set(*b)),
;

pub assume_specification[ Set::is_disjoint ](a: &Set, b: &Set) -> (r: bool)
    ensures
        r == !m::value::values_intersect(&abs_set(*a), &abs_set(*b)),
;

/// `Set::iter` (`self.authoritative.iter()`) yields `set_elems(s)`, in order.
pub assume_specification<'a>[ Set::iter ](s: &'a Set) -> (r: impl Iterator<Item = &'a Value>)
    ensures
        vstd::std_specs::iter::IteratorSpec::obeys_prophetic_iter_laws(&r),
        vstd::std_specs::iter::IteratorSpec::remaining(&r).len() == set_elems(*s).len(),
        forall|i: int| 0 <= i < set_elems(*s).len() ==>
            *#[trigger] vstd::std_specs::iter::IteratorSpec::remaining(&r)[i] == set_elems(*s)[i],
        vstd::std_specs::iter::IteratorSpec::decrease(&r) is Some,
;

pub assume_specification[ Set::contains ](s: &Set, v: &Value) -> (r: bool)
    ensures
        r == m::value::values_contains(&abs_set(*s), &abs_value(*v)),
;

/// Collecting into a `BTreeSet` sorts and dedups, like `values_canonicalize`.
pub assume_specification[ crate::evaluator::value_set_from_vec ](vals: Vec<Value>, loc: Option<Loc>) -> (r: Value)
    ensures
        (forall|i: int| 0 <= i < vals@.len() ==> #[trigger] modeled(vals@[i])) ==> {
            &&& modeled(r)
            &&& abs_value(r) == m::value::Value::Set(Box::new(m::value::values_canonicalize(
                super::abs::seq_to_list(vals@.map_values(|v: Value| abs_value(v))),
            )))
        },
;

/// Collecting distinct-key pairs into a `BTreeMap` sorts them by key, like
/// `attrs_canonicalize`.
pub assume_specification[ crate::evaluator::value_record_from_vec ](pairs: Vec<(SmolStr, Value)>, loc: Option<Loc>) -> (r: Value)
    ensures
        (forall|i: int| 0 <= i < pairs@.len() ==> #[trigger] modeled(pairs@[i].1))
            && (forall|i: int, j: int| #![trigger pairs@[i], pairs@[j]] 0 <= i < j < pairs@.len() ==> pairs@[i].0 != pairs@[j].0)
            ==> {
            &&& modeled(r)
            &&& abs_value(r) == m::value::Value::Record(Box::new(m::value::attrs_canonicalize(
                super::abs::seq_to_list(pairs@.map_values(|e: (SmolStr, Value)| (super::abs::abs_str(e.0), abs_value(e.1)))),
            )))
        },
;

// ---------------------------------------------------------------------------
// Entities. `entities_wf`: the store is concrete and every attribute and tag
// value is modeled (in particular, not a residual).
// ---------------------------------------------------------------------------

pub uninterp spec fn abs_entities(es: Entities) -> m::entities::Entities;

pub uninterp spec fn abs_entity_data(e: Entity) -> m::entities::EntityData;

pub uninterp spec fn entities_wf(es: Entities) -> bool;

pub uninterp spec fn entity_wf(e: Entity) -> bool;

pub assume_specification<'a>[ Entities::entity ](es: &'a Entities, uid: &EntityUID) -> (r: Dereference<'a, Entity>)
    ensures
        entities_wf(*es) ==> match r {
            Dereference::Data(e) => entity_wf(*e) && m::entities::entities_find(
                &abs_entities(*es),
                &super::abs::abs_uid(*uid),
            ) == Some(&abs_entity_data(*e)),
            Dereference::NoSuchEntity => m::entities::entities_find(
                &abs_entities(*es),
                &super::abs::abs_uid(*uid),
            ) is None,
            Dereference::Residual(_) => false,
        },
;

pub assume_specification<'a>[ Entity::get ](e: &'a Entity, attr: &str) -> (r: Option<&'a PartialValue>)
    ensures
        entity_wf(*e) ==> match r {
            Some(pv) => match *pv {
                PartialValue::Value(v) => modeled(v) && m::value::attrs_find(
                    &abs_entity_data(*e).attrs,
                    &super::abs::seq_to_list(attr@),
                ) == Some(&abs_value(v)),
                PartialValue::Residual(_) => false,
            },
            None => m::value::attrs_find(&abs_entity_data(*e).attrs, &super::abs::seq_to_list(attr@)) is None,
        },
;

pub assume_specification<'a>[ Entity::get_tag ](e: &'a Entity, tag: &str) -> (r: Option<&'a PartialValue>)
    ensures
        entity_wf(*e) ==> match r {
            Some(pv) => match *pv {
                PartialValue::Value(v) => modeled(v) && m::value::attrs_find(
                    &abs_entity_data(*e).tags,
                    &super::abs::seq_to_list(tag@),
                ) == Some(&abs_value(v)),
                PartialValue::Residual(_) => false,
            },
            None => m::value::attrs_find(&abs_entity_data(*e).tags, &super::abs::seq_to_list(tag@)) is None,
        },
;

pub assume_specification[ Entity::is_descendant_of ](e: &Entity, uid: &EntityUID) -> (r: bool)
    ensures
        r == m::value::uids_contains(&abs_entity_data(*e).ancestors, &super::abs::abs_uid(*uid)),
;

pub assume_specification[ SmolStr::as_str ](s: &SmolStr) -> (r: &str)
    ensures
        r@ == smol_view(*s),
;

pub assume_specification[ <SmolStr as std::ops::Deref>::deref ](s: &SmolStr) -> (r: &str)
    ensures
        r@ == smol_view(*s),
;

impl vstd::std_specs::cmp::PartialEqSpecImpl for EntityUID {
    open spec fn obeys_eq_spec() -> bool {
        true
    }

    open spec fn eq_spec(&self, other: &EntityUID) -> bool {
        super::abs::abs_uid(*self) == super::abs::abs_uid(*other)
    }
}


impl vstd::std_specs::cmp::PartialEqSpecImpl for EntityType {
    open spec fn obeys_eq_spec() -> bool {
        true
    }

    open spec fn eq_spec(&self, other: &EntityType) -> bool {
        super::abs::abs_entity_type(*self) == super::abs::abs_entity_type(*other)
    }
}


// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

pub assume_specification[ Unknown::new_untyped ](n: impl Into<SmolStr>) -> Unknown;
pub assume_specification[ Unknown::new_with_type ](n: impl Into<SmolStr>, t: Type) -> Unknown;
pub assume_specification<T: core::fmt::Display + ?Sized>[ <T as smol_str::ToSmolStr>::to_smolstr ](t: &T) -> SmolStr;
pub assume_specification<T>[ Expr::<T>::is_projectable ](e: &Expr<T>) -> bool;
pub assume_specification<T: Clone>[ <Expr<T> as Clone>::clone ](e: &Expr<T>) -> (r: Expr<T>)
    ensures
        r == *e,
;

/// `SlotId`'s derived `Eq` and `Hash` obey the `HashMap` model.
pub broadcast axiom fn axiom_slot_id_obeys_key_model()
    ensures
        #[trigger] vstd::std_specs::hash::obeys_key_model::<SlotId>(),
;



pub assume_specification<T, E, U, D: FnOnce(E) -> U, F: FnOnce(T) -> U>[ Result::<T, E>::map_or_else ](
    r: Result<T, E>,
    default: D,
    f: F,
) -> U;

pub assume_specification<T, E, F: FnOnce(E) -> T>[ Result::<T, E>::unwrap_or_else ](r: Result<T, E>, op: F) -> T;

// ---------------------------------------------------------------------------
// Policies and policy sets
// ---------------------------------------------------------------------------

pub open spec fn policy_id_str(id: PolicyID) -> SmolStr {
    id.spec_str()
}


/// Policy IDs with the same characters are equal.
pub proof fn lemma_policy_id_str_injective(a: PolicyID, b: PolicyID)
    requires
        smol_view(policy_id_str(a)) == smol_view(policy_id_str(b)),
    ensures
        a == b,
{
    axiom_smol_view_injective(policy_id_str(a));
    axiom_smol_view_injective(policy_id_str(b));
    PolicyID::lemma_spec_str_injective(a, b);
}

pub broadcast axiom fn axiom_policy_id_obeys_key_model()
    ensures
        #[trigger] vstd::std_specs::hash::obeys_key_model::<PolicyID>(),
;

pub assume_specification[ <PolicyID as Clone>::clone ](v: &PolicyID) -> (r: PolicyID)
    ensures
        r == *v,
;

/// The policies of a policy set (the values of its `LinkedHashMap` `links`),
/// in iteration order
pub uninterp spec fn pset_policies(ps: PolicySet) -> Seq<Policy>;

/// `PolicySet::policies` (`self.links.values()`) yields `pset_policies(ps)`, in order.
pub assume_specification<'a>[ PolicySet::policies ](ps: &'a PolicySet) -> (r: impl Iterator<Item = &'a Policy>)
    ensures
        vstd::std_specs::iter::IteratorSpec::obeys_prophetic_iter_laws(&r),
        vstd::std_specs::iter::IteratorSpec::decrease(&r) is Some,
        vstd::std_specs::iter::IteratorSpec::remaining(&r).len() == pset_policies(*ps).len(),
        forall|i: int| 0 <= i < pset_policies(*ps).len() ==>
            *#[trigger] vstd::std_specs::iter::IteratorSpec::remaining(&r)[i] == pset_policies(*ps)[i],
;

/// Iterating over a `Vec` yields its elements.
pub broadcast axiom fn axiom_vec_into_iter_remaining<T>(v: Vec<T>)
    ensures
        #[trigger] vstd::std_specs::iter::into_iter_remaining::<T, Vec<T>>(v) == v@,
;

// ---------------------------------------------------------------------------
// Authorization responses
// ---------------------------------------------------------------------------

pub open spec fn ids_of<A>(v: Seq<(PolicyID, A)>) -> vstd::set::Set<PolicyID> {
    v.map_values(|x: (PolicyID, A)| x.0).to_set()
}

pub open spec fn error_policy_id(e: AuthorizationError) -> PolicyID {
    match e {
        AuthorizationError::PolicyEvaluationError { id, .. } => id,
    }
}

pub open spec fn error_ids(v: Seq<AuthorizationError>) -> vstd::set::Set<PolicyID> {
    v.map_values(|e: AuthorizationError| error_policy_id(e)).to_set()
}

/// Collects the categorized policies into `HashMap`s keyed by policy ID.
pub assume_specification[ PartialResponse::new ](
    true_permits: impl IntoIterator<Item = (PolicyID, std::sync::Arc<Annotations>)>,
    false_permits: impl IntoIterator<Item = (PolicyID, (crate::authorizer::ErrorState, std::sync::Arc<Annotations>))>,
    residual_permits: impl IntoIterator<Item = (PolicyID, (std::sync::Arc<Expr>, std::sync::Arc<Annotations>))>,
    true_forbids: impl IntoIterator<Item = (PolicyID, std::sync::Arc<Annotations>)>,
    false_forbids: impl IntoIterator<Item = (PolicyID, (crate::authorizer::ErrorState, std::sync::Arc<Annotations>))>,
    residual_forbids: impl IntoIterator<Item = (PolicyID, (std::sync::Arc<Expr>, std::sync::Arc<Annotations>))>,
    errors: impl IntoIterator<Item = AuthorizationError>,
    request: std::sync::Arc<Request>,
) -> (r: PartialResponse)
    ensures
        r.spec_satisfied_permits() == ids_of::<std::sync::Arc<Annotations>>(vstd::std_specs::iter::into_iter_remaining::<(PolicyID, std::sync::Arc<Annotations>), _>(true_permits)),
        r.spec_satisfied_forbids() == ids_of::<std::sync::Arc<Annotations>>(vstd::std_specs::iter::into_iter_remaining::<(PolicyID, std::sync::Arc<Annotations>), _>(true_forbids)),
        r.spec_residual_permits() == ids_of::<(std::sync::Arc<Expr>, std::sync::Arc<Annotations>)>(vstd::std_specs::iter::into_iter_remaining::<(PolicyID, (std::sync::Arc<Expr>, std::sync::Arc<Annotations>)), _>(residual_permits)),
        r.spec_residual_forbids() == ids_of::<(std::sync::Arc<Expr>, std::sync::Arc<Annotations>)>(vstd::std_specs::iter::into_iter_remaining::<(PolicyID, (std::sync::Arc<Expr>, std::sync::Arc<Annotations>)), _>(residual_forbids)),
        r.spec_errors() == vstd::std_specs::iter::into_iter_remaining::<AuthorizationError, _>(errors),
;

pub assume_specification[ <Request as Clone>::clone ](q: &Request) -> (r: Request)
    ensures
        r == *q,
;

// ---------------------------------------------------------------------------
// Evaluation environment
// ---------------------------------------------------------------------------

/// The stack is close to overflowing, so evaluation stops with an error. The
/// theorems assume this does not happen.
pub uninterp spec fn stack_exhausted() -> bool;

pub assume_specification[ crate::evaluator::stack_size_check ]() -> (r: crate::evaluator::Result<()>)
    ensures
        !stack_exhausted() ==> r is Ok,
;

// ---------------------------------------------------------------------------
// Derived `Clone` impls (invisible to Verus) produce equal values.
// ---------------------------------------------------------------------------

pub assume_specification[ <Value as Clone>::clone ](v: &Value) -> (r: Value)
    ensures
        r == *v,
;

pub assume_specification[ <PartialValue as Clone>::clone ](v: &PartialValue) -> (r: PartialValue)
    ensures
        r == *v,
;

pub assume_specification[ <Literal as Clone>::clone ](v: &Literal) -> (r: Literal)
    ensures
        r == *v,
;

pub assume_specification[ <EntityUID as Clone>::clone ](v: &EntityUID) -> (r: EntityUID)
    ensures
        r == *v,
;

pub assume_specification[ <SmolStr as Clone>::clone ](v: &SmolStr) -> (r: SmolStr)
    ensures
        r == *v,
;

pub assume_specification[ <EntityType as Clone>::clone ](v: &EntityType) -> (r: EntityType)
    ensures
        r == *v,
;





// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------




pub assume_specification[ EvaluationError::type_error_single ](
    expected: Type,
    actual: &Value,
) -> EvaluationError;

pub assume_specification[ Type::entity_type ](name: Name) -> Type;

pub assume_specification[ EvaluationError::source_loc ](e: &EvaluationError) -> Option<&Loc>;

pub assume_specification[ EvaluationError::with_maybe_source_loc ](e: EvaluationError, l: Option<Loc>) -> EvaluationError;

pub assume_specification[ EvaluationError::type_error ](expected: nonempty::NonEmpty<Type>, actual: &Value) -> EvaluationError;


pub assume_specification[ EvaluationError::unlinked_slot ](slot: SlotId, source_loc: Option<Loc>) -> EvaluationError;

pub assume_specification[ EvaluationError::non_value ](e: Expr) -> EvaluationError;

pub assume_specification[ EvaluationError::entity_does_not_exist ](
    uid: std::sync::Arc<EntityUID>,
    source_loc: Option<Loc>,
) -> EvaluationError;

pub assume_specification<'a>[ EvaluationError::record_attr_does_not_exist ](
    attr: SmolStr,
    available_attrs: impl IntoIterator<Item = &'a SmolStr>,
    total_attrs: usize,
    source_loc: Option<Loc>,
) -> EvaluationError;



// ---------------------------------------------------------------------------
// Extension values (see also `ext_trusted`)
// ---------------------------------------------------------------------------

/// Only `datetime` and `duration` values support `<` and `<=`.
pub assume_specification[ RepresentableExtensionValue::supports_operator_overloading ](
    v: &RepresentableExtensionValue,
) -> (r: bool)
    ensures
        r == (super::ext_trusted::ext_of(*v) is Datetime || super::ext_trusted::ext_of(*v) is Duration),
;

pub assume_specification[ RepresentableExtensionValue::typename ](v: &RepresentableExtensionValue) -> (r: Name)
    ensures
        r == super::ext_trusted::ext_typename(super::ext_trusted::ext_of(*v)),
;


impl vstd::std_specs::cmp::PartialEqSpecImpl for Name {
    open spec fn obeys_eq_spec() -> bool {
        true
    }

    open spec fn eq_spec(&self, other: &Name) -> bool {
        super::abs::abs_name(*self) == super::abs::abs_name(*other)
    }
}


pub broadcast group group_trusted {
    axiom_value_peq,
    axiom_smol_view_injective,
    axiom_smol_str_cmp,
    axiom_smol_str_obeys_cmp,
    axiom_policy_id_obeys_key_model,
    axiom_vec_into_iter_remaining,
    axiom_slot_id_obeys_key_model,
    super::ext_trusted::axiom_ext_typename,
}

} // verus!
