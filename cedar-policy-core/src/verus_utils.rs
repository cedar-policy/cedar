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

//! Extra utilties for Verus verification

#![allow(missing_debug_implementations)] // vstd types Seq/Set/Map don't impl Debug

use smol_str::SmolStr;
use std::collections::HashSet;
use std::hash::Hash;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::hash::*;

// Specification macros

#[allow(unused_macros)]
macro_rules! clone_spec_for {
    ($type:ty) => {
        verus! {
            pub assume_specification[ <$type as Clone>::clone ](this: &$type) -> (other: $type)
                ensures this@ == other@;
        }
    };
}
#[allow(unused_imports)]
pub(crate) use clone_spec_for;

#[allow(unused_macros)]
macro_rules! empty_clone_spec_for {
    ($type:ty) => {
        verus! {
            pub assume_specification[ <$type as Clone>::clone ](this: &$type) -> (other: $type);
        }
    };
}
#[allow(unused_imports)]
pub(crate) use empty_clone_spec_for;

// Specifications for external types

verus! {

#[verifier::external_type_specification]
#[verifier::external_body]
#[derive(Debug)]
pub struct ExSmolStr(SmolStr);

pub assume_specification [<SmolStr as Clone>::clone](s: &SmolStr) -> (res: SmolStr)
ensures res == s;

}

// Helper data structures (should be in vstd)

verus! {

/// A statically finite set (backed internally by a `Seq`)
/// needed due to https://verus-lang.zulipchat.com/#narrow/channel/399078-help/topic/Recursive.20structure.20with.20vstd.20.60Set.60/with/518139335
/// should eventually be replaced with the vstd finite set from https://github.com/verus-lang/verus/tree/jonh/sets-typed-finite
/// but that branch doesn't build yet
#[verifier::accept_recursive_types(T)]
pub struct FiniteSet<T> {
    s: Seq<T>,
}

impl<T> FiniteSet<T> {
    #[verifier::type_invariant]
    pub closed spec fn no_duplicates(self) -> bool {
        self.s.no_duplicates()
    }

}


}

// Helper functions (should be in vstd)

verus! {

#[verifier::external_body]
pub fn hash_set_from_vec<T: Eq + Hash>(vec: Vec<T>) -> (hset: HashSet<T>)
{
    HashSet::from_iter(vec)
}

#[verifier::external_body]
pub fn vec_is_empty<T>(v: &Vec<T>) -> (res: bool)
    ensures
        res <==> v@.len() == 0
{
    v.is_empty()
}

// #[cfg(verus_keep_ghost)]
// pub assume_specification<T, A: std::alloc::Allocator>[ Vec::<T>::is_empty ](
//     v: &Vec<T, A>,
// ) -> (res: bool)
//     ensures
//         res <==> v@.len() == 0,
// ;

}
