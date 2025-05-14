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

//! This module contains spec data structures modeling the Cedar AST

pub use vstd::{map::*, prelude::*, seq::*, set::*};

verus! {

//////////////////////////////////////////////////
// VALUES: see cedar-spec/Cedar/Spec/Value.lean //
//////////////////////////////////////////////////

pub type Id = Seq<char>;

pub struct Name {
    pub id: Id,
    pub path: Seq<Id>,
}

pub type EntityType = Name;

pub struct EntityUID {
    ty: EntityType,
    eid: Seq<char>,
}

pub enum Prim {
    Bool(bool),
    Int(i64),
    String(Seq<char>),
    EntityUID(EntityUID),
}

pub type Attr = Seq<char>;


pub enum Value {
    Prim(Prim),
    Set(Set<Value>), // fails due to https://verus-lang.zulipchat.com/#narrow/channel/399078-help/topic/Recursive.20structure.20with.20vstd.20.60Set.60/with/518139335
    Record(Map<Attr, Value>),
    // Ext(Ext) // TODO(Pratap): extensions
}



///////////////////////////////////////////////////////
// ENTITIES: see cedar-spec/Cedar/Spec/Entities.lean //
///////////////////////////////////////////////////////

pub type Tag = Seq<char>;

pub struct EntityData {
    pub attrs: Map<Attr, Value>,
    pub ancestors: Set<EntityUID>,
    pub tags: Map<Tag, Value>
}

pub type Entities = Map<EntityUID, EntityData>;




} // verus!
