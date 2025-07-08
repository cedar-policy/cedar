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

//! Annotate entity manifest with type information.

use std::collections::HashMap;

use crate::ast::{RequestType, Var};

use crate::validator::entity_manifest::AccessPaths;
use crate::validator::{
    entity_manifest::{
        AccessDag, EntityManifest, EntityRoot, MismatchedEntityManifestError,
        MismatchedMissingEntityError, MismatchedNotStrictSchemaError,
    },
    types::{Attributes, EntityRecordKind, Type},
    ValidatorSchema,
};

impl EntityManifest {
    /// Given an untyped entity manifest and the schema that produced it,
    /// return a newly typed entity manifest.
    /// Makes the types field of the manifest Some instead of None
    pub(crate) fn to_typed(
        &self,
        schema: &ValidatorSchema,
    ) -> Result<EntityManifest, MismatchedEntityManifestError> {
        todo!()
    }
}

impl AccessDag {
    /// Type-annotate this primary slice, given the type of
    /// the request and the schema.
    pub(crate) fn to_typed(
        &self,
        request_type: &RequestType,
        schema: &ValidatorSchema,
    ) -> Result<AccessDag, MismatchedEntityManifestError> {
        // TODO add types
        todo!()
    }
}
