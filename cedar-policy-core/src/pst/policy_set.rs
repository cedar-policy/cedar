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

//! Policy set types for PST.

use super::{EntityUID, PolicyID, SlotId, StaticPolicy, Template};

use linked_hash_map::LinkedHashMap;
use std::collections::HashMap;

/// PolicySet representation.
#[derive(Debug, Clone)]
pub struct PolicySet {
    /// The set of templates in a policy set
    pub templates: LinkedHashMap<PolicyID, Template>,
    /// The set of static policies in a policy set
    pub policies: LinkedHashMap<PolicyID, StaticPolicy>,
    /// The set of template links in the policy set
    pub template_links: Vec<TemplateLink>,
}

/// Template link representation.
#[derive(Debug, Clone)]
pub struct TemplateLink {
    /// Id of the template to link against
    pub template_id: PolicyID,
    /// Id of the generated policy
    pub new_id: PolicyID,
    /// The values of the link
    pub values: HashMap<SlotId, EntityUID>,
}
