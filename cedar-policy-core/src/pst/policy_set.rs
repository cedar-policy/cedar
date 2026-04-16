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

/// A collection of Cedar policies, templates, and template links.
///
/// Use [`PolicySet`] to group related policies for conversion to the
/// authorization engine's internal representation via
/// [`cedar_policy::PolicySet::from_pst()`](https://docs.rs/cedar-policy/latest/cedar_policy/struct.PolicySet.html#method.from_pst).
///
/// ```
/// # use cedar_policy_core::pst::*;
/// # use smol_str::SmolStr;
/// let mut ps = PolicySet {
///     templates: LinkedHashMap::new(),
///     policies: LinkedHashMap::new(),
///     template_links: vec![],
/// };
/// let template = Template::new(
///     "p0", Effect::Permit,
///     PrincipalConstraint::Any, ActionConstraint::Any, ResourceConstraint::Any,
/// );
/// ps.policies.insert(
///     template.id.clone(),
///     StaticPolicy::try_from(template).unwrap(),
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySet {
    /// Templates (policies with slots) keyed by template id.
    pub templates: LinkedHashMap<PolicyID, Template>,
    /// Static policies (no slots) keyed by policy id.
    pub policies: LinkedHashMap<PolicyID, StaticPolicy>,
    /// Links that instantiate templates with concrete entity UIDs.
    pub template_links: Vec<TemplateLink>,
}

/// A link that instantiates a [`Template`] by filling its slots with concrete entity UIDs.
///
/// ```
/// # use cedar_policy_core::pst::*;
/// # use smol_str::SmolStr;
/// # use std::collections::HashMap;
/// let user = Name::unqualified("User").unwrap();
/// let user_alice = EntityUID {
///     ty: EntityType::from_name(user),
///     eid: SmolStr::from("alice"),
/// };
/// let link = TemplateLink {
///     template_id: PolicyID("template_123".into()),
///     new_id: PolicyID("instance_0".into()),
///     values: HashMap::from([(SlotId::Principal, user_alice)]),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateLink {
    /// Id of the template to instantiate.
    pub template_id: PolicyID,
    /// Id for the resulting linked policy.
    pub new_id: PolicyID,
    /// Slot values: maps each slot to a concrete entity UID.
    pub values: HashMap<SlotId, EntityUID>,
}
