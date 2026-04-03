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

use cedar_policy::{EntityUid, PolicyId, PolicySet, SlotId};
use miette::{IntoDiagnostic, Result, WrapErr};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path, str::FromStr};

/// Iterate over links in the template-linked file and add them to the set
pub(crate) fn add_template_links_to_set(
    path: impl AsRef<Path>,
    policy_set: &mut PolicySet,
) -> Result<()> {
    for template_linked in load_links_from_file(path)? {
        let slot_env = create_slot_env(&template_linked.args)?;
        policy_set.link(
            PolicyId::new(&template_linked.template_id),
            PolicyId::new(&template_linked.link_id),
            slot_env,
        )?;
    }
    Ok(())
}

pub(crate) fn create_slot_env(
    data: &HashMap<SlotId, String>,
) -> Result<HashMap<SlotId, EntityUid>> {
    data.iter()
        .map(|(key, value)| Ok(EntityUid::from_str(value).map(|euid| (key.clone(), euid))?))
        .collect::<Result<HashMap<SlotId, EntityUid>>>()
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(try_from = "LiteralTemplateLinked")]
#[serde(into = "LiteralTemplateLinked")]
pub(crate) struct TemplateLinked {
    pub(crate) template_id: String,
    pub(crate) link_id: String,
    pub(crate) args: HashMap<SlotId, String>,
}

impl TryFrom<LiteralTemplateLinked> for TemplateLinked {
    type Error = String;

    fn try_from(value: LiteralTemplateLinked) -> Result<Self, Self::Error> {
        Ok(Self {
            template_id: value.template_id,
            link_id: value.link_id,
            args: value
                .args
                .into_iter()
                .map(|(k, v)| parse_slot_id(k).map(|slot_id| (slot_id, v)))
                .collect::<Result<HashMap<SlotId, String>, Self::Error>>()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct LiteralTemplateLinked {
    template_id: String,
    link_id: String,
    args: HashMap<String, String>,
}

impl From<TemplateLinked> for LiteralTemplateLinked {
    fn from(i: TemplateLinked) -> Self {
        Self {
            template_id: i.template_id,
            link_id: i.link_id,
            args: i
                .args
                .into_iter()
                .map(|(k, v)| (format!("{k}"), v))
                .collect(),
        }
    }
}

/// Given a file containing template links, return a `Vec` of those links
pub(crate) fn load_links_from_file(path: impl AsRef<Path>) -> Result<Vec<TemplateLinked>> {
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => {
            // If the file doesn't exist, then give back the empty entity set
            return Ok(vec![]);
        }
    };
    if f.metadata()
        .into_diagnostic()
        .wrap_err("Failed to read metadata")?
        .len()
        == 0
    {
        // File is empty, return empty set
        Ok(vec![])
    } else {
        // File has contents, deserialize
        serde_json::from_reader(f)
            .into_diagnostic()
            .wrap_err("Deserialization error")
    }
}

pub(crate) fn parse_slot_id<S: AsRef<str>>(s: S) -> Result<SlotId, String> {
    match s.as_ref() {
        "?principal" => Ok(SlotId::principal()),
        "?resource" => Ok(SlotId::resource()),
        _ => Err(format!(
            "Invalid SlotId! Expected ?principal|?resource, got: {}",
            s.as_ref()
        )),
    }
}
