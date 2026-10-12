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

//! Request environment pruning in `Typechecker::typecheck_policy` must not
//! change its result. Each test typechecks a corpus of policies and templates
//! with and without pruning and requires the same return value, errors and
//! warnings.

use std::collections::HashSet;

use crate::ast::PolicyID;
use crate::parser::parse_policy_or_template;
#[cfg(feature = "partial-validate")]
use crate::validator::{json_schema, RawName};
use crate::validator::{
    typecheck::Typechecker, ValidationError, ValidationMode, ValidationWarning, ValidatorSchema,
};

use super::test_utils::SchemaProvider;

const SCHEMA: &str = r#"
entity Group;
entity User in [Group] { name: String, level?: Long };
entity Admin in [Group] { level: Long };
entity Service;
entity Folder in [Folder];
entity Doc in [Folder] { owner: User, tags: Set<String> };
entity Photo in [Folder] { owner: Admin };
entity Color enum ["red", "green"];
action Admins;
action read in [Admins] appliesTo {
    principal: [User, Admin],
    resource: [Doc, Photo],
    context: { flag: Bool }
};
action write in [Admins] appliesTo {
    principal: [User],
    resource: [Doc],
    context: {}
};
action deploy appliesTo {
    principal: [Service],
    resource: [Folder, Doc],
    context: { region: String }
};
action paint appliesTo {
    principal: [User, Service],
    resource: [Color],
    context: {}
};
"#;

/// Principal scopes, including every slot constraint kind the grammar allows.
const PRINCIPALS: &[&str] = &[
    "principal",
    r#"principal == User::"a""#,
    r#"principal in Group::"g""#,
    "principal is User",
    r#"principal is Admin in Group::"g""#,
    "principal is Service",
    r#"principal in Folder::"f""#,
    "principal == ?principal",
    "principal in ?principal",
    "principal is User in ?principal",
    "principal is Service in ?principal",
    r#"principal == Nope::"x""#,
    r#"principal in Color::"red""#,
];

const ACTIONS: &[&str] = &[
    "action",
    r#"action == Action::"read""#,
    r#"action == Action::"deploy""#,
    r#"action in [Action::"read", Action::"deploy"]"#,
    r#"action in Action::"Admins""#,
    r#"action == Action::"nope""#,
    r#"action in [Action::"nope", Action::"paint"]"#,
];

const RESOURCES: &[&str] = &[
    "resource",
    r#"resource == Doc::"d""#,
    r#"resource in Folder::"f""#,
    "resource is Doc",
    r#"resource is Photo in Folder::"f""#,
    "resource is Color",
    r#"resource == Color::"blue""#,
    "resource == ?resource",
    "resource in ?resource",
    "resource is Doc in ?resource",
    "resource is Color in ?resource",
    r#"resource == Nope::"y""#,
];

/// Conditions that type differently, or fail, across environments.
const BODIES: &[&str] = &[
    "",
    r#"when { principal.name == "x" }"#,
    "when { resource.owner == principal }",
    "when { context.flag }",
    r#"when { context.region like "us-*" }"#,
    r#"when { 1 + "a" }"#,
    "when { false }",
    "when { principal has level && principal.level > 1 }",
    r#"when { resource.tags.contains("x") } unless { principal is Admin }"#,
    r#"when { principal == Color::"blue" }"#,
    "when { principal in resource }",
];

type Outcome = (bool, HashSet<ValidationError>, HashSet<ValidationWarning>);

fn typecheck(schema: &ValidatorSchema, mode: ValidationMode, src: &str, prune: bool) -> Outcome {
    let t = parse_policy_or_template(Some(PolicyID::from_string("p")), src)
        .unwrap_or_else(|e| panic!("failed to parse {src}: {e:?}"));
    let mut errors = HashSet::new();
    let mut warnings = HashSet::new();
    let ok = Typechecker::new(schema, mode).typecheck_policy_pruned(
        &t,
        &mut errors,
        &mut warnings,
        prune,
    );
    (ok, errors, warnings)
}

/// Every combination of scope and condition from the lists above.
fn corpus() -> impl Iterator<Item = String> {
    PRINCIPALS.iter().flat_map(|p| {
        ACTIONS.iter().flat_map(move |a| {
            RESOURCES.iter().flat_map(move |r| {
                BODIES
                    .iter()
                    .map(move |b| format!("permit({p}, {a}, {r}) {b};"))
            })
        })
    })
}

fn modes() -> Vec<ValidationMode> {
    vec![
        ValidationMode::Strict,
        ValidationMode::Permissive,
        #[cfg(feature = "partial-validate")]
        ValidationMode::Partial,
    ]
}

/// Asserts pruning is invisible for every corpus entry, and returns how many
/// entries produced each kind of outcome so callers can check the corpus
/// actually exercises them.
#[track_caller]
fn assert_pruning_exact(schema: &ValidatorSchema, mode: ValidationMode) -> OutcomeCounts {
    let mut counts = OutcomeCounts::default();
    for src in corpus() {
        let unpruned = typecheck(schema, mode, &src, false);
        let pruned = typecheck(schema, mode, &src, true);
        assert_eq!(
            unpruned, pruned,
            "pruning changed the result in {mode:?} mode for: {src}"
        );
        let (ok, errors, warnings) = unpruned;
        counts.passed += usize::from(ok);
        counts.with_errors += usize::from(!errors.is_empty());
        counts.impossible += usize::from(!warnings.is_empty());
    }
    counts
}

#[derive(Debug, Default)]
struct OutcomeCounts {
    passed: usize,
    with_errors: usize,
    impossible: usize,
}

impl OutcomeCounts {
    #[track_caller]
    fn assert_all_kinds(&self) {
        assert!(self.passed > 0, "{self:?}");
        assert!(self.with_errors > 0, "{self:?}");
        assert!(self.impossible > 0, "{self:?}");
    }
}

#[test]
fn pruning_is_exact_in_every_mode() {
    let schema = SCHEMA.schema();
    for mode in modes() {
        assert_pruning_exact(&schema, mode).assert_all_kinds();
    }
}

/// Partial validation with entity types that allow undeclared attributes, and
/// an action with no declared context.
#[cfg(feature = "partial-validate")]
#[test]
fn pruning_is_exact_with_partial_schema() {
    let fragment: json_schema::Fragment<RawName> = serde_json::from_value(serde_json::json!({
        "": {
            "entityTypes": {
                "Group": {},
                "User": {
                    "memberOfTypes": ["Group"],
                    "shape": {
                        "type": "Record",
                        "attributes": { "name": { "type": "String" } },
                        "additionalAttributes": true
                    }
                },
                "Admin": { "memberOfTypes": ["Group"] },
                "Service": {},
                "Folder": { "memberOfTypes": ["Folder"] },
                "Doc": {
                    "memberOfTypes": ["Folder"],
                    "shape": {
                        "type": "Record",
                        "attributes": {},
                        "additionalAttributes": true
                    }
                },
                "Photo": { "memberOfTypes": ["Folder"] }
            },
            "actions": {
                "Admins": {},
                "read": {
                    "memberOf": [{ "id": "Admins" }],
                    "appliesTo": {
                        "principalTypes": ["User", "Admin"],
                        "resourceTypes": ["Doc", "Photo"]
                    }
                },
                "deploy": {
                    "appliesTo": {
                        "principalTypes": ["Service"],
                        "resourceTypes": ["Folder", "Doc"]
                    }
                }
            }
        }
    }))
    .unwrap();
    let schema = fragment.schema();
    assert_pruning_exact(&schema, ValidationMode::Partial).assert_all_kinds();
}
