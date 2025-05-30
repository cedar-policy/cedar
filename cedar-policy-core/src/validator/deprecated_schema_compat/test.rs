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

//! Test that a successful parse gives us the expected result. Test in this
//! crate so we can compare the actual constructed schema data structures. Error
//! cases are tested from the public API.

use crate::validator::json_schema::Fragment;

// This property unfortunately does not hold in general. If a JSON value parses
// with in both modes, then the resulting `Fragments` could be different if the
// 2.5.x compatible parser ignores an attribute which is used by main schema
// parsers. This specifically affects types containing annotations.
#[track_caller]
fn assert_parses_to_same_fragment(schema: serde_json::Value) {
    let deprecated_parse = Fragment::from_deprecated_json_value(schema.clone()).unwrap();
    let current_parse = Fragment::from_json_value(schema).unwrap();
    assert_eq!(deprecated_parse, current_parse);
}

#[test]
fn empty() {
    assert_parses_to_same_fragment(serde_json::json!({}));
}

#[test]
fn empty_string_ns() {
    assert_parses_to_same_fragment(serde_json::json!({
        "": {
            "entityTypes": {},
            "actions": {},
        }
    }));
}

#[test]
fn multiple_namespace() {
    assert_parses_to_same_fragment(serde_json::json!({
        "ns0": {
            "entityTypes": {},
            "actions": {},
        },
        "ns1": {
            "entityTypes": {},
            "actions": {},
        },
        "ns2": {
            "entityTypes": {},
            "actions": {},
        }
    }));
}

#[test]
fn declared_common_types() {
    assert_parses_to_same_fragment(serde_json::json!({
        "ns": {
            "commonTypes": {
                "foo": {"type": "Bool"},
                "bar": {"type": "foo"},
                "baz": {"type": "Long"},
            },
            "entityTypes": {},
            "actions": {},
        }
    }));
}

#[test]
fn member_of_types() {
    assert_parses_to_same_fragment(serde_json::json!({
        "ns": {
            "entityTypes": {
                "User": { "memberOfTypes": ["Group1", "Group2"] },
                "Group1": { },
                "Group2": { }
            },
            "actions": { }
        }
    }));
}

#[test]
fn entity_shape() {
    assert_parses_to_same_fragment(serde_json::json!({
        "ns": {
            "entityTypes": {
                "User": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "foo": {"type": "String"},
                            "bar": {"type": "Entity", "name": "User"}
                        }
                    }
                },
            },
            "actions": { }
        }
    }));
}

#[test]
fn member_of() {
    assert_parses_to_same_fragment(serde_json::json!({
        "ns": {
            "entityTypes": {},
            "actions": {
                "foo": { "memberOf": [{"type": "Action", "id": "foo"}, {"id": "baz"}] },
                "bar": {},
                "baz": {},
            },
        }
    }));
}

#[test]
fn applies_to() {
    assert_parses_to_same_fragment(serde_json::json!({
        "ns": {
            "entityTypes": {
                "User": {}
            },
            "actions": {
                "foo": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["User"],
                    }
                }
            },
        }
    }));
}

#[test]
fn context() {
    assert_parses_to_same_fragment(serde_json::json!({
        "ns": {
            "entityTypes": { },
            "actions": {
                "foo": {
                    "appliesTo": {
                        "principalTypes": [],
                        "resourceTypes": [],
                        "context": {
                            "type": "Record",
                            "attributes": {
                                "foo": {
                                    "type": "Set",
                                    "element": {"type": "Extension", "name": "ip"},
                                    "required": false,
                                }
                            }
                        }
                    }
                }
            },
        }
    }));
}
