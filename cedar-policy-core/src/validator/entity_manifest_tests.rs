#[cfg(test)]
mod entity_manifest_tests {
    use crate::validator::entity_manifest::{compute_entity_manifest, EntityManifest, HumanEntityManifest};
    use crate::{
        ast::PolicyID, extensions::Extensions, parser::parse_policy, validator::ValidatorSchema,
    };

    use super::*;

    use std::collections::hash_map::Entry;
    use std::collections::{HashMap, HashSet};
    use std::fmt::{Display, Formatter};
    use std::rc::Rc;

    use crate::ast::{
        self, BinaryOp, EntityUID, Expr, ExprKind, Literal, PolicySet, RequestType, UnaryOp, Var,
    };
    use crate::entities::err::EntitiesError;
    use miette::Diagnostic;
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use smol_str::SmolStr;
    use thiserror::Error;


    use crate::validator::entity_manifest::analysis::{
        EntityManifestAnalysisResult, WrappedAccessPaths,
    };
    use crate::validator::{
        typecheck::{PolicyCheck, Typechecker},
        types::Type,
        ValidationMode, 
    };
    use crate::validator::{ValidationResult, Validator};

    // Schema for testing in this module
    fn schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            "
entity User = {
  name: String,
};

entity Document;

action Read appliesTo {
  principal: [User],
  resource: [Document]
};
    ",
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    fn document_fields_schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            "
entity User = {
name: String,
};

entity Document = {
owner: User,
viewer: User,
};

action Read appliesTo {
principal: [User],
resource: [Document]
};
",
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    #[test]
    fn test_simple_entity_manifest() {
        let mut pset = PolicySet::new();
        let policy = parse_policy(
            None,
            r#"permit(principal, action, resource)
when {
    principal.name == "John"
};"#,
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let validator = Validator::new(schema());

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json! ({
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "name",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                      "isAncestor": false
                    }
                  ]
                ]
              }
            ]
          ]
        });
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_empty_entity_manifest() {
        let mut pset = PolicySet::new();
        let policy =
            parse_policy(None, "permit(principal, action, resource);").expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let validator = Validator::new(schema());

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");

        // Define the human manifest using the json! macro
        let human_json = serde_json::json!({
            "perAction": {
                "User::Action::\"Read\"::Document": []
            }
        });

        // Convert the JSON value to a HumanEntityManifest
        let human_manifest: HumanEntityManifest = serde_json::from_value(human_json).unwrap();

        // Convert the human manifest to an EntityManifest
        let expected_manifest = human_manifest
            .to_entity_manifest(validator.schema())
            .unwrap();

        // Compare the computed manifest with the expected manifest
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_ancestors_required() {
        let mut pset = PolicySet::new();
        let policy = parse_policy(
            None,
            "permit(principal, action, resource)
when {
    principal in resource || principal.manager in resource
};",
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = ValidatorSchema::from_cedarschema_str(
            "
entity User in [Document] = {
  name: String,
  manager: User
};
entity Document;
action Read appliesTo {
  principal: [User],
  resource: [Document]
};
  ",
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        let validator = Validator::new(schema);

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json!(
        {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "manager",
                          {
                            "children": [],
                            "ancestorsTrie": {
                              "trie": [
                                [
                                  {
                                    "var": "resource",
                                  },
                                  {
                                    "children": [],
                                    "isAncestor": true,
                                    "ancestorsTrie": { "trie": [] }
                                  }
                                ]
                              ]
                            },
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": {
                              "trie": [
                                [
                                  {
                                    "var": "resource",
                                  },
                                  {
                                    "children": [],
                                    "isAncestor": true,
                                    "ancestorsTrie": { "trie": [] }
                                  }
                                ]
                              ]
                            },
                      "isAncestor": false
                    }
                  ]
                ]
              }
            ]
          ]
        });
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_multiple_types() {
        let mut pset = PolicySet::new();
        let policy = parse_policy(
            None,
            r#"permit(principal, action, resource)
when {
    principal.name == "John"
};"#,
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = ValidatorSchema::from_cedarschema_str(
            "
entity User = {
  name: String,
};

entity OtherUserType = {
  name: String,
  irrelevant: String,
};

entity Document;

action Read appliesTo {
  principal: [User, OtherUserType],
  resource: [Document]
};
        ",
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        let validator = Validator::new(schema);

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json!(
        {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "name",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                      "isAncestor": false
                    }
                  ]
                ]
              }
            ],
            [
              {
                "principal": "OtherUserType",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "name",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                      "isAncestor": false
                    }
                  ]
                ]
              }
            ]
          ]
            });
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_multiple_branches() {
        let mut pset = PolicySet::new();
        let policy1 = parse_policy(
            None,
            r#"
permit(
  principal,
  action == Action::"Read",
  resource
)
when
{
  resource.readers.contains(principal)
};"#,
        )
        .unwrap();
        let policy2 = parse_policy(
            Some(PolicyID::from_string("Policy2")),
            r#"permit(
  principal,
  action == Action::"Read",
  resource
)
when
{
  resource.metadata.owner == principal
};"#,
        )
        .unwrap();
        pset.add(policy1.into()).expect("should succeed");
        pset.add(policy2.into()).expect("should succeed");

        let schema = ValidatorSchema::from_cedarschema_str(
            "
entity User;

entity Metadata = {
   owner: User,
   time: String,
};

entity Document = {
  metadata: Metadata,
  readers: Set<User>,
};

action Read appliesTo {
  principal: [User],
  resource: [Document]
};
        ",
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        let validator = Validator::new(schema);

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json!(
        {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "resource"
                    },
                    {
                      "children": [
                        [
                          "metadata",
                          {
                            "children": [
                              [
                                "owner",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ]
                            ],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ],
                        [
                          "readers",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                      "isAncestor": false
                    }
                  ],
                ]
              }
            ]
          ]
        });
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_struct_equality() {
        let mut pset = PolicySet::new();
        // we need to load all of the metadata, not just nickname
        // no need to load actual name
        let policy = parse_policy(
            None,
            r#"permit(principal, action, resource)
when {
    principal.metadata.nickname == "timmy" && principal.metadata == {
        "friends": [ "oliver" ],
        "nickname": "timmy"
    }
};"#,
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = ValidatorSchema::from_cedarschema_str(
            "
entity User = {
  name: String,
  metadata: {
    friends: Set<String>,
    nickname: String,
  },
};

entity Document;

action BeSad appliesTo {
  principal: [User],
  resource: [Document]
};
        ",
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        let validator = Validator::new(schema);

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json!(
        {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "BeSad"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "metadata",
                          {
                            "children": [
                              [
                                "nickname",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ],
                              [
                                "friends",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ]
                            ],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                      "isAncestor": false
                    }
                  ]
                ]
              }
            ]
          ]
        });
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_struct_equality_left_right_different() {
        let mut pset = PolicySet::new();
        // we need to load all of the metadata, not just nickname
        // no need to load actual name
        let policy = parse_policy(
            None,
            r#"permit(principal, action, resource)
when {
    principal.metadata == resource.metadata
};"#,
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = ValidatorSchema::from_cedarschema_str(
            "
entity User = {
  name: String,
  metadata: {
    friends: Set<String>,
    nickname: String,
  },
};

entity Document;

action Hello appliesTo {
  principal: [User],
  resource: [User]
};
        ",
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        let validator = Validator::new(schema);

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json!(
        {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Hello"
                },
                "resource": "User"
              },
              {
                "trie": [
                  [
                    {
                      "var": "resource"
                    },
                    {
                      "children": [
                        [
                          "metadata",
                          {
                            "children": [
                              [
                                "friends",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ],
                              [
                                "nickname",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ]
                            ],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                    }
                  ],
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "metadata",
                          {
                            "children": [
                              [
                                "nickname",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ],
                              [
                                "friends",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ]
                            ],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                      "isAncestor": false
                    }
                  ]
                ]
              }
            ]
          ]
        });
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_with_if() {
        let mut pset = PolicySet::new();

        let validator = Validator::new(document_fields_schema());

        let policy = parse_policy(
            None,
            r#"permit(principal, action, resource)
when {
    if principal.name == "John"
    then resource.owner.name == User::"oliver".name
    else resource.viewer == User::"oliver"
};"#,
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json! ( {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "name",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                    }
                  ],
                  [
                    {
                      "literal": {
                        "ty": "User",
                        "eid": "oliver"
                      }
                    },
                    {
                      "children": [
                        [
                          "name",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                    }
                  ],
                  [
                    {
                      "var": "resource"
                    },
                    {
                      "children": [
                        [
                          "viewer",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ],
                        [
                          "owner",
                          {
                            "children": [
                              [
                                "name",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                                }
                              ]
                            ],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                    }
                  ]
                ]
              }
            ]
          ]
        }
        );
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }

    #[test]
    fn test_entity_manifest_if_literal_record() {
        let mut pset = PolicySet::new();

        let validator = Validator::new(document_fields_schema());

        let policy = parse_policy(
            None,
            r#"permit(principal, action, resource)
when {
    {
      "myfield":
          {
            "secondfield":
            if principal.name == "yihong"
            then principal
            else resource.owner,
            "ignored but still important due to errors":
            resource.viewer
          }
    }["myfield"]["secondfield"].name == "pavel"
};"#,
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let entity_manifest = compute_entity_manifest(&validator, &pset).expect("Should succeed");
        let expected = serde_json::json! ( {
          "perAction": [
            [
              {
                "principal": "User",
                "action": {
                  "ty": "Action",
                  "eid": "Read"
                },
                "resource": "Document"
              },
              {
                "trie": [
                  [
                    {
                      "var": "principal"
                    },
                    {
                      "children": [
                        [
                          "name",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                    }
                  ],
                  [
                    {
                      "var": "resource"
                    },
                    {
                      "children": [
                        [
                          "viewer",
                          {
                            "children": [],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ],
                        [
                          "owner",
                          {
                            "children": [
                              [
                                "name",
                                {
                                  "children": [],
                                  "ancestorsTrie": { "trie": []},
                                  "isAncestor": false
                                }
                              ]
                            ],
                            "ancestorsTrie": { "trie": []},
                            "isAncestor": false
                          }
                        ]
                      ],
                      "ancestorsTrie": { "trie": []},
                      "isAncestor": false
                    }
                  ]
                ]
              }
            ]
          ]
        }
        );
        let expected_manifest =
            EntityManifest::from_json_value(expected, validator.schema()).unwrap();
        assert_eq!(entity_manifest, expected_manifest);
    }
}
