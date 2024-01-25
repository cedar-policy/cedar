use cedar_wasm::*;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn test_get_cedar_version() {
    let version = get_cedar_version();
    assert_eq!(version, std::env!("CEDAR_VERSION").to_string());
}

#[wasm_bindgen_test]
fn test_is_authorized() {
    let principal = r#"User::"alice""#;
    let action = r#"Action::"read""#;
    let resource = r#"Photo::"foo.jpg""#;
    let context = r#"{}"#;
    let policies = r#"
            permit(
                principal == User::"alice",
                action    in [Action::"read", Action::"edit"],
                resource  == Photo::"foo.jpg"
            );
        "#;
    let entities = r#"[]"#;

    let result = is_authorized(principal, action, resource, context, policies, entities);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();
    let data = json["data"].clone();

    assert_eq!(json["code"], 0);
    assert_eq!(data["decision"], "Allow");
    assert_eq!(data["reasons"], serde_json::json!(["policy0"]));
    assert_eq!(data["errors"], serde_json::json!([]));
}

#[wasm_bindgen_test]
fn test_is_authorized_principal_err() {
    let principal = r#"User:"alice""#;
    let action = r#"Action::"read""#;
    let resource = r#"Photo::"foo.jpg""#;
    let context = r#"{}"#;
    let policies = r#"
            permit(
                principal == User::"alice",
                action    in [Action::"read", Action::"edit"],
                resource  == Photo::"foo.jpg"
            );
        "#;
    let entities = r#"[]"#;

    let result = is_authorized(principal, action, resource, context, policies, entities);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 101);
    assert_eq!(json["message"], "[PrincipalErr]: unexpected token `:`");
}

#[wasm_bindgen_test]
fn test_is_authorized_action_err() {
    let principal = r#"User::"alice""#;
    let action = r#"Action:"read""#;
    let resource = r#"Photo::"foo.jpg""#;
    let context = r#"{}"#;
    let policies = r#"
            permit(
                principal == User::"alice",
                action    in [Action::"read", Action::"edit"],
                resource  == Photo::"foo.jpg"
            );
        "#;
    let entities = r#"[]"#;

    let result = is_authorized(principal, action, resource, context, policies, entities);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 102);
    assert_eq!(json["message"], "[ActionErr]: unexpected token `:`");
}

#[wasm_bindgen_test]
fn test_is_authorized_resource_err() {
    let principal = r#"User::"alice""#;
    let action = r#"Action::"read""#;
    let resource = r#"Photo:"foo.jpg""#;
    let context = r#"{}"#;
    let policies = r#"
            permit(
                principal == User::"alice",
                action    in [Action::"read", Action::"edit"],
                resource  == Photo::"foo.jpg"
            );
        "#;
    let entities = r#"[]"#;

    let result = is_authorized(principal, action, resource, context, policies, entities);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 103);
    assert_eq!(json["message"], "[ResourceErr]: unexpected token `:`");
}

#[wasm_bindgen_test]
fn test_is_authorized_context_err() {
    let principal = r#"User::"alice""#;
    let action = r#"Action::"read""#;
    let resource = r#"Photo::"foo.jpg""#;
    let context = r#"[]"#;
    let policies = r#"
            permit(
                principal == User::"alice",
                action    in [Action::"read", Action::"edit"],
                resource  == Photo::"foo.jpg"
            );
        "#;
    let entities = r#"[]"#;

    let result = is_authorized(principal, action, resource, context, policies, entities);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 104);
    assert_eq!(
        json["message"],
        "[ContextErr]: expression is not a record: `[]`"
    );
}

#[wasm_bindgen_test]
fn test_is_authorized_policies_err() {
    let principal = r#"User::"alice""#;
    let action = r#"Action::"read""#;
    let resource = r#"Photo::"foo.jpg""#;
    let context = r#"{}"#;
    let policies = r#"
            permit(
                principal == User:"alice",
                action    in [Action::"read", Action::"edit"],
                resource  == Photo::"foo.jpg"
            );
        "#;
    let entities = r#"[]"#;

    let result = is_authorized(principal, action, resource, context, policies, entities);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 105);
    assert_eq!(json["message"], "[PoliciesErr]: unexpected token `:`");
}

#[wasm_bindgen_test]
fn test_is_authorized_entities_err() {
    let principal = r#"User::"alice""#;
    let action = r#"Action::"read""#;
    let resource = r#"Photo::"foo.jpg""#;
    let context = r#"{}"#;
    let policies = r#"
            permit(
                principal == User::"alice",
                action    in [Action::"read", Action::"edit"],
                resource  == Photo::"foo.jpg"
            );
        "#;
    let entities = r#"{}"#;

    let result = is_authorized(principal, action, resource, context, policies, entities);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 106);
    assert_eq!(json["message"], "[EntitiesErr]: error during entity deserialization: invalid type: map, expected a sequence at line 1 column 0");
}

#[wasm_bindgen_test]
fn test_validate_ok() {
    let schema = r#"
            {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr"
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "employeeId": {
                                        "type": "String",
                                        "required": true
                                    },
                                    "personInfo": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "Album"
                            ]
                        },
                        "Album": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "createPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "listPhotos": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        "#;
    let policy = r#"
            permit(
                principal in PhotoApp::UserGroup::"janeFriends",
                action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"], 
                resource in PhotoApp::Album::"janeTrips"
            );
        "#;

    let result = validate(schema, policy);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 0);
    assert_eq!(json["data"], "no errors or warnings");
}

#[wasm_bindgen_test]
fn test_validate_fail() {
    let schema = r#"
            {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr"
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "employeeId": {
                                        "type": "String",
                                        "required": true
                                    },
                                    "personInfo": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "Album"
                            ]
                        },
                        "Album": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "createPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "listPhotos": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        "#;
    let policy = r#"
            permit(
                principal in PhotoApp::UserGroup1::"janeFriends",
                action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"], 
                resource in PhotoApp::Album::"janeTrips"
            );
        "#;

    let result = validate(schema, policy);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 0);
    assert_eq!(
        json["data"],
        "validation error on policy `policy0`: unrecognized entity type `PhotoApp::UserGroup1`"
    );
}

#[wasm_bindgen_test]
fn test_validate_schema_json_err() {
    let schema = r#"
            {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        }
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr"
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "employeeId": {
                                        "type": "String",
                                        "required": true
                                    },
                                    "personInfo": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "Album"
                            ]
                        },
                        "Album": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "createPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "listPhotos": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        "#;
    let policy = r#"
            permit(
                principal in PhotoApp::UserGroup::"janeFriends",
                action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"],
                resource in PhotoApp::Album::"janeTrips"
            );
        "#;

    let result = validate(schema, policy);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 201);
    assert_eq!(
        json["message"],
        "[SchemaErr]: failed to parse schema: expected `,` or `}` at line 16 column 25"
    );
}

#[wasm_bindgen_test]
fn test_validate_on_schema_err() {
    let schema = r#"
            {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr"
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "employeeId": {
                                        "type": "String",
                                        "required": true
                                    },
                                    "personInfo": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "Album"
                            ]
                        },
                        "Album": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "createPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "listPhotos": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        "#;
    let policy = r#"
            permit(
                principal in PhotoApp::UserGroup::"janeFriends",
                action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"], 
                resource in PhotoApp::Album::"janeTrips"
            );
        "#;

    let result = validate(schema, policy);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 201);
    assert_eq!(
        json["message"],
        "[SchemaErr]: failed to parse schema: missing field `type` at line 14 column 25"
    );
}

#[wasm_bindgen_test]
fn test_validate_policy_err() {
    let schema = r#"
            {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr"
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "employeeId": {
                                        "type": "String",
                                        "required": true
                                    },
                                    "personInfo": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "Album"
                            ]
                        },
                        "Album": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "createPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "listPhotos": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        "#;
    let policy = r#"
            permit(
                principal in PhotoApp:UserGroup::"janeFriends",
                action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"], 
                resource in PhotoApp::Album::"janeTrips"
            );
        "#;

    let result = validate(schema, policy);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 202);
    assert_eq!(json["message"], "[PolicyErr]: unexpected token `:`");
}

#[wasm_bindgen_test]
fn test_policy_to_json() {
    let policy = r#"
            permit(
                principal in PhotoApp::UserGroup::"janeFriends",
                action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"], 
                resource in PhotoApp::Album::"janeTrips"
            );
        "#;

    let result = policy_to_json(policy);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 0);
    assert_eq!(
            json["data"].to_string(),
            "{\"effect\":\"permit\",\"principal\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::UserGroup\",\"id\":\"janeFriends\"}},\"action\":{\"op\":\"in\",\"entities\":[{\"type\":\"PhotoApp::Action\",\"id\":\"viewPhoto\"},{\"type\":\"PhotoApp::Action\",\"id\":\"listPhotos\"}]},\"resource\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::Album\",\"id\":\"janeTrips\"}},\"conditions\":[]}"
        );
}

#[wasm_bindgen_test]
fn test_policy_to_json_err() {
    let policy = r#"
            permit(
                principal in PhotoApp:UserGroup::"janeFriends",
                action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"], 
                resource in PhotoApp::Album::"janeTrips"
            );
        "#;

    let result = policy_to_json(policy);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 301);
    assert_eq!(json["message"], "[PolicyErr]: unexpected token `:`");
}

#[wasm_bindgen_test]
fn test_policy_from_json() {
    let policy = "{\"effect\":\"permit\",\"principal\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::UserGroup\",\"id\":\"janeFriends\"}},\"action\":{\"op\":\"in\",\"entities\":[{\"type\":\"PhotoApp::Action\",\"id\":\"viewPhoto\"},{\"type\":\"PhotoApp::Action\",\"id\":\"listPhotos\"}]},\"resource\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::Album\",\"id\":\"janeTrips\"}},\"conditions\":[]}";

    let result = policy_from_json(policy);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 0);
    assert_eq!(
            json["data"].to_string(),
            "\"permit(principal in PhotoApp::UserGroup::\\\"janeFriends\\\", action in [PhotoApp::Action::\\\"viewPhoto\\\", PhotoApp::Action::\\\"listPhotos\\\"], resource in PhotoApp::Album::\\\"janeTrips\\\");\""
        );
}

#[wasm_bindgen_test]
fn test_policy_from_json_policy_json_err() {
    let policy = "{\"effect\"\"permit\",\"principal\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::UserGroup\",\"id\":\"janeFriends\"}},\"action\":{\"op\":\"in\",\"entities\":[{\"type\":\"PhotoApp::Action\",\"id\":\"viewPhoto\"},{\"type\":\"PhotoApp::Action\",\"id\":\"listPhotos\"}]},\"resource\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::Album\",\"id\":\"janeTrips\"}},\"conditions\":[]}";

    let result = policy_from_json(policy);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 401);
    assert_eq!(
        json["message"],
        "[PolicyJsonErr]: expected `:` at line 1 column 10"
    );
}

#[wasm_bindgen_test]
fn test_policy_from_json_policy_err() {
    let policy = "{\"principal\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::UserGroup\",\"id\":\"janeFriends\"}},\"action\":{\"op\":\"in\",\"entities\":[{\"type\":\"PhotoApp::Action\",\"id\":\"viewPhoto\"},{\"type\":\"PhotoApp::Action\",\"id\":\"listPhotos\"}]},\"resource\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::Album\",\"id\":\"janeTrips\"}},\"conditions\":[]}";

    let result = policy_from_json(policy);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 402);
    assert_eq!(json["message"], "[PolicyErr]: missing field `effect`");
}

#[wasm_bindgen_test]
fn test_validate_schema_ok() {
    let schema = r#"
            {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr"
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "employeeId": {
                                        "type": "String",
                                        "required": true
                                    },
                                    "personInfo": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "Album"
                            ]
                        },
                        "Album": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "createPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "listPhotos": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        "#;

    let result = validate_schema(schema);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 0);
    assert_eq!(json["data"], "no errors or warnings");
}

#[wasm_bindgen_test]
fn test_validate_schema_err() {
    let schema = r#"
            {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        }
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr"
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "employeeId": {
                                        "type": "String",
                                        "required": true
                                    },
                                    "personInfo": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "Album"
                            ]
                        },
                        "Album": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "createPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "listPhotos": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        "#;

    let result = validate_schema(schema);
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(json["code"], 501);
    assert_eq!(
        json["message"],
        "[SchemaErr]: failed to parse schema: expected `,` or `}` at line 16 column 25"
    );
}
