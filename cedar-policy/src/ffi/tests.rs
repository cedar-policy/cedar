#[cfg(test)]
mod ffi_tests {
    #[cfg(feature = "partial-eval")]
    use crate::ffi::is_authorized_partial_json;
    use crate::ffi::{is_authorized_json, validate_json};
    use cool_asserts::assert_matches;

    #[test]
    fn test_fail_unknown_field_policy_slice() {
        let json = serde_json::json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "slice": {
             "policies": {},
             "templatePolicies": {},
             "entities": []
            }
        });

        assert_matches!(is_authorized_json(json), Err(e) => {
            assert_eq!(e.to_string(), "unknown field `slice`, expected one of `principal`, `action`, `resource`, `context`, `schema`, `validateRequest`, `policies`, `entities`");
        });
    }

    #[test]
    fn test_fail_unknown_field_enable_request_validation() {
        let json = serde_json::json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "policies": {},
            "entities": [],
            "enableRequestValidation": true,
        });

        assert_matches!(is_authorized_json(json), Err(e) => {
            assert_eq!(e.to_string(), "unknown field `enableRequestValidation`, expected one of `principal`, `action`, `resource`, `context`, `schema`, `validateRequest`, `policies`, `entities`");
        });
    }

    #[test]
    fn test_fail_unknown_field_policies() {
        let json = serde_json::json!({
            "principal": {
             "type": "User",
             "id": "alice"
            },
            "action": {
             "type": "Photo",
             "id": "view"
            },
            "resource": {
             "type": "Photo",
             "id": "door"
            },
            "context": {},
            "policies": {
              "policies": {}
            },
            "entities": []
        });

        assert_matches!(is_authorized_json(json), Err(e) => {
            assert_eq!(e.to_string(), "unknown field `policies`, expected one of `staticPolicies`, `templates`, `templateLinks`");
        });
    }

    #[cfg(feature = "partial-eval")]
    #[test]
    fn test_fail_unknown_field_partial_evaluation() {
        let json = serde_json::json!({
            "principal": {
                "type": "User",
                "id": "alice"
            },
            "action": {
                "type": "Photo",
                "id": "view"
            },
            "context": {},
            "policies": {
                "staticPolicies": {
                    "ID1": "permit(principal == User::\"alice\", action, resource);"
                }
            },
            "entities": [],
            "partial_evaluation": true
        });

        assert_matches!(is_authorized_partial_json(json), Err(e) => {
            assert_eq!(e.to_string(), "unknown field `partial_evaluation`, expected one of `principal`, `action`, `resource`, `context`, `schema`, `validateRequest`, `policies`, `entities`");
        });
    }

    #[test]
    fn test_fail_unknown_field_validation() {
        let json = serde_json::json!({
          "schema": { "json": { "": {
            "entityTypes": {
              "User": {
                "memberOfTypes": [ ]
              },
              "Photo": {
                "memberOfTypes": [ ]
              }
            },
            "actions": {
              "viewPhoto": {
                "appliesTo": {
                  "resourceTypes": [ "Photo" ],
                  "principalTypes": [ "User" ]
                }
              }
            }
          }}},
          "Policies": "forbid(principal, action, resource);permit(principal == Photo::\"photo.jpg\", action == Action::\"viewPhoto\", resource == User::\"alice\");"
        });

        assert_matches!(validate_json(json), Err(e) => {
            assert_eq!(e.to_string(), "unknown field `Policies`, expected one of `validationSettings`, `schema`, `policies`");
        });
    }
}
