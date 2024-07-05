#[cfg(test)]
mod ffi_tests {
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
            assert!(e.to_string().contains("expected one of"));
        });
    }

    #[test]
    fn test_fail_unknown_field_request() {
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
             "entities": []
            },
            "enableRequestValidation": "foo",
        });

        assert_matches!(is_authorized_json(json), Err(e) => {
            assert!(e.to_string().contains("expected one of"));
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
            assert!(e.to_string().contains("expected one of"));
        });
    }
}
