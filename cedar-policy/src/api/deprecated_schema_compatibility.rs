use cedar_policy_core::extensions::Extensions;
use cedar_policy_validator::SchemaError;

use super::{Schema, SchemaFragment};

impl SchemaFragment {
    /// Create a [`SchemaFragment`] from a string containing JSON in the
    /// deprecated JSON schema format used for versions 2.5.0 and earlier of
    /// this library. Most callers should use [`SchemaFragment::from_json_str`]
    /// instead.
    #[deprecated(since = "4.5.0", note = "use `SchemaFragment::from_json_str` instead")]
    pub fn from_deprecated_json_str(src: &str) -> Result<Self, SchemaError> {
        let lossless =
            cedar_policy_validator::json_schema::Fragment::from_json_str_ignore_unknown_type_fields(src)?;
        Ok(Self {
            value: lossless.clone().try_into()?,
            lossless,
        })
    }

    /// Create a [`SchemaFragment`] from a JSON value in shape of the deprecated
    /// JSON schema format used for versions 2.5.0 and earlier of this library.
    /// Most callers should use [`SchemaFragment::from_json_value`] instead.
    #[deprecated(
        since = "4.5.0",
        note = "use `SchemaFragment::from_json_value` instead"
    )]
    pub fn from_deprecated_json_value(json: serde_json::Value) -> Result<Self, SchemaError> {
        let lossless = cedar_policy_validator::json_schema::Fragment::from_json_value_ignore_unknown_type_fields(json)?;
        Ok(Self {
            value: lossless.clone().try_into()?,
            lossless,
        })
    }

    /// Create a [`SchemaFragment`] directly from a JSON file containing JSON in
    /// the deprecated JSON schema format used for versions 2.5.0 and earlier of
    /// this library. Most callers should use [`SchemaFragment::from_json_file`]
    /// instead.
    #[deprecated(since = "4.5.0", note = "use `SchemaFragment::from_json_file` instead")]
    pub fn from_deprecated_json_file(file: impl std::io::Read) -> Result<Self, SchemaError> {
        let lossless = cedar_policy_validator::json_schema::Fragment::from_json_file_ignore_unknown_type_fields(file)?;
        Ok(Self {
            value: lossless.clone().try_into()?,
            lossless,
        })
    }
}

impl Schema {
    /// Create a [`Schema`] from a string containing JSON in the
    /// deprecated JSON schema format used for versions 2.5.0 and earlier of
    /// this library. Most callers should use [`Schema::from_json_str`]
    /// instead.
    #[deprecated(since = "4.5.0", note = "use `Schema::from_json_str` instead")]
    pub fn from_deprecated_json_value(json: serde_json::Value) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_validator::ValidatorSchema::from_json_value_ignore_unknown_type_fields(
                json,
                Extensions::all_available(),
            )?,
        ))
    }

    /// Create a [`Schema`] from a JSON value in shape of the deprecated
    /// JSON schema format used for versions 2.5.0 and earlier of this library.
    /// Most callers should use [`Schema::from_json_value`] instead.
    #[deprecated(since = "4.5.0", note = "use `Schema::from_json_value` instead")]
    pub fn from_deprecated_json_str(json: &str) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_validator::ValidatorSchema::from_json_str_ignore_unknown_type_fields(
                json,
                Extensions::all_available(),
            )?,
        ))
    }

    /// Create a [`Schema`] directly from a JSON file containing JSON in
    /// the deprecated JSON schema format used for versions 2.5.0 and earlier of
    /// this library. Most callers should use [`Schema::from_json_file`]
    /// instead.
    #[deprecated(since = "4.5.0", note = "use `Schema::from_json_file` instead")]
    pub fn from_deprecated_json_file(file: impl std::io::Read) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_validator::ValidatorSchema::from_json_file_ignore_unknown_type_fields(
                file,
                Extensions::all_available(),
            )?,
        ))
    }
}

/// These tests assert that specific unknown fields are allowed in the
/// compatibility mode, but not allowed in the standard schema parsing mode.
#[cfg(test)]
#[allow(deprecated)]
mod extra_fields_allowed {
    use cedar_policy_core::test_utils::{expect_err, ExpectedErrorMessageBuilder};
    use miette::Report;
    use serde_json::json;

    use crate::Schema;

    fn schema_with_entity_attribute(attr_ty: serde_json::Value) -> serde_json::Value {
        json!({
            "ns": {
                "commonTypes": {"ty": {"type": "Long"}},
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "foo": attr_ty,
                            },
                        },
                    }
                },
                "actions": {},
            }
        })
    }

    fn schema_with_entity_tag(attr_ty: serde_json::Value) -> serde_json::Value {
        json!({
            "ns": {
                "commonTypes": {"ty": {"type": "Long"}},
                "entityTypes": {
                    "User": { "tags": attr_ty, }
                },
                "actions": {},
            }
        })
    }

    fn schema_with_context_attribute(attr_ty: serde_json::Value) -> serde_json::Value {
        json!({
            "ns": {
                "commonTypes": {"ty": {"type": "Long"}},
                "entityTypes": {
                    "User": {}
                },
                "actions": {
                    "Act": {
                        "appliesTo": {
                            "principalTypes": [],
                            "resourceTypes": [],
                            "context": {
                                "type": "Record",
                                "attributes": {
                                    "foo": attr_ty,
                                },
                            }
                        }
                    }
                },
            }
        })
    }

    fn schema_with_common_type(ty: serde_json::Value) -> serde_json::Value {
        json!({
            "ns": {
                "commonTypes": {
                    "ty": {"type": "Long"},
                    "ty2": ty,
                },
                "entityTypes": {
                    "User": {}
                },
                "actions": {},
            }
        })
    }

    #[track_caller]
    fn assert_ok_deprecated_and_err_standard(ty: serde_json::Value, err: &str) {
        let in_entity_attr = schema_with_entity_attribute(ty.clone());
        Schema::from_deprecated_json_value(in_entity_attr.clone()).unwrap();
        expect_err(
            "",
            &Report::new(Schema::from_json_value(in_entity_attr).unwrap_err()),
            &ExpectedErrorMessageBuilder::error(err).build(),
        );
        let in_entity_tag = schema_with_entity_tag(ty.clone());
        Schema::from_deprecated_json_value(in_entity_tag.clone()).unwrap();
        expect_err(
            "",
            &Report::new(Schema::from_json_value(in_entity_tag).unwrap_err()),
            &ExpectedErrorMessageBuilder::error(err).build(),
        );
        let in_context = schema_with_context_attribute(ty.clone());
        Schema::from_deprecated_json_value(in_context.clone()).unwrap();
        expect_err(
            "",
            &Report::new(Schema::from_json_value(in_context).unwrap_err()),
            &ExpectedErrorMessageBuilder::error(err).build(),
        );
        let in_common = schema_with_common_type(ty.clone());
        Schema::from_deprecated_json_value(in_common.clone()).unwrap();
        expect_err(
            "",
            &Report::new(Schema::from_json_value(in_common).unwrap_err()),
            &ExpectedErrorMessageBuilder::error(err).build(),
        );
    }

    #[test]
    fn in_long() {
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Long",
                "name": "my_long",
            }),
            "unknown field `name`, there are no fields",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Long",
                "element": {"type": "Long"},
            }),
            "unknown field `element`, there are no fields",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Long",
                "attributes": {},
            }),
            "unknown field `attributes`, there are no fields",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Long",
                "additionalAttributes": false,
            }),
            "unknown field `additionalAttributes`, there are no fields",
        );
    }

    #[test]
    fn in_bool() {
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Boolean",
                "name": "my_long",
            }),
            "unknown field `name`, there are no fields",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Boolean",
                "element": {"type": "Long"},
            }),
            "unknown field `element`, there are no fields",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Boolean",
                "attributes": {},
            }),
            "unknown field `attributes`, there are no fields",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Boolean",
                "additionalAttributes": false,
            }),
            "unknown field `additionalAttributes`, there are no fields",
        );
    }

    #[test]
    fn in_string() {
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "String",
                "name": "my_long",
            }),
            "unknown field `name`, there are no fields",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "String",
                "element": {"type": "Long"},
            }),
            "unknown field `element`, there are no fields",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "String",
                "attributes": {},
            }),
            "unknown field `attributes`, there are no fields",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "String",
                "additionalAttributes": false,
            }),
            "unknown field `additionalAttributes`, there are no fields",
        );
    }

    #[test]
    fn in_set() {
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Set",
                "element": {"type": "Long"},
                "name": "my_long",
            }),
            "unknown field `name`, expected `element`",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Set",
                "element": {"type": "Long", "name": "my_long"},
            }),
            "unknown field `name`, there are no fields",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Set",
                "element": {"type": "Long"},
                "attributes": {},
            }),
            "unknown field `attributes`, expected `element`",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Set",
                "element": {"type": "Long"},
                "additionalAttributes": false,
            }),
            "unknown field `additionalAttributes`, expected `element`",
        );
    }

    #[test]
    fn in_entity() {
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Entity",
                "name": "User",
                "element": {"type": "Long"},
            }),
            "unknown field `element`, expected `name`",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Entity",
                "name": "User",
                "attributes": {},
            }),
            "unknown field `attributes`, expected `name`",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Entity",
                "name": "User",
                "additionalAttributes": false,
            }),
            "unknown field `additionalAttributes`, expected `name`",
        );
    }

    #[test]
    fn in_extension() {
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Extension",
                "name": "decimal",
                "element": {"type": "Long"},
            }),
            "unknown field `element`, expected `name`",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Extension",
                "name": "decimal",
                "attributes": {},
            }),
            "unknown field `attributes`, expected `name`",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Extension",
                "name": "decimal",
                "additionalAttributes": false,
            }),
            "unknown field `additionalAttributes`, expected `name`",
        );
    }

    #[test]
    fn in_record() {
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Record",
                "attributes": {},
                "element": {"type": "Long"},
            }),
            "unknown field `element`, expected `attributes` or `additionalAttributes`",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Record",
                "attributes": {},
                "name": "decimal",
            }),
            "unknown field `name`, expected `attributes` or `additionalAttributes`",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "Record",
                "attributes": { "a": {"type": "Long", "name": "foo"} },
            }),
            "unknown field `name`, there are no fields",
        );
    }

    #[test]
    fn in_common() {
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "ty",
                "name": "my_long",
            }),
            "unknown field `name`, there are no fields",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "ty",
                "element": {"type": "Long"},
            }),
            "unknown field `element`, there are no fields",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "ty",
                "attributes": {},
            }),
            "unknown field `attributes`, there are no fields",
        );
        assert_ok_deprecated_and_err_standard(
            json!({
                "type": "ty",
                "additionalAttributes": false,
            }),
            "unknown field `additionalAttributes`, there are no fields",
        );
    }
}

/// These tests check the behavior of extra fields that should still be forbidden
#[cfg(test)]
#[allow(deprecated)]
mod extra_fields_forbidden {
    use cedar_policy_core::test_utils::{expect_err, ExpectedErrorMessageBuilder};
    use miette::Report;
    use serde_json::json;

    use crate::Schema;

    #[track_caller]
    fn assert_err_deprecated_and_standard(schema: serde_json::Value, err: &str) {
        expect_err(
            "",
            &Report::new(Schema::from_json_value(schema.clone()).unwrap_err()),
            &ExpectedErrorMessageBuilder::error(err).build(),
        );
        expect_err(
            "",
            &Report::new(Schema::from_deprecated_json_value(schema.clone()).unwrap_err()),
            &ExpectedErrorMessageBuilder::error(err).build(),
        );
    }

    #[test]
    fn extra_field_in_namespace() {
        assert_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {},
                    "foo": {},
                }
            }),
            "unknown field `foo`, expected one of `commonTypes`, `entityTypes`, `actions`, `annotations`",
        );
    }

    #[test]
    fn extra_field_in_entity_type() {
        assert_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": {
                        "User": {
                            "foo": {},
                        }
                    },
                    "actions": {},
                }
            }),
            "unknown field `foo`, expected one of `memberOfTypes`, `shape`, `tags`, `enum`, `annotations`",
        );
    }

    #[test]
    fn extra_field_in_action() {
        assert_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": {
                    },
                    "actions": {
                        "act": {
                            "foo": {}
                        },
                    },
                }
            }),
            "unknown field `foo`, expected one of `attributes`, `appliesTo`, `memberOf`, `annotations`",
        );
    }

    #[test]
    fn extra_field_in_applies_to() {
        assert_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": { },
                    "actions": {
                        "act": {
                            "appliesTo": {
                                "principalTypes": [],
                                "resourceTypes": [],
                                "foo": {},
                            }
                        },
                    },
                }
            }),
            "unknown field `foo`, expected one of `resourceTypes`, `principalTypes`, `context`",
        );
    }
}
