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
            cedar_policy_validator::json_schema::Fragment::from_deprecated_schema_json_str(src)?;
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
        let lossless = cedar_policy_validator::json_schema::Fragment::from_json_value(json)?;
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
        let lossless = cedar_policy_validator::json_schema::Fragment::from_json_file(file)?;
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
            cedar_policy_validator::ValidatorSchema::from_deprecated_json_value(
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
            cedar_policy_validator::ValidatorSchema::from_deprecated_json_str(
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
            cedar_policy_validator::ValidatorSchema::from_deprecated_json_file(
                file,
                Extensions::all_available(),
            )?,
        ))
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod test {
    use cedar_policy_core::test_utils::{expect_err, ExpectedErrorMessageBuilder};
    use miette::Report;
    use serde_json::json;

    use crate::Schema;

    use cedar_policy_deprecated_schema_compatibility as cedar2;

    #[track_caller]
    fn assert_err_cedar_2_and_compatibility_layer(schema: serde_json::Value, err: &str) {
        assert_eq!(
            cedar2::Schema::from_json_value(schema.clone())
                .unwrap_err()
                .to_string(),
            format!("JSON Schema file could not be parsed: {err}")
        );
        expect_err(
            "",
            &Report::new(Schema::from_deprecated_json_value(schema.clone()).unwrap_err()),
            &ExpectedErrorMessageBuilder::error(err).build(),
        );
    }

    #[test]
    fn extra_field_in_namespace() {
        assert_err_cedar_2_and_compatibility_layer(
            json!({
                "ns": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {},
                    "foo": {},
                }
            }),
            "unknown field `foo`, expected one of `commonTypes`, `entityTypes`, `actions`",
        );
    }

    #[test]
    fn extra_field_in_entity_type() {
        assert_err_cedar_2_and_compatibility_layer(
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
            "unknown field `foo`, expected `memberOfTypes` or `shape`",
        );
    }

    #[test]
    fn extra_field_in_action() {
        assert_err_cedar_2_and_compatibility_layer(
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
            "unknown field `foo`, expected one of `attributes`, `appliesTo`, `memberOf`",
        );
    }

    #[test]
    fn extra_field_in_applies_to() {
        assert_err_cedar_2_and_compatibility_layer(
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

    #[test]
    fn extra_field_in_entity_shape() {
        assert_err_cedar_2_and_compatibility_layer(
            json!({
                "ns": {
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "foo": {},
                                "attributes": {},
                            },
                        }
                    },
                    "actions": {},
                }
            }),
            "unknown field `foo`, expected `memberOfTypes` or `shape`",
        );
    }

    fn assert_parses_cedar_2_and_compatibility_layer(schema: serde_json::Value) {
        cedar2::Schema::from_json_value(schema.clone()).unwrap();
        Schema::from_deprecated_json_value(schema.clone()).unwrap();
    }

    fn schema_with_attribute(attr_ty: serde_json::Value) -> serde_json::Value {
        json!({
            "ns": {
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

    #[test]
    fn extra_fields_in_long() {
        assert_parses_cedar_2_and_compatibility_layer(schema_with_attribute(json!({
            "type": "Long",
            "name": "my_long",
        })));
        assert_parses_cedar_2_and_compatibility_layer(schema_with_attribute(json!({
            "type": "Long",
            "element": "thing",
        })));
        assert_parses_cedar_2_and_compatibility_layer(schema_with_attribute(json!({
            "type": "Long",
            "attributes": "bar",
        })));
        assert_parses_cedar_2_and_compatibility_layer(schema_with_attribute(json!({
            "type": "Long",
            "additional_attributes": "bar",
        })));
    }

    #[test]
    fn extra_fields_in_bool() {
        assert_parses_cedar_2_and_compatibility_layer(schema_with_attribute(json!({
            "type": "Boolean",
            "name": "my_long",
        })));
        assert_parses_cedar_2_and_compatibility_layer(schema_with_attribute(json!({
            "type": "Boolean",
            "element": "thing",
        })));
        assert_parses_cedar_2_and_compatibility_layer(schema_with_attribute(json!({
            "type": "Boolean",
            "attributes": "bar",
        })));
        assert_parses_cedar_2_and_compatibility_layer(schema_with_attribute(json!({
            "type": "Boolean",
            "additional_attributes": "bar",
        })));
    }

    #[test]
    fn extra_fields_in_string() {
        assert_parses_cedar_2_and_compatibility_layer(schema_with_attribute(json!({
            "type": "String",
            "name": "my_long",
        })));
        assert_parses_cedar_2_and_compatibility_layer(schema_with_attribute(json!({
            "type": "String",
            "element": "thing",
        })));
        assert_parses_cedar_2_and_compatibility_layer(schema_with_attribute(json!({
            "type": "String",
            "attributes": "bar",
        })));
        assert_parses_cedar_2_and_compatibility_layer(schema_with_attribute(json!({
            "type": "String",
            "additional_attributes": "bar",
        })));
    }
}
