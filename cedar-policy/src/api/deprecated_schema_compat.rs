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

//! Defines functions for parsing schema using a format (mostly) compatible with
//! version 2.5.0 of this library.

// Note: We'll likely want to remove these functions in the future if we can get
// everyone on to the updated schema format. If we ever get there, we should
// keep some of the tests in this file. Many of the tests check error behavior
// and actually test the behavior of standard schema parsing in addition to the
// functions defined.

use cedar_policy_core::extensions::Extensions;
use cedar_policy_core::validator::SchemaError;

use super::{Schema, SchemaFragment};

impl SchemaFragment {
    /// Create a [`SchemaFragment`] from a JSON value in shape of the deprecated
    /// JSON schema format used for versions 2.5.0 of this library.  Most
    /// callers should use [`SchemaFragment::from_json_value`] instead.
    #[deprecated(
        since = "4.5.0",
        note = "use `SchemaFragment::from_json_value` instead"
    )]
    pub fn from_deprecated_json_value(json: serde_json::Value) -> Result<Self, SchemaError> {
        let lossless =
            cedar_policy_core::validator::json_schema::Fragment::from_deprecated_json_value(json)?;
        Ok(Self {
            value: lossless.clone().try_into()?,
            lossless,
        })
    }

    /// Create a [`SchemaFragment`] from a string containing JSON in the
    /// deprecated JSON schema format used for versions 2.5.0 of this library.
    /// Most callers should use [`SchemaFragment::from_json_str`] instead.
    #[deprecated(since = "4.5.0", note = "use `SchemaFragment::from_json_str` instead")]
    pub fn from_deprecated_json_str(src: &str) -> Result<Self, SchemaError> {
        let lossless =
            cedar_policy_core::validator::json_schema::Fragment::from_deprecated_json_str(src)?;
        Ok(Self {
            value: lossless.clone().try_into()?,
            lossless,
        })
    }

    /// Create a [`SchemaFragment`] directly from a JSON file containing JSON in
    /// the deprecated JSON schema format used for versions 2.5.0 of this
    /// library. Most callers should use [`SchemaFragment::from_json_file`]
    /// instead.
    #[deprecated(since = "4.5.0", note = "use `SchemaFragment::from_json_file` instead")]
    pub fn from_deprecated_json_file(file: impl std::io::Read) -> Result<Self, SchemaError> {
        let lossless =
            cedar_policy_core::validator::json_schema::Fragment::from_deprecated_json_file(file)?;
        Ok(Self {
            value: lossless.clone().try_into()?,
            lossless,
        })
    }
}

impl Schema {
    /// Create a [`Schema`] from a string containing JSON in the
    /// deprecated JSON schema format used for versions 2.5.0 of this library.
    /// Most callers should use [`Schema::from_json_str`] instead.
    #[deprecated(since = "4.5.0", note = "use `Schema::from_json_str` instead")]
    pub fn from_deprecated_json_value(json: serde_json::Value) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_core::validator::ValidatorSchema::from_deprecated_json_value(
                json,
                Extensions::all_available(),
            )?,
        ))
    }

    /// Create a [`Schema`] from a JSON value in shape of the deprecated
    /// JSON schema format used for versions 2.5.0 of this library.  Most
    /// callers should use [`Schema::from_json_value`] instead.
    #[deprecated(since = "4.5.0", note = "use `Schema::from_json_value` instead")]
    pub fn from_deprecated_json_str(json: &str) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_core::validator::ValidatorSchema::from_deprecated_json_str(
                json,
                Extensions::all_available(),
            )?,
        ))
    }

    /// Create a [`Schema`] directly from a JSON file containing JSON in
    /// the deprecated JSON schema format used for versions 2.5.0 of this
    /// library. Most callers should use [`Schema::from_json_file`] instead.
    #[deprecated(since = "4.5.0", note = "use `Schema::from_json_file` instead")]
    pub fn from_deprecated_json_file(file: impl std::io::Read) -> Result<Self, SchemaError> {
        Ok(Self(
            cedar_policy_core::validator::ValidatorSchema::from_deprecated_json_file(
                file,
                Extensions::all_available(),
            )?,
        ))
    }
}

#[cfg(test)]
mod test_utils {
    use cedar_policy_core::test_utils::{
        expect_err, ExpectedErrorMessage, ExpectedErrorMessageBuilder,
    };
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
    #[allow(deprecated)]
    pub(crate) fn assert_type_json_ok_deprecated_and_err_standard(
        ty: serde_json::Value,
        err: &str,
    ) {
        let in_entity_attr = schema_with_entity_attribute(ty.clone());
        Schema::from_deprecated_json_value(in_entity_attr.clone()).unwrap();
        expect_err(
            "",
            &Report::new(Schema::from_json_value(in_entity_attr).unwrap_err()),
            &ExpectedErrorMessageBuilder::error(err).build(),
        );
        let in_context = schema_with_context_attribute(ty.clone());
        Schema::from_deprecated_json_value(in_context.clone()).unwrap();
        expect_err(
            "",
            &Report::new(Schema::from_json_value(in_context).unwrap_err()),
            &ExpectedErrorMessageBuilder::error(err).build(),
        );
        let in_common = schema_with_common_type(ty);
        Schema::from_deprecated_json_value(in_common.clone()).unwrap();
        expect_err(
            "",
            &Report::new(Schema::from_json_value(in_common).unwrap_err()),
            &ExpectedErrorMessageBuilder::error(err).build(),
        );
    }

    #[track_caller]
    #[allow(deprecated)]
    pub(crate) fn assert_type_json_ok_deprecated_and_standard(ty: serde_json::Value) {
        let in_entity_attr = schema_with_entity_attribute(ty.clone());
        Schema::from_deprecated_json_value(in_entity_attr.clone()).unwrap();
        Schema::from_json_value(in_entity_attr).unwrap();
        let in_context = schema_with_context_attribute(ty.clone());
        Schema::from_deprecated_json_value(in_context.clone()).unwrap();
        Schema::from_json_value(in_context).unwrap();
        let in_common = schema_with_common_type(ty);
        Schema::from_deprecated_json_value(in_common.clone()).unwrap();
        Schema::from_json_value(in_common).unwrap();
    }

    #[track_caller]
    #[allow(deprecated)]
    pub(crate) fn assert_type_json_err_deprecated_and_standard(
        ty: serde_json::Value,
        current_err: &ExpectedErrorMessage<'_>,
        deprecated_err: &ExpectedErrorMessage<'_>,
    ) {
        let in_entity_attr = schema_with_entity_attribute(ty.clone());
        assert_schema_json_err_deprecated_and_standard(in_entity_attr, current_err, deprecated_err);
        let in_context = schema_with_context_attribute(ty.clone());
        assert_schema_json_err_deprecated_and_standard(in_context, current_err, deprecated_err);
        let in_common = schema_with_common_type(ty);
        assert_schema_json_err_deprecated_and_standard(in_common, current_err, deprecated_err);
    }

    #[track_caller]
    #[allow(deprecated)]
    pub(crate) fn assert_schema_json_err_deprecated_and_standard(
        schema: serde_json::Value,
        current_err: &ExpectedErrorMessage<'_>,
        deprecated_err: &ExpectedErrorMessage<'_>,
    ) {
        expect_err(
            "",
            &Report::new(Schema::from_json_value(schema.clone()).unwrap_err()),
            current_err,
        );
        expect_err(
            "",
            &Report::new(Schema::from_deprecated_json_value(schema).unwrap_err()),
            deprecated_err,
        );
    }
}

/// These tests assert that unknown fields are allowed in specific locations in
/// the compatibility mode, but not allowed in the standard schema parsing mode.
#[cfg(test)]
mod extra_fields_allowed {
    use super::test_utils::*;
    use serde_json::json;

    #[test]
    fn in_long() {
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "Long",
                "bogus": "bogus",
            }),
            "unknown field `bogus`, expected one of `type`, `element`, `attributes`, `additionalAttributes`, `name`",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "Long",
                "name": "my_long",
            }),
            "unknown field `name`, there are no fields",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "Long",
                "element": "bogus"
            }),
            "invalid type: string \"bogus\", expected builtin type or reference to type defined in commonTypes",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "Long",
                "attributes": "bogus",
            }),
            "invalid type: string \"bogus\", expected a map",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "Long",
                "additionalAttributes": "bogus",
            }),
            "invalid type: string \"bogus\", expected a boolean",
        );
        assert_type_json_ok_deprecated_and_standard(json!({
            "type": "Long",
            "annotations": {},
        }));
    }

    #[test]
    fn in_bool() {
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "Boolean",
                "bogus": "bogus",
            }),
            "unknown field `bogus`, expected one of `type`, `element`, `attributes`, `additionalAttributes`, `name`",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "Boolean",
                "name": "my_long",
            }),
            "unknown field `name`, there are no fields",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "Boolean",
                "element": "bogus",
            }),
            "invalid type: string \"bogus\", expected builtin type or reference to type defined in commonTypes",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "Boolean",
                "attributes": "bogus",
            }),
            "invalid type: string \"bogus\", expected a map",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "Boolean",
                "additionalAttributes": "bogus",
            }),
            "invalid type: string \"bogus\", expected a boolean",
        );
        assert_type_json_ok_deprecated_and_standard(json!({
            "type": "Boolean",
            "annotations": {},
        }));
    }

    #[test]
    fn in_string() {
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "String",
                "bogus": "bogus",
            }),
            "unknown field `bogus`, expected one of `type`, `element`, `attributes`, `additionalAttributes`, `name`",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "String",
                "name": "bogus",
            }),
            "unknown field `name`, there are no fields",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "String",
                "element": {"type": "Long"}
            }),
            "unknown field `element`, there are no fields",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "String",
                "attributes": {},
            }),
            "unknown field `attributes`, there are no fields",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "String",
                "additionalAttributes": false,
            }),
            "unknown field `additionalAttributes`, there are no fields",
        );
        assert_type_json_ok_deprecated_and_standard(json!({
            "type": "String",
            "annotations": {},
        }));
    }

    #[test]
    fn in_common() {
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "ty",
                "bogus": "bogus",
            }),
            "unknown field `bogus`, expected one of `type`, `element`, `attributes`, `additionalAttributes`, `name`",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "ty",
                "name": "my_long",
            }),
            "unknown field `name`, there are no fields",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "ty",
                "element": 10,
            }),
            "invalid type: integer `10`, expected builtin type or reference to type defined in commonTypes",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "ty",
                "attributes": ["bogus"],
            }),
            "invalid type: sequence, expected a map",
        );
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "ty",
                "additionalAttributes": {"bogus": "bogus"},
            }),
            "invalid type: map, expected a boolean",
        );
        assert_type_json_ok_deprecated_and_standard(json!({
            "type": "ty",
            "annotations": {},
        }));
    }

    #[test]
    fn in_set_elem() {
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "Set",
                "element": {"type": "Long", "name": "my_long"},
            }),
            "unknown field `name`, there are no fields",
        );
    }

    #[test]
    fn in_record_attr() {
        assert_type_json_ok_deprecated_and_err_standard(
            json!({
                "type": "Record",
                "attributes": { "a": {"type": "Long", "name": "foo"} },
            }),
            "unknown field `name`, there are no fields",
        );
    }
}

/// These tests check the behavior of extra fields that should still be forbidden
#[cfg(test)]
mod extra_fields_forbidden {
    use super::test_utils::*;
    use cedar_policy_core::test_utils::ExpectedErrorMessageBuilder;
    use serde_json::json;

    #[test]
    fn in_set() {
        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Set",
                "element": {"type": "Long"},
                "bogus": "bogus",
            }),
            &ExpectedErrorMessageBuilder::error("unknown field `bogus`, expected one of `type`, `element`, `attributes`, `additionalAttributes`, `name`")
                .build(),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: Set")
                .help("neither `ns::Set` nor `Set` refers to anything that has been declared as a common type")
                .exactly_one_underline("Set")
                .build(),
        );
        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Set",
                "element": {"type": "Long"},
                "name": "my_long",
            }),
            &ExpectedErrorMessageBuilder::error("unknown field `name`, expected `element`")
                .build(),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: Set")
                .help("neither `ns::Set` nor `Set` refers to anything that has been declared as a common type")
                .exactly_one_underline("Set")
                .build(),
        );

        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Set",
                "element": {"type": "Long"},
                "attributes": {},
            }),
            &ExpectedErrorMessageBuilder::error("unknown field `attributes`, expected `element`")
                .build(),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: Set")
                .help("neither `ns::Set` nor `Set` refers to anything that has been declared as a common type")
                .exactly_one_underline("Set")
                .build(),
        );
        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Set",
                "element": {"type": "Long"},
                "additionalAttributes": false,
            }),
            &ExpectedErrorMessageBuilder::error("unknown field `additionalAttributes`, expected `element`")
                .build(),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: Set")
                .help("neither `ns::Set` nor `Set` refers to anything that has been declared as a common type")
                .exactly_one_underline("Set")
                .build(),
        );
    }

    #[test]
    fn in_entity() {
        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Entity",
                "name": "User",
                "bogus": "bogus",
            }),
            &ExpectedErrorMessageBuilder::error("unknown field `bogus`, expected one of `type`, `element`, `attributes`, `additionalAttributes`, `name`")
                .build(),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: Entity")
                .help("neither `ns::Entity` nor `Entity` refers to anything that has been declared as a common type")
                .exactly_one_underline("Entity")
                .build(),
        );
        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Entity",
                "name": "User",
                "element": {"type": "Long"},
            }),
            &ExpectedErrorMessageBuilder::error("unknown field `element`, expected `name`")
                .build(),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: Entity")
                .help("neither `ns::Entity` nor `Entity` refers to anything that has been declared as a common type")
                .exactly_one_underline("Entity")
                .build(),
        );
        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Entity",
                "name": "User",
                "attributes": {},
            }),
            &ExpectedErrorMessageBuilder::error("unknown field `attributes`, expected `name`")
                .build(),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: Entity")
                .help("neither `ns::Entity` nor `Entity` refers to anything that has been declared as a common type")
                .exactly_one_underline("Entity")
                .build(),
        );
        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Entity",
                "name": "User",
                "additionalAttributes": false,
            }),
            &ExpectedErrorMessageBuilder::error( "unknown field `additionalAttributes`, expected `name`",)
                .build(),
            &ExpectedErrorMessageBuilder::error( "failed to resolve type: Entity",)
                .help("neither `ns::Entity` nor `Entity` refers to anything that has been declared as a common type")
                .exactly_one_underline("Entity")
                .build(),
        );
    }

    #[test]
    fn in_extension() {
        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Extension",
                "name": "ip",
                "bogus": "bogus"
            }),
            &ExpectedErrorMessageBuilder::error("unknown field `bogus`, expected one of `type`, `element`, `attributes`, `additionalAttributes`, `name`")
                .build(),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: Extension")
                .help("neither `ns::Extension` nor `Extension` refers to anything that has been declared as a common type")
                .exactly_one_underline("Extension")
                .build(),
        );
        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Extension",
                "name": "ip",
                "element": {"type": "Long"},
            }),
            &ExpectedErrorMessageBuilder::error("unknown field `element`, expected `name`")
                .build(),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: Extension")
                .help("neither `ns::Extension` nor `Extension` refers to anything that has been declared as a common type")
                .exactly_one_underline("Extension")
                .build(),
        );
        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Extension",
                "name": "ip",
                "attributes": {},
            }),
            &ExpectedErrorMessageBuilder::error("unknown field `attributes`, expected `name`")
                .build(),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: Extension")
                .help("neither `ns::Extension` nor `Extension` refers to anything that has been declared as a common type")
                .exactly_one_underline("Extension")
                .build(),
        );
        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Extension",
                "name": "ip",
                "additionalAttributes": false,
            }),
            &ExpectedErrorMessageBuilder::error( "unknown field `additionalAttributes`, expected `name`",)
                .build(),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: Extension")
                .help("neither `ns::Extension` nor `Extension` refers to anything that has been declared as a common type")
                .exactly_one_underline("Extension")
                .build(),
        );
    }

    #[test]
    fn in_record() {
        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Record",
                "attributes": {},
                "bogus": "bogus"
            }),
            &ExpectedErrorMessageBuilder::error("unknown field `bogus`, expected one of `type`, `element`, `attributes`, `additionalAttributes`, `name`")
                .build(),
            &ExpectedErrorMessageBuilder::error("failed to resolve type: Record")
                .help("neither `ns::Record` nor `Record` refers to anything that has been declared as a common type")
                .exactly_one_underline("Record")
                .build(),
        );
        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Record",
                "attributes": {},
                "element": {"type": "Long"},
            }),
            &ExpectedErrorMessageBuilder::error( "unknown field `element`, expected `attributes` or `additionalAttributes`",)
                .build(),
            &ExpectedErrorMessageBuilder::error( "failed to resolve type: Record",)
                .help("neither `ns::Record` nor `Record` refers to anything that has been declared as a common type")
                .exactly_one_underline("Record")
                .build(),
        );
        assert_type_json_err_deprecated_and_standard(
            json!({
                "type": "Record",
                "attributes": {},
                "name": "ip",
            }),
            &ExpectedErrorMessageBuilder::error( "unknown field `name`, expected `attributes` or `additionalAttributes`",)
                 .build(),
            &ExpectedErrorMessageBuilder::error( "failed to resolve type: Record",)
                .help("neither `ns::Record` nor `Record` refers to anything that has been declared as a common type")
                .exactly_one_underline("Record")
                .build(),
        );
    }

    #[test]
    fn in_namespace() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {},
                    "foo": {},
                }
            }),
            &ExpectedErrorMessageBuilder::error("unknown field `foo`, expected one of `commonTypes`, `entityTypes`, `actions`, `annotations`").build(),
            &ExpectedErrorMessageBuilder::error("unknown field `foo`, expected one of `commonTypes`, `entityTypes`, `actions`").build(),
        );
    }

    #[test]
    fn in_entity_type() {
        assert_schema_json_err_deprecated_and_standard(
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
            &ExpectedErrorMessageBuilder::error("unknown field `foo`, expected one of `memberOfTypes`, `shape`, `tags`, `enum`, `annotations`").build(),
            &ExpectedErrorMessageBuilder::error("unknown field `foo`, expected `memberOfTypes` or `shape`").build(),
        );
    }

    #[test]
    fn in_action() {
        assert_schema_json_err_deprecated_and_standard(
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
            &ExpectedErrorMessageBuilder::error("unknown field `foo`, expected one of `attributes`, `appliesTo`, `memberOf`, `annotations`").build(),
            &ExpectedErrorMessageBuilder::error("unknown field `foo`, expected one of `attributes`, `appliesTo`, `memberOf`").build(),
        );
    }

    #[test]
    fn in_applies_to() {
        assert_schema_json_err_deprecated_and_standard(
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
            &ExpectedErrorMessageBuilder::error(
                "unknown field `foo`, expected one of `resourceTypes`, `principalTypes`, `context`",
            )
            .build(),
            &ExpectedErrorMessageBuilder::error(
                "unknown field `foo`, expected one of `resourceTypes`, `principalTypes`, `context`",
            )
            .build(),
        );
    }
}

/// Unspecified `appliesTo` is still reported as an error
#[cfg(test)]
mod unspecified_not_allowed {
    use cedar_policy_core::test_utils::ExpectedErrorMessageBuilder;
    use serde_json::json;

    use super::test_utils::*;

    #[test]
    fn missing_principal() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": { },
                    "actions": {
                        "act": {
                            "appliesTo": {
                                "resourceTypes": [],
                            }
                        },
                    },
                }
            }),
            &ExpectedErrorMessageBuilder::error("missing field `principalTypes`").build(),
            &ExpectedErrorMessageBuilder::error("missing field `principalTypes`").build(),
        );
    }

    #[test]
    fn missing_resource() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": { },
                    "actions": {
                        "act": {
                            "appliesTo": {
                                "principalTypes": [],
                            }
                        },
                    },
                }
            }),
            &ExpectedErrorMessageBuilder::error("missing field `resourceTypes`").build(),
            &ExpectedErrorMessageBuilder::error("missing field `resourceTypes`").build(),
        );
    }

    #[test]
    fn missing_both() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": { },
                    "actions": {
                        "act": {
                            "appliesTo": { }
                        },
                    },
                }
            }),
            &ExpectedErrorMessageBuilder::error("missing field `resourceTypes`").build(),
            &ExpectedErrorMessageBuilder::error("missing field `resourceTypes`").build(),
        );
    }

    #[test]
    fn null_values() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": { },
                    "actions": {
                        "act": {
                            "appliesTo": {
                                "principalTypes": [],
                                "resourceTypes": null
                            }
                        },
                    },
                }
            }),
            &ExpectedErrorMessageBuilder::error("invalid type: null, expected a sequence").build(),
            &ExpectedErrorMessageBuilder::error("missing field `resourceTypes`").build(),
        );
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": { },
                    "actions": {
                        "act": {
                            "appliesTo": {
                                "principalTypes": null,
                                "resourceTypes": [],
                            }
                        },
                    },
                }
            }),
            &ExpectedErrorMessageBuilder::error("invalid type: null, expected a sequence").build(),
            &ExpectedErrorMessageBuilder::error("missing field `principalTypes`").build(),
        );
    }
}

#[cfg(test)]
mod invalid_names_detected {
    use cedar_policy_core::test_utils::ExpectedErrorMessageBuilder;
    use serde_json::json;

    use super::test_utils::*;

    #[test]
    fn in_namespace() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                " space": {
                    "entityTypes": { },
                    "actions": { },
                }
            }),
            &ExpectedErrorMessageBuilder::error("invalid namespace ` space`: `Name` needs to be normalized (e.g., whitespace removed):  space").build(),
            &ExpectedErrorMessageBuilder::error("invalid namespace ` space`: `Name` needs to be normalized (e.g., whitespace removed):  space").build(),
        );
    }

    #[test]
    fn in_common_type() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "commonTypes": {
                        " space": {"type": "Long"}
                    },
                    "entityTypes": { },
                    "actions": { },
                }
            }),
            &ExpectedErrorMessageBuilder::error("invalid id ` space`: `Id` needs to be normalized (e.g., whitespace removed):  space").build(),
            &ExpectedErrorMessageBuilder::error("invalid id ` space`: `Id` needs to be normalized (e.g., whitespace removed):  space").build(),
        );
    }

    #[test]
    fn in_common_type_ref() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "foo": {"type": " space"}
                                }
                            }
                        }
                    },
                    "actions": { },
                }
            }),
            &ExpectedErrorMessageBuilder::error("invalid common type ` space`: `internal name` needs to be normalized (e.g., whitespace removed):  space").build(),
            &ExpectedErrorMessageBuilder::error("invalid common type ` space`: `internal name` needs to be normalized (e.g., whitespace removed):  space").build(),
        );
    }

    #[test]
    fn reserved_common_type() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "commonTypes": {
                        "Long": {"type": "Long"}
                    },
                    "entityTypes": { },
                    "actions": { },
                }
            }),
            &ExpectedErrorMessageBuilder::error(
                "this is reserved and cannot be the basename of a common-type declaration: Long",
            )
            .build(),
            &ExpectedErrorMessageBuilder::error(
                "this is reserved and cannot be the basename of a common-type declaration: Long",
            )
            .build(),
        );
    }

    #[test]
    fn in_entity_type() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": {
                        " space": { }
                    },
                    "actions": { },
                }
            }),
            &ExpectedErrorMessageBuilder::error("invalid id ` space`: `Id` needs to be normalized (e.g., whitespace removed):  space").build(),
            &ExpectedErrorMessageBuilder::error("invalid id ` space`: `Id` needs to be normalized (e.g., whitespace removed):  space").build(),
        );
    }

    #[test]
    fn in_member_of_types() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": {
                        "User": {
                            "memberOfTypes": [" User"]
                        }
                    },
                    "actions": { },
                }
            }),
            &ExpectedErrorMessageBuilder::error("invalid name ` User`: `internal name` needs to be normalized (e.g., whitespace removed):  User").build(),
            &ExpectedErrorMessageBuilder::error("invalid name ` User`: `internal name` needs to be normalized (e.g., whitespace removed):  User").build(),
        );
    }

    #[test]
    fn in_entity_type_ref() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "foo": {"type": "Entity", "name": " space"}
                                }
                            }
                        }
                    },
                    "actions": { },
                }
            }),
            &ExpectedErrorMessageBuilder::error("invalid entity type ` space`: `internal name` needs to be normalized (e.g., whitespace removed):  space").build(),
            &ExpectedErrorMessageBuilder::error("invalid entity type ` space`: `internal name` needs to be normalized (e.g., whitespace removed):  space").build(),
        );
    }

    #[test]
    fn in_extension_type() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "foo": {"type": "Extension", "name": " ip"}
                                }
                            }
                        }
                    },
                    "actions": { },
                }
            }),
            &ExpectedErrorMessageBuilder::error("invalid extension type ` ip`: `Unreserved Id` needs to be normalized (e.g., whitespace removed):  ip").build(),
            &ExpectedErrorMessageBuilder::error("invalid extension type ` ip`: `Unreserved Id` needs to be normalized (e.g., whitespace removed):  ip").build(),
        );
    }

    #[test]
    fn in_applies_to_principals() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": { },
                    "actions": {
                        "act": {
                            "appliesTo": {
                                "principalTypes": [" User"],
                                "resourceTypes": [],
                            }
                        }
                    },
                }
            }),
            &ExpectedErrorMessageBuilder::error("invalid name ` User`: `internal name` needs to be normalized (e.g., whitespace removed):  User").build(),
            &ExpectedErrorMessageBuilder::error("invalid name ` User`: `internal name` needs to be normalized (e.g., whitespace removed):  User").build(),
        );
    }

    #[test]
    fn in_applies_to_resources() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": { },
                    "actions": {
                        "act": {
                            "appliesTo": {
                                "principalTypes": [],
                                "resourceTypes": [" User"],
                            }
                        }
                    },
                }
            }),
            &ExpectedErrorMessageBuilder::error("invalid name ` User`: `internal name` needs to be normalized (e.g., whitespace removed):  User").build(),
            &ExpectedErrorMessageBuilder::error("invalid name ` User`: `internal name` needs to be normalized (e.g., whitespace removed):  User").build(),
        );
    }

    #[test]
    fn in_member_of() {
        assert_schema_json_err_deprecated_and_standard(
            json!({
                "ns": {
                    "entityTypes": { },
                    "actions": {
                        "other": {},
                        "act": {
                            "memberOf": [{"type": " Action", "id": "other"}],
                        }
                    },
                }
            }),
            &ExpectedErrorMessageBuilder::error("invalid name ` Action`: `internal name` needs to be normalized (e.g., whitespace removed):  Action").build(),
            &ExpectedErrorMessageBuilder::error("invalid name ` Action`: `internal name` needs to be normalized (e.g., whitespace removed):  Action").build(),
        );
    }
}

#[cfg(test)]
mod from_str_parse_err {

    use miette::Report;

    use crate::{Schema, SchemaFragment};
    use cedar_policy_core::test_utils::{expect_err, ExpectedErrorMessageBuilder};

    #[test]
    #[allow(deprecated)]
    fn from_cedar_schema_str_err() {
        let src = "entity User;";
        expect_err(
            src,
            &Report::new(Schema::from_deprecated_json_str(src).unwrap_err()),
            &ExpectedErrorMessageBuilder::error("expected value at line 1 column 1").help("this API was expecting a schema in the JSON format; did you mean to use a different function, which expects the Cedar schema format?").build(),
        );
        expect_err(
            src,
            &Report::new(SchemaFragment::from_deprecated_json_str(src).unwrap_err()),
            &ExpectedErrorMessageBuilder::error("expected value at line 1 column 1").help("this API was expecting a schema in the JSON format; did you mean to use a different function, which expects the Cedar schema format?").build(),
        );
    }
}
