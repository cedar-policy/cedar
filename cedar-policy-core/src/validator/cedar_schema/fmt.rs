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

//! `Display` implementations for formatting a [`json_schema::Fragment`] in the
//! Cedar schema syntax

use std::{collections::HashSet, fmt::Display};

use itertools::Itertools;
use miette::Diagnostic;
use nonempty::NonEmpty;
use thiserror::Error;

use crate::validator::{json_schema, RawName};
use crate::{ast::InternalName, impl_diagnostic_from_method_on_nonempty_field};

/// Number of spaces of indentation per level in the Cedarschema file
pub const NUM_INDENTATION_SPACES: usize = 2;

/// Helper struct to indent Cedarschema files with `NUM_INDENTATION_SPACES` spaces at each level.
struct BaseIndentation(String);

impl BaseIndentation {
    /// Do not use any base indentation.
    fn none() -> Self {
        BaseIndentation(String::new())
    }

    /// Indent base using `NUM_INDENTATION_SPACES` more than current self.
    fn next(&self) -> Self {
        BaseIndentation(" ".repeat(self.len() + NUM_INDENTATION_SPACES))
    }

    /// Get the length of how many spaces are used for the base indentation
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl Display for BaseIndentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Support for formatting with a given base indentation (spaces) that should be applied after newlines.
trait IndentedDisplay {
    fn fmt_indented(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        base_indentation: &BaseIndentation,
    ) -> std::fmt::Result;
}

/// Display a type supporting indentation with the given amount of base indentation
struct Indented<'a, T: IndentedDisplay>(&'a T, &'a BaseIndentation);

impl<T: IndentedDisplay> Display for Indented<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt_indented(f, self.1)
    }
}

impl<N: Display> Display for json_schema::Fragment<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, (ns, def)) in self.0.iter().enumerate() {
            match ns {
                // Invariant: NamespaceDefinition always prints a newline in the end
                None => def.fmt(f)?,
                Some(ns) => writeln!(
                    f,
                    "{}namespace {ns} {{\n{}}}",
                    def.annotations,
                    Indented(def, &BaseIndentation::none().next())
                )?,
            }

            // extra newline to separate namespaces
            if i < (self.0.len() - 1) {
                writeln!(f)?
            }
        }
        Ok(())
    }
}

impl<N: Display> Display for json_schema::NamespaceDefinition<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt_indented(f, &BaseIndentation::none())
    }
}

impl<N: Display> IndentedDisplay for json_schema::NamespaceDefinition<N> {
    fn fmt_indented(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        base_indentation: &BaseIndentation,
    ) -> std::fmt::Result {
        let total_len = self.common_types.len() + self.entity_types.len() + self.actions.len();

        for (i, (n, ty)) in self.common_types.iter().enumerate() {
            ty.annotations.fmt_indented(f, base_indentation.len())?;
            writeln!(
                f,
                "{base_indentation}type {n} = {};",
                Indented(&ty.ty, base_indentation)
            )?;

            if i < (total_len - 1) {
                // only skip writing an extra newline if this is the last of all items
                writeln!(f)?
            }
        }
        for (i, (n, ty)) in self.entity_types.iter().enumerate() {
            ty.annotations.fmt_indented(f, base_indentation.len())?;
            writeln!(
                f,
                "{base_indentation}entity {n}{};",
                Indented(ty, base_indentation)
            )?;

            if self.common_types.len() + i < (total_len - 1) {
                writeln!(f)?
            }
        }
        for (i, (n, a)) in self.actions.iter().enumerate() {
            a.annotations.fmt_indented(f, base_indentation.len())?;
            writeln!(
                f,
                "{base_indentation}action \"{}\"{};",
                n.escape_debug(),
                Indented(a, base_indentation)
            )?;

            if self.common_types.len() + self.entity_types.len() + i < (total_len - 1) {
                writeln!(f)?
            }
        }
        Ok(())
    }
}

impl<N: Display> Display for json_schema::Type<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt_indented(f, &BaseIndentation::none())
    }
}

impl<N: Display> IndentedDisplay for json_schema::Type<N> {
    fn fmt_indented(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        base_indentation: &BaseIndentation,
    ) -> std::fmt::Result {
        match self {
            json_schema::Type::Type { ty, .. } => match ty {
                json_schema::TypeVariant::Boolean => write!(f, "__cedar::Bool"),
                json_schema::TypeVariant::Entity { name } => write!(f, "{name}"),
                json_schema::TypeVariant::EntityOrCommon { type_name } => {
                    write!(f, "{type_name}")
                }
                json_schema::TypeVariant::Extension { name } => write!(f, "__cedar::{name}"),
                json_schema::TypeVariant::Long => write!(f, "__cedar::Long"),
                json_schema::TypeVariant::Record(rty) => rty.fmt_indented(f, base_indentation),
                json_schema::TypeVariant::Set { element } => {
                    write!(f, "Set<{}>", Indented(element.as_ref(), base_indentation))
                } // It is possible to do Set<{"foo": String}>
                json_schema::TypeVariant::String => write!(f, "__cedar::String"),
            },
            json_schema::Type::CommonTypeRef { type_name, .. } => write!(f, "{type_name}"),
        }
    }
}

impl<N: Display> IndentedDisplay for json_schema::RecordType<N> {
    fn fmt_indented(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        base_indentation: &BaseIndentation,
    ) -> std::fmt::Result {
        // Record members are indented two spaces more than the base
        let member_indentation = base_indentation.next();

        // Don't write a newline here, as there might not be attributes, and then we want just "{}"
        write!(f, "{{")?;
        for (i, (n, ty)) in self.attributes.iter().enumerate() {
            if i == 0 {
                writeln!(f)?;
            }
            ty.annotations.fmt_indented(f, member_indentation.len())?;
            writeln!(
                f,
                "{member_indentation}\"{}\"{}: {}{}",
                n.escape_debug(),
                if ty.required { "" } else { "?" },
                Indented(&ty.ty, &member_indentation),
                // TODO: Always print trailing commas when
                // https://github.com/cedar-policy/rfcs/blob/main/text/0071-trailing-commas.md
                // has been implemented
                if i < (self.attributes.len() - 1) {
                    ","
                } else {
                    ""
                }
            )?;
        }
        write!(f, "{base_indentation}}}")?;
        Ok(())
    }
}

fn fmt_non_empty_slice<T: Display>(
    f: &mut std::fmt::Formatter<'_>,
    (head, tail): (&T, &[T]),
) -> std::fmt::Result {
    write!(f, "[{head}")?;
    for e in tail {
        write!(f, ", {e}")?;
    }
    write!(f, "]")
}

impl<N: Display> Display for json_schema::EntityType<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt_indented(f, &BaseIndentation::none())
    }
}

impl<N: Display> IndentedDisplay for json_schema::EntityType<N> {
    fn fmt_indented(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        base_indentation: &BaseIndentation,
    ) -> std::fmt::Result {
        match &self.kind {
            json_schema::EntityTypeKind::Standard(ty) => ty.fmt_indented(f, base_indentation),
            json_schema::EntityTypeKind::Enum { choices } => write!(
                f,
                " enum [{}]",
                choices
                    .iter()
                    .map(|e| format!("\"{}\"", e.escape_debug()))
                    .join(", ")
            ),
        }
    }
}

impl<N: Display> Display for json_schema::StandardEntityType<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt_indented(f, &BaseIndentation::none())
    }
}

impl<N: Display> IndentedDisplay for json_schema::StandardEntityType<N> {
    fn fmt_indented(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        base_indentation: &BaseIndentation,
    ) -> std::fmt::Result {
        if let Some(non_empty) = self.member_of_types.split_first() {
            write!(f, " in ")?;
            fmt_non_empty_slice(f, non_empty)?;
        }

        let ty = &self.shape;
        // Don't print `= { }`
        if !ty.is_empty_record() {
            write!(f, " = {}", Indented(&ty.0, base_indentation))?;
        }

        if let Some(tags) = &self.tags {
            write!(f, " tags {tags}")?;
        }

        Ok(())
    }
}

impl<N: Display> Display for json_schema::ActionType<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt_indented(f, &BaseIndentation::none())
    }
}

impl<N: Display> IndentedDisplay for json_schema::ActionType<N> {
    fn fmt_indented(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        base_indentation: &BaseIndentation,
    ) -> std::fmt::Result {
        if let Some(parents) = self.member_of.as_ref().and_then(|refs| refs.split_first()) {
            write!(f, " in ")?;
            fmt_non_empty_slice(f, parents)?;
        }
        if let Some(spec) = &self.applies_to {
            match (
                spec.principal_types.split_first(),
                spec.resource_types.split_first(),
            ) {
                // One of the lists is empty
                // This can only be represented by the empty action
                // This implies an action group
                (None, _) | (_, None) => {
                    write!(f, "")?;
                }
                // Both list are non empty
                (Some(ps), Some(rs)) => {
                    let member_indent = base_indentation.next();
                    write!(f, " appliesTo {{")?;
                    write!(f, "\n{member_indent}principal: ")?;
                    fmt_non_empty_slice(f, ps)?;
                    write!(f, ",\n{member_indent}resource: ")?;
                    fmt_non_empty_slice(f, rs)?;
                    write!(f, ",\n{member_indent}context: {}", &spec.context.0)?;

                    write!(f, "\n{base_indentation}}}")?;
                }
            }
        }
        // No `appliesTo` key: action does not apply to anything
        Ok(())
    }
}

/// Error converting a schema to the Cedar syntax
#[derive(Debug, Diagnostic, Error)]
pub enum ToCedarSchemaSyntaxError {
    /// Collisions between names prevented the conversion to the Cedar syntax
    #[diagnostic(transparent)]
    #[error(transparent)]
    NameCollisions(#[from] NameCollisionsError),
}

/// Duplicate names were found in the schema
//
// This is NOT a publicly exported error type.
#[derive(Debug, Error)]
#[error("There are name collisions: [{}]", .names.iter().join(", "))]
pub struct NameCollisionsError {
    /// Names that had collisions
    names: NonEmpty<InternalName>,
}

impl Diagnostic for NameCollisionsError {
    impl_diagnostic_from_method_on_nonempty_field!(names, loc);
}

impl NameCollisionsError {
    /// Get the names that had collisions
    pub fn names(&self) -> impl Iterator<Item = &InternalName> {
        self.names.iter()
    }
}

/// Convert a [`json_schema::Fragment`] to a string containing the Cedar schema syntax
///
/// As of this writing, this existing code throws an error if any
/// fully-qualified name in a non-empty namespace is a valid common type and
/// also a valid entity type.
//
// Two notes:
// 1) This check is more conservative than necessary. Schemas are allowed to
// shadow an entity type with a common type declaration in the same namespace;
// see RFCs 24 and 70. What the Cedar syntax can't express is if, in that
// situation, we then specifically refer to the shadowed entity type name.  But
// it's harder to walk all type references than it is to walk all type
// declarations, so the conservative code here is fine; we can always make it
// less conservative in the future without breaking people.
// 2) This code is also likely the cause of #1063; see that issue
pub fn json_schema_to_cedar_schema_str<N: Display>(
    json_schema: &json_schema::Fragment<N>,
) -> Result<String, ToCedarSchemaSyntaxError> {
    let mut name_collisions: Vec<InternalName> = Vec::new();
    for (name, ns) in json_schema.0.iter().filter(|(name, _)| !name.is_none()) {
        let entity_types: HashSet<InternalName> = ns
            .entity_types
            .keys()
            .map(|ty_name| {
                RawName::new_from_unreserved(ty_name.clone(), None).qualify_with_name(name.as_ref())
            })
            .collect();
        let common_types: HashSet<InternalName> = ns
            .common_types
            .keys()
            .map(|ty_name| {
                RawName::new_from_unreserved(ty_name.clone().into(), None)
                    .qualify_with_name(name.as_ref())
            })
            .collect();
        name_collisions.extend(entity_types.intersection(&common_types).cloned());
    }
    if let Some(non_empty_collisions) = NonEmpty::from_vec(name_collisions) {
        return Err(NameCollisionsError {
            names: non_empty_collisions,
        }
        .into());
    }
    Ok(json_schema.to_string())
}

#[cfg(test)]
mod tests {
    use crate::extensions::Extensions;

    use crate::validator::{
        cedar_schema::parser::parse_cedar_schema_fragment, json_schema, RawName,
    };

    use similar_asserts::assert_eq;

    #[track_caller]
    fn test_round_trip(src: &str) {
        let (cedar_schema, _) =
            parse_cedar_schema_fragment(src, Extensions::none()).expect("should parse");
        let printed_cedar_schema = cedar_schema.to_cedarschema().expect("should convert");
        let (parsed_cedar_schema, _) =
            parse_cedar_schema_fragment(&printed_cedar_schema, Extensions::none())
                .expect("should parse");
        assert_eq!(cedar_schema, parsed_cedar_schema);
    }

    #[test]
    fn rfc_example() {
        let src = "entity User = {
            jobLevel: Long,
          } tags Set<String>;
          entity Document = {
            owner: User,
          } tags Set<String>;";
        test_round_trip(src);
    }

    #[test]
    fn annotations() {
        let src = r#"@doc("this is the namespace")
namespace TinyTodo {
    @doc("a common type representing a task")
    type Task = {
        @doc("task id")
        "id": Long,
        "name": String,
        "state": String,
    };
    @doc("a common type representing a set of tasks")
    type Tasks = Set<Task>;

    @doc("an entity type representing a list")
    @docComment("any entity type is a child of type `Application`")
    entity List in [Application] = {
        @doc("editors of a list")
        "editors": Team,
        "name": String,
        "owner": User,
        @doc("readers of a list")
        "readers": Team,
        "tasks": Tasks,
    };

    @doc("actions that a user can operate on a list")
    action DeleteList, GetList, UpdateList appliesTo {
        principal: [User],
        resource: [List]
    };
}"#;
        test_round_trip(src);
    }

    #[test]
    fn attrs_types_roundtrip() {
        test_round_trip(r#"entity Foo {a: Bool};"#);
        test_round_trip(r#"entity Foo {a: Long};"#);
        test_round_trip(r#"entity Foo {a: String};"#);
        test_round_trip(r#"entity Foo {a: Set<Bool>};"#);
        test_round_trip(r#"entity Foo {a: {b: Long}};"#);
        test_round_trip(r#"entity Foo {a: {}};"#);
        test_round_trip(
            r#"
        type A = Long;
        entity Foo {a: A};
        "#,
        );
        test_round_trip(
            r#"
        entity A;
        entity Foo {a: A};
        "#,
        );
    }

    #[test]
    fn enum_entities_roundtrip() {
        test_round_trip(r#"entity Foo enum ["Bar", "Baz"];"#);
        test_round_trip(r#"entity Foo enum ["Bar"];"#);
        test_round_trip(r#"entity Foo enum ["\0\n\x7f"];"#);
        test_round_trip(r#"entity enum enum ["enum"];"#);
    }

    #[test]
    fn action_in_roundtrip() {
        test_round_trip(r#"action Delete in Action::"Edit";"#);
        test_round_trip(r#"action Delete in Action::"\n\x00";"#);
        test_round_trip(r#"action Delete in [Action::"Edit", Action::"Destroy"];"#);
    }

    #[test]
    fn primitives_roundtrip_to_entity_or_common() {
        // Converting cedar->json never produces these primitve type nodes, instead using `EntityOrCommon`, so we need to test this starting from json.
        let schema_json = serde_json::json!(
            {
                "": {
                    "entityTypes": {
                        "User": { },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "foo": { "type": "Long" },
                                    "bar": { "type": "String" },
                                    "baz": { "type": "Boolean" }
                                }
                            }
                        }
                    },
                    "actions": {}
                }
            }
        );

        let fragment: json_schema::Fragment<RawName> = serde_json::from_value(schema_json).unwrap();
        let cedar_schema = fragment.to_cedarschema().unwrap();

        let (parsed_cedar_schema, _) =
            parse_cedar_schema_fragment(&cedar_schema, Extensions::all_available()).unwrap();

        let roundtrip_json = serde_json::to_value(parsed_cedar_schema).unwrap();
        let expected_roundtrip = serde_json::json!(
            {
                "": {
                    "entityTypes": {
                        "User": { },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "foo": {
                                        "type": "EntityOrCommon",
                                        "name": "__cedar::Long"
                                    },
                                    "bar": {
                                        "type": "EntityOrCommon",
                                        "name": "__cedar::String"
                                    },
                                    "baz": {
                                        "type": "EntityOrCommon",
                                        "name": "__cedar::Bool"
                                    }
                                }
                            }
                        }
                    },
                    "actions": {}
                }
            }
        );

        assert_eq!(expected_roundtrip, roundtrip_json,);
    }

    #[test]
    fn entity_type_reference_roundtrips_to_entity_or_common() {
        // Converting cedar->json never produces `Entity` nodes, so we need to test this starting from json.
        let schema_json = serde_json::json!(
            {
                "": {
                    "entityTypes": {
                        "User": { },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "owner": {
                                        "type": "Entity",
                                        "name": "User"
                                    }
                                }
                            }
                        }
                    },
                    "actions": {}
                }
            }
        );

        let fragment: json_schema::Fragment<RawName> = serde_json::from_value(schema_json).unwrap();
        let cedar_schema = fragment.to_cedarschema().unwrap();

        let (parsed_cedar_schema, _) =
            parse_cedar_schema_fragment(&cedar_schema, Extensions::all_available()).unwrap();

        let roundtrip_json = serde_json::to_value(parsed_cedar_schema).unwrap();
        let expected_roundtrip = serde_json::json!(
            {
                "": {
                    "entityTypes": {
                        "User": { },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "owner": {
                                        "type": "EntityOrCommon",
                                        "name": "User"
                                    }
                                }
                            }
                        }
                    },
                    "actions": {}
                }
            }
        );

        assert_eq!(expected_roundtrip, roundtrip_json,);
    }

    #[test]
    fn extension_type_roundtrips_to_entity_or_common() {
        // Converting cedar->json never produces `Extension` nodes, so we need to test this starting from json.
        let schema_json = serde_json::json!(
            {
                "": {
                    "entityTypes": {
                        "User": { },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "owner": {
                                        "type": "Extension",
                                        "name": "Decimal"
                                    }
                                }
                            }
                        }
                    },
                    "actions": {}
                }
            }
        );

        let fragment: json_schema::Fragment<RawName> = serde_json::from_value(schema_json).unwrap();
        let cedar_schema = fragment.to_cedarschema().unwrap();

        let (parsed_cedar_schema, _) =
            parse_cedar_schema_fragment(&cedar_schema, Extensions::all_available()).unwrap();

        let roundtrip_json = serde_json::to_value(parsed_cedar_schema).unwrap();
        let expected_roundtrip = serde_json::json!(
            {
                "": {
                    "entityTypes": {
                        "User": { },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "owner": {
                                        "type": "EntityOrCommon",
                                        "name": "__cedar::Decimal"
                                    }
                                }
                            }
                        }
                    },
                    "actions": {}
                }
            }
        );

        assert_eq!(expected_roundtrip, roundtrip_json,);
    }

    #[test]
    fn test_formatting_roundtrip() {
        use crate::validator::json_schema::Fragment;
        let test_schema_str =
            std::fs::read_to_string("src/validator/cedar_schema/testfiles/example.cedarschema")
                .expect("missing test schema");
        println!("{}", test_schema_str);

        let (f, _) = Fragment::from_cedarschema_str(&test_schema_str, Extensions::all_available())
            .expect("test schema is valid");
        // assert test schema file is already formatted
        assert_eq!(
            f.to_cedarschema().expect("test schema can be displayed"),
            test_schema_str,
        )
    }
}
