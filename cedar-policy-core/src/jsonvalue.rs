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

//! This module provides general-purpose JSON utilities not specific to Cedar.

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

/// Wrapper around `serde_json::Value`, with a different `Deserialize`
/// implementation, such that duplicate keys in JSON objects (maps/records) are
/// not allowed (result in an error).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JsonValueWithNoDuplicateKeys(serde_json::Value);

impl std::ops::Deref for JsonValueWithNoDuplicateKeys {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// this implementation heavily borrows from the `Deserialize` implementation
// for `serde_json::Value`
impl<'de> Deserialize<'de> for JsonValueWithNoDuplicateKeys {
    fn deserialize<D>(deserializer: D) -> Result<JsonValueWithNoDuplicateKeys, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = JsonValueWithNoDuplicateKeys;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("any valid JSON value")
            }

            fn visit_bool<E>(self, value: bool) -> Result<JsonValueWithNoDuplicateKeys, E> {
                Ok(JsonValueWithNoDuplicateKeys(serde_json::Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<JsonValueWithNoDuplicateKeys, E> {
                Ok(JsonValueWithNoDuplicateKeys(serde_json::Value::Number(
                    value.into(),
                )))
            }

            fn visit_u64<E>(self, value: u64) -> Result<JsonValueWithNoDuplicateKeys, E> {
                Ok(JsonValueWithNoDuplicateKeys(serde_json::Value::Number(
                    value.into(),
                )))
            }

            fn visit_f64<E>(self, value: f64) -> Result<JsonValueWithNoDuplicateKeys, E> {
                Ok(JsonValueWithNoDuplicateKeys(
                    serde_json::Number::from_f64(value)
                        .map_or(serde_json::Value::Null, serde_json::Value::Number),
                ))
            }

            fn visit_str<E>(self, value: &str) -> Result<JsonValueWithNoDuplicateKeys, E>
            where
                E: serde::de::Error,
            {
                self.visit_string(String::from(value))
            }

            fn visit_string<E>(self, value: String) -> Result<JsonValueWithNoDuplicateKeys, E> {
                Ok(JsonValueWithNoDuplicateKeys(serde_json::Value::String(
                    value,
                )))
            }

            fn visit_none<E>(self) -> Result<JsonValueWithNoDuplicateKeys, E> {
                Ok(JsonValueWithNoDuplicateKeys(serde_json::Value::Null))
            }

            fn visit_some<D>(
                self,
                deserializer: D,
            ) -> Result<JsonValueWithNoDuplicateKeys, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Deserialize::deserialize(deserializer)
            }

            fn visit_unit<E>(self) -> Result<JsonValueWithNoDuplicateKeys, E> {
                Ok(JsonValueWithNoDuplicateKeys(serde_json::Value::Null))
            }

            fn visit_seq<A>(self, mut access: A) -> Result<JsonValueWithNoDuplicateKeys, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut vec: Vec<serde_json::Value> = Vec::new();

                while let Some(elem) = access.next_element::<JsonValueWithNoDuplicateKeys>()? {
                    vec.push(elem.0);
                }

                Ok(JsonValueWithNoDuplicateKeys(serde_json::Value::Array(vec)))
            }

            fn visit_map<A>(self, mut access: A) -> Result<JsonValueWithNoDuplicateKeys, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

                while let Some((k, v)) =
                    access.next_entry::<String, JsonValueWithNoDuplicateKeys>()?
                {
                    match map.entry(k) {
                        serde_json::map::Entry::Vacant(ventry) => {
                            ventry.insert(v.0);
                        }
                        serde_json::map::Entry::Occupied(oentry) => {
                            return Err(serde::de::Error::custom(format!(
                                "the key `{}` occurs two or more times in the same JSON object",
                                oentry.key()
                            )));
                        }
                    }
                }

                Ok(JsonValueWithNoDuplicateKeys(serde_json::Value::Object(map)))
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}

impl std::str::FromStr for JsonValueWithNoDuplicateKeys {
    type Err = serde_json::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl From<serde_json::Value> for JsonValueWithNoDuplicateKeys {
    fn from(value: serde_json::Value) -> Self {
        // the `serde_json::Value` representation cannot represent duplicate keys, so we can just wrap.
        // If there were any duplicate keys, they're already gone as a result of creating the `serde_json::Value`.
        Self(value)
    }
}

impl From<JsonValueWithNoDuplicateKeys> for serde_json::Value {
    fn from(value: JsonValueWithNoDuplicateKeys) -> Self {
        value.0
    }
}
