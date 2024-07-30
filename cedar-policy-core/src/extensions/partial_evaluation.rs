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
#![cfg(feature = "partial-eval")]

//! This module contains the extension for including unknown values
use crate::{
    ast::{CallStyle, Extension, ExtensionFunction, ExtensionOutputValue, Unknown, Value},
    entities::SchemaType,
    evaluator,
};

/// Create a new untyped `Unknown`
fn create_new_unknown(v: Value) -> evaluator::Result<ExtensionOutputValue> {
    Ok(ExtensionOutputValue::Unknown(Unknown::new_untyped(
        v.get_as_string()?.clone(),
    )))
}

/// Construct the extension
// PANIC SAFETY: all uses of `unwrap` here on parsing extension names are correct names
#[allow(clippy::unwrap_used)]
pub fn extension() -> Extension {
    Extension::new(
        "partial_evaluation".parse().unwrap(),
        vec![ExtensionFunction::partial_eval_unknown(
            "unknown".parse().unwrap(),
            CallStyle::FunctionStyle,
            Box::new(create_new_unknown),
            SchemaType::String,
        )],
    )
}
