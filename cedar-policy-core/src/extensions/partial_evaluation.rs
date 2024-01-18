/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

//! This module contains the extension for including unknown values
use crate::{
    ast::{CallStyle, Extension, ExtensionFunction, ExtensionOutputValue, Unknown, Value},
    entities::SchemaType,
    evaluator::{self, EvaluationError},
};

/// Create a new untyped `Unknown`
fn create_new_unknown(v: Value) -> evaluator::Result<ExtensionOutputValue> {
    Ok(ExtensionOutputValue::Unknown(Unknown::new_untyped(
        v.get_as_string()?.clone(),
    )))
}

fn throw_error(v: Value) -> evaluator::Result<ExtensionOutputValue> {
    let msg = v.get_as_string()?;
    // PANIC SAFETY: This name is fully static, and is a valid extension name
    #[allow(clippy::unwrap_used)]
    let err = EvaluationError::failed_extension_function_application(
        "partial_evaluation".parse().unwrap(),
        msg.to_string(),
        None, // source loc will be added by the evaluator
    );
    Err(err)
}

/// Construct the extension
// PANIC SAFETY: all uses of `unwrap` here on parsing extension names are correct names
#[allow(clippy::unwrap_used)]
pub fn extension() -> Extension {
    Extension::new(
        "partial_evaluation".parse().unwrap(),
        vec![
            ExtensionFunction::unary_never(
                "unknown".parse().unwrap(),
                CallStyle::FunctionStyle,
                Box::new(create_new_unknown),
                Some(SchemaType::String),
            ),
            ExtensionFunction::unary_never(
                "error".parse().unwrap(),
                CallStyle::FunctionStyle,
                Box::new(throw_error),
                Some(SchemaType::String),
            ),
        ],
    )
}
