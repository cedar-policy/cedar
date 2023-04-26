//! This module contains the extension for including unknown values
use crate::{
    ast::{CallStyle, Extension, ExtensionFunction, ExtensionOutputValue, Value},
    entities::SchemaType,
    evaluator::{self, EvaluationError},
};

fn create_new_unknown(v: Value) -> evaluator::Result<ExtensionOutputValue> {
    Ok(ExtensionOutputValue::Unknown(v.get_as_string()?.clone()))
}

fn throw_error(v: Value) -> evaluator::Result<ExtensionOutputValue> {
    let msg = v.get_as_string()?;
    let err = EvaluationError::ExtensionError {
        extension_name: "partial_evaluation".parse().unwrap(),
        msg: msg.to_string(),
    };
    Err(err)
}

/// Construct the extension
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
