use crate::ast;
use crate::entities::JsonDeserializationError;
use crate::parser::unescape;
use smol_str::SmolStr;
use thiserror::Error;

/// Errors arising while converting EST to AST
#[derive(Debug, Error)]
pub enum EstToAstError {
    /// Error while deserializing JSON
    #[error(transparent)]
    JsonDeserializationError(#[from] JsonDeserializationError),
    /// Tried to convert an EST representing a template to an AST representing a policy
    #[error("tried to convert JSON representing a template to a Policy rather than Template: {0}")]
    TemplateToPolicy(#[from] ast::ContainsSlot),
    /// Slot name was not valid for the position it was used in. (Currently, principal slots must
    /// be named `?principal`, and resource slots must be named `?resource`.)
    #[error("invalid slot name, or used in wrong position")]
    InvalidSlotName,
    /// EST contained a template slot for `action`. This is not currently allowed
    #[error("specified a slot for `action`")]
    ActionSlot,
    /// EST contained the empty JSON object `{}` where a key (operator) was expected
    #[error("Missing operator, found empty object")]
    MissingOperator,
    /// EST contained an object with multiple keys (operators) where a single operator was expected
    #[error("Found multiple operators where one was expected: {ops:?}")]
    MultipleOperators {
        /// the multiple operators that were found where one was expected
        ops: Vec<SmolStr>,
    },
    /// At most one of the operands in `a * b * c * d * ...` can be a non-{constant int}
    #[error("Multiplication must be by a constant int. Neither {arg1} nor {arg2} is a constant")]
    MultiplicationByNonConstant {
        /// First non-constant argument
        arg1: ast::Expr,
        /// Second non-constant argument
        arg2: ast::Expr,
    },
    /// Error thrown while processing string escapes
    #[error("{:?}", .0.iter().map(|e| e.to_string()).collect::<Vec<String>>())]
    UnescapeError(Vec<unescape::UnescapeError>),
}

/// Errors while instantiating a policy
#[derive(Debug, PartialEq, Error)]
pub enum InstantiationError {
    /// Template contains this slot, but a value wasn't provided for it
    #[error("failed to instantiate template: no value provided for {slot}")]
    MissedSlot {
        /// Slot which didn't have a value provided for it
        slot: ast::SlotId,
    },
}
