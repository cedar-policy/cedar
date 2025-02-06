include!(concat!(env!("OUT_DIR"), "/cedar_policy_core.rs"));
include!(concat!(env!("OUT_DIR"), "/cedar_policy_validator.rs"));

/// Conversions between proto types and cedar_policy_core::ast types (other than policy/policyset types)
mod ast;

/// Conversions between proto types and cedar_policy_core::ast policy/policyset types
mod policy;

/// Conversions between proto types and cedar_policy_core::entities types
mod entities;

/// Conversions between proto types and cedar_policy_validator types
mod validator;
