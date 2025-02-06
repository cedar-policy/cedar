/// Protobuf structures for types in cedar_policy_core and cedar_policy_validator
pub mod models {
    mod cedar_policy_core {
        #![allow(missing_docs)]
        include!(concat!(env!("OUT_DIR"), "/cedar_policy_core.rs"));
    }
    mod cedar_policy_validator {
        #![allow(missing_docs)]
        include!(concat!(env!("OUT_DIR"), "/cedar_policy_validator.rs"));
    }
    pub use cedar_policy_core::*;
    pub use cedar_policy_validator::*;
}

/// Conversions between proto types and cedar_policy_core::ast types (other than policy/policyset types)
mod ast;

/// Conversions between proto types and cedar_policy_core::ast policy/policyset types
mod policy;

/// Conversions between proto types and cedar_policy_core::entities types
mod entities;

/// Conversions between proto types and cedar_policy_validator types
mod validator;
