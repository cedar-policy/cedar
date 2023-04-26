//! This module contains type information for all of the standard Cedar extensions.

use crate::extension_schema::ExtensionSchema;

#[cfg(feature = "ipaddr")]
pub mod ipaddr;

#[cfg(feature = "decimal")]
pub mod decimal;

pub mod partial_evaluation;

/// Get schemas for all the available extensions.
pub fn all_available_extension_schemas() -> Vec<ExtensionSchema> {
    vec![
        #[cfg(feature = "ipaddr")]
        ipaddr::extension_schema(),
        #[cfg(feature = "decimal")]
        decimal::extension_schema(),
        partial_evaluation::extension_schema(),
    ]
}
