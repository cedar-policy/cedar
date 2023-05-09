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
