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

//! The Cedar syntax for schemas

mod ast;
pub use ast::Path;
mod err;
pub mod fmt;
pub mod parser;
pub(crate) mod test;
pub mod to_json_schema;
pub use err::ParseError;
pub use err::{schema_warnings, SchemaWarning};
