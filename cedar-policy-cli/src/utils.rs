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

use miette::{IntoDiagnostic, Result, WrapErr};
use std::path::Path;

mod policies;
pub use policies::*;
mod links;
pub(crate) use links::*;
mod request;
pub use request::*;
mod schema;
pub use schema::*;
mod entities;
pub(crate) use entities::*;

// Read from a file (when `filename` is a `Some`) or stdin (when `filename` is `None`) to a `String`
pub(crate) fn read_from_file_or_stdin(
    filename: Option<&impl AsRef<Path>>,
    context: &str,
) -> Result<String> {
    let mut src_str = String::new();
    match filename {
        Some(path) => {
            src_str = std::fs::read_to_string(path)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!("failed to open {context} file {}", path.as_ref().display())
                })?;
        }
        None => {
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut src_str)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read {context} from stdin"))?;
        }
    };
    Ok(src_str)
}

// Convenient wrapper around `read_from_file_or_stdin` to just read from a file
fn read_from_file(filename: impl AsRef<Path>, context: &str) -> Result<String> {
    read_from_file_or_stdin(Some(&filename), context)
}
