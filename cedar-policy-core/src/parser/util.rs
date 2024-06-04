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

//! Utility functions used by multiple parts of the parser.

use super::err::ParseErrors;

type Result<T> = std::result::Result<T, ParseErrors>;

/// Combine two `Result`s into a single `Result`
pub fn flatten_tuple_2<T1, T2>(res1: Result<T1>, res2: Result<T2>) -> Result<(T1, T2)> {
    match (res1, res2) {
        (Ok(v1), Ok(v2)) => Ok((v1, v2)),
        (Err(errs1), Ok(_)) => Err(errs1),
        (Ok(_), Err(errs2)) => Err(errs2),
        (Err(mut errs1), Err(errs2)) => {
            errs1.extend(errs2);
            Err(errs1)
        }
    }
}

/// Combine three `Result`s into a single `Result`
pub fn flatten_tuple_3<T1, T2, T3>(
    res1: Result<T1>,
    res2: Result<T2>,
    res3: Result<T3>,
) -> Result<(T1, T2, T3)> {
    let ((v1, v2), v3) = flatten_tuple_2(flatten_tuple_2(res1, res2), res3)?;
    Ok((v1, v2, v3))
}

/// Combine four `Result`s into a single `Result`
pub fn flatten_tuple_4<T1, T2, T3, T4>(
    res1: Result<T1>,
    res2: Result<T2>,
    res3: Result<T3>,
    res4: Result<T4>,
) -> Result<(T1, T2, T3, T4)> {
    let (((v1, v2), v3), v4) =
        flatten_tuple_2(flatten_tuple_2(flatten_tuple_2(res1, res2), res3), res4)?;
    Ok((v1, v2, v3, v4))
}
