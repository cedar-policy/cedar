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

/// The integer types we use (both internally and for parsing).
/// By default this is i64, but you may change to some suitable Integer type.
/// If you do change this, some tests for over/underflow will need to change as well.

/// The integer type we use internally
pub type Integer = i64;

/// The integer type we use when parsing input
pub type InputInteger = i64;
