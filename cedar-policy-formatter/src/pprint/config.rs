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

use super::token::WrappedToken;

/// Configuraton struct that specifies line width and indentation width
#[derive(Debug, Clone)]
pub struct Config {
    pub line_width: usize,
    pub indent_width: isize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            line_width: 80,
            indent_width: 2,
        }
    }
}

#[derive(Debug)]
pub struct Context<'a> {
    pub config: &'a Config,
    pub tokens: Vec<WrappedToken>,
}
