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

use lalrpop_util::lalrpop_mod;

lalrpop_mod!(
    #[allow(warnings, unused)]
    //PANIC SAFETY: lalrpop uses unwraps, and we are trusting lalrpop to generate correct code
    #[allow(clippy::unwrap_used)]
    //PANIC SAFETY: lalrpop uses slicing, and we are trusting lalrpop to generate correct code
    #[allow(clippy::indexing_slicing)]
    //PANIC SAFETY: lalrpop uses unreachable, and we are trusting lalrpop to generate correct code
    #[allow(clippy::unreachable)]
    //PANIC SAFETY: lalrpop uses panic, and we are trusting lalrpop to generate correct code
    #[allow(clippy::panic)]
    pub grammar,
    "/src/custom_schema/grammar.rs"
);
