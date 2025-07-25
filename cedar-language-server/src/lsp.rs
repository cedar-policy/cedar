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

pub(crate) fn new_symbol(
    name: String,
    range: tower_lsp_server::lsp_types::Range,
    kind: tower_lsp_server::lsp_types::SymbolKind,
) -> tower_lsp_server::lsp_types::DocumentSymbol {
    tower_lsp_server::lsp_types::DocumentSymbol {
        name,
        detail: None,
        kind,
        tags: None,
        range,
        selection_range: range,
        children: None,
        #[allow(deprecated)]
        deprecated: None,
    }
}
