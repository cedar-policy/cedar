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

use std::collections::HashMap;

use tower_lsp_server::lsp_types::{
    CodeAction, CodeActionContext, CodeActionKind, TextEdit, Uri, WorkspaceEdit,
};

use super::DidYouMeanCodeAction;

#[must_use]
pub fn policy_quickfix_code_actions(
    uri: &Uri,
    context: CodeActionContext,
) -> Option<Vec<CodeAction>> {
    let mut code_actions = Vec::new();

    for diagnostic in context.diagnostics {
        // Check if this is a diagnostic with "did you mean" suggestion
        if let Some(ref value) = diagnostic.data {
            // Try to parse the data as DidYouMeanAction
            if let Ok(did_you_mean) = serde_json::from_value::<DidYouMeanCodeAction>(value.clone())
            {
                // Create a TextEdit for the correction
                let edit = TextEdit {
                    range: did_you_mean.range,
                    new_text: did_you_mean.alternative.clone(),
                };

                // Create a workspace edit
                #[expect(
                    clippy::mutable_key_type,
                    reason = "type required by tower_lsp_server::lsp_types::WorkspaceEdit"
                )]
                let changes = HashMap::from([(uri.clone(), vec![edit])]);
                let workspace_edit = WorkspaceEdit {
                    changes: Some(changes.into_iter().collect()),
                    document_changes: None,
                    change_annotations: None,
                };

                // Create the code action
                let code_action = CodeAction {
                    title: format!("Change to '{}'", did_you_mean.alternative),
                    kind: Some(CodeActionKind::QUICKFIX),
                    diagnostics: Some(vec![diagnostic]),
                    edit: Some(workspace_edit),
                    command: None,
                    is_preferred: Some(true),
                    disabled: None,
                    data: None,
                };

                code_actions.push(code_action);
            }
        }
    }

    if code_actions.is_empty() {
        None
    } else {
        Some(code_actions)
    }
}
