use std::collections::HashMap;

use lsp_types::{CodeAction, CodeActionContext, CodeActionKind, TextEdit, Url, WorkspaceEdit};

use super::DidYouMeanCodeAction;

#[must_use]
pub fn policy_quickfix_code_actions(
    uri: &Url,
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
                let mut changes = HashMap::new();
                changes.insert(uri.clone(), vec![edit]);
                let workspace_edit = WorkspaceEdit {
                    changes: Some(changes),
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
