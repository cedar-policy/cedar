#![cfg(test)]
use crate::server::Backend;
use crate::server::Client;
use crate::utils::tests::remove_caret_marker;
use crate::utils::tests::slice_range;
use cool_asserts::assert_matches;
use dashmap::DashMap;
use similar_asserts::assert_eq;
use std::sync::Arc;
use tower_lsp::lsp_types::*;
use tower_lsp::LanguageServer;

// Mock client for testing
#[derive(Debug, Clone, Default)]
struct MockClient {
    diagnostics: Arc<DashMap<String, Vec<Diagnostic>>>,
}

impl MockClient {
    fn new() -> Self {
        Self {
            diagnostics: Arc::new(DashMap::new()),
        }
    }
}

#[tower_lsp::async_trait]
impl Client for MockClient {
    async fn log_message(&self, _: MessageType, _: impl std::fmt::Display + Send) {}

    async fn publish_diagnostics(&self, uri: Url, diagnostics: Vec<Diagnostic>, _: Option<i32>) {
        self.diagnostics.insert(uri.to_string(), diagnostics);
    }

    async fn code_lens_refresh(&self) -> tower_lsp::jsonrpc::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn initialize_and_shutdown() {
    let backend = Backend::new(MockClient::new());
    let result = backend
        .initialize(InitializeParams::default())
        .await
        .unwrap();

    if let Some(cmd_provider) = result.capabilities.execute_command_provider {
        // Custom commands
        assert!(cmd_provider
            .commands
            .contains(&"cedar.associateSchema".to_string()));
        assert!(cmd_provider
            .commands
            .contains(&"cedar.removeSchemaAssociation".to_string()));
        assert!(cmd_provider
            .commands
            .contains(&"cedar.findWorkspaceSchema".to_string()));
        assert!(cmd_provider
            .commands
            .contains(&"cedar.transformSchema".to_string()));
    } else {
        panic!("Execute command provider not configured");
    }
    backend.shutdown().await.unwrap();
}

#[tokio::test]
async fn did_open_did_close() {
    let backend = Backend::new(MockClient::new());

    let uri = Url::parse("file:///test/document.cedar").unwrap();
    let params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "cedar".to_string(),
            version: 1,
            text: "permit(principal, action, resource);".to_string(),
        },
    };

    backend.did_open(params).await;

    assert!(backend.documents.contains_key(&uri));
    assert!(
        backend
            .client
            .diagnostics
            .get(uri.as_str())
            .unwrap()
            .is_empty(),
        "{:?}",
        backend.client.diagnostics
    );

    let uri = Url::parse("file:///test/document.cedar").unwrap();
    let params = DidCloseTextDocumentParams {
        text_document: TextDocumentIdentifier { uri: uri.clone() },
    };

    backend.did_close(params).await;
}

#[tokio::test]
async fn did_change() {
    let backend = Backend::new(MockClient::new());
    let src = "|caret|permit|caret|(principal, action, resource);";
    let (src, start) = remove_caret_marker(src);
    let (src, end) = remove_caret_marker(src);

    let uri = Url::parse("file:///test/document.cedar").unwrap();
    let open_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "cedar".to_string(),
            version: 1,
            text: src.clone(),
        },
    };

    backend.did_open(open_params).await;

    let change_params = DidChangeTextDocumentParams {
        text_document: VersionedTextDocumentIdentifier {
            uri: uri.clone(),
            version: 2,
        },
        content_changes: vec![TextDocumentContentChangeEvent {
            range: Some(Range { start, end }),
            range_length: None,
            text: "forbid".to_string(),
        }],
    };

    backend.did_change(change_params).await;

    let doc = backend.documents.get(&uri).unwrap();
    assert_eq!(
        doc.content().to_string(),
        "forbid(principal, action, resource);"
    );
    assert_eq!(doc.version(), 2);
}

#[tokio::test]
async fn policy_diagnostic() {
    let backend = Backend::new(MockClient::new());

    let uri = Url::parse("file:///test/document.cedar").unwrap();
    let src = "permit(principal = User::\"alice\", action, resource);";
    let params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "cedar".to_string(),
            version: 1,
            text: src.to_string(),
        },
    };

    backend.did_open(params).await;

    assert!(backend.documents.contains_key(&uri));
    let diagnostic = &backend.client.diagnostics.get(uri.as_str()).unwrap()[0];
    assert_eq!(
        diagnostic.message,
        "'=' is not a valid operator in Cedar. try using '==' instead"
    );
    assert_eq!(
        r#"principal = User::"alice""#,
        slice_range(src, diagnostic.range),
    );
}

#[tokio::test]
async fn cedar_schema_diagnostic() {
    let backend = Backend::new(MockClient::new());

    let uri = Url::parse("file:///test/document.cedarschema").unwrap();
    let src = "entity E { a: X };";
    let params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "cedarschema".to_string(),
            version: 1,
            text: src.to_string(),
        },
    };

    backend.did_open(params).await;

    assert!(backend.documents.contains_key(&uri));
    let diagnostic = &backend.client.diagnostics.get(uri.as_str()).unwrap()[0];
    assert_eq!(
        diagnostic.message,
        "failed to resolve type: X. `X` has not been declared as a common or entity type"
    );
    assert_eq!("X", slice_range(src, diagnostic.range),);
}

#[tokio::test]
async fn json_schema_diagnostic() {
    let backend = Backend::new(MockClient::new());

    let uri = Url::parse("file:///test/document.cedarschema.json").unwrap();
    let src = "entity E;";
    let params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "cedarschema.json".to_string(),
            version: 1,
            text: src.to_string(),
        },
    };

    backend.did_open(params).await;

    assert!(backend.documents.contains_key(&uri));
    let diagnostic = &backend.client.diagnostics.get(uri.as_str()).unwrap()[0];
    assert_eq!(
            diagnostic.message,
            "expected value at line 1 column 1. this API was expecting a schema in the JSON format; did you mean to use a different function, which expects the Cedar schema format?"
        );
}

#[tokio::test]
async fn entities_diagnostic() {
    let backend = Backend::new(MockClient::new());

    let uri = Url::parse("file:///test/document.cedarentities.json").unwrap();
    let src = "{}";
    let params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "cedarentities.json".to_string(),
            version: 1,
            text: src.to_string(),
        },
    };

    backend.did_open(params).await;

    assert!(backend.documents.contains_key(&uri));
    let diagnostic = &backend.client.diagnostics.get(uri.as_str()).unwrap()[0];
    assert_eq!(
            diagnostic.message,
            "error during entity deserialization. invalid type: map, expected a sequence at line 1 column 0"
        );
}

#[tokio::test]
async fn policy_formatting() {
    let backend = Backend::new(MockClient::new());

    let uri = Url::parse("file:///test/document.cedar").unwrap();
    let open_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "cedar".to_string(),
            version: 1,
            text: "permit(principal,\naction,resource);".to_string(),
        },
    };

    backend.did_open(open_params).await;

    let format_params = DocumentFormattingParams {
        text_document: TextDocumentIdentifier { uri: uri.clone() },
        options: FormattingOptions {
            tab_size: 4,
            insert_spaces: true,
            ..Default::default()
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
    };

    let result = backend.formatting(format_params).await.unwrap();
    assert_eq!(
        result.unwrap()[0].new_text,
        "permit (principal, action, resource);\n"
    );
}

#[tokio::test]
async fn schema_assoc_code_lens() {
    let backend = Backend::new(MockClient::new());

    // Create and open a policy document
    let doc_uri = Url::parse("file:///test/document.cedar").unwrap();
    let open_doc_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: doc_uri.clone(),
            language_id: "cedar".to_string(),
            version: 1,
            text: "permit(principal, action, resource);".to_string(),
        },
    };
    backend.did_open(open_doc_params).await;

    // Create and open a schema document
    let schema_uri = Url::parse("file:///test/schema.cedarschema").unwrap();
    let open_schema_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: schema_uri.clone(),
            language_id: "cedarschema".to_string(),
            version: 1,
            text: "entity E; action A appliesTo {principal: E, resource: E};".to_string(),
        },
    };
    backend.did_open(open_schema_params).await;

    // Get code lens before schema association
    let code_lens_params = CodeLensParams {
        text_document: TextDocumentIdentifier {
            uri: doc_uri.clone(),
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };

    let lens = backend
        .code_lens(code_lens_params.clone())
        .await
        .unwrap()
        .unwrap();
    let lens = lens[0].command.as_ref().unwrap();
    assert_eq!("Click to associate schema", lens.title,);
    assert_eq!("cedar.schemaOptions", lens.command);

    let command_params = ExecuteCommandParams {
        command: "cedar.associateSchema".to_string(),
        arguments: vec![serde_json::json!({
            "document_uri": doc_uri.to_string(),
            "schema_uri": schema_uri.to_string()
        })],
        work_done_progress_params: WorkDoneProgressParams::default(),
    };
    backend.execute_command(command_params).await.unwrap();

    let lens = backend
        .code_lens(code_lens_params.clone())
        .await
        .unwrap()
        .unwrap();
    let lens = lens[0].command.as_ref().unwrap();
    assert_eq!(
        lens.title,
        format!("Schema: {schema_uri} (click to change or remove)")
    );
    assert_eq!("cedar.schemaOptions", lens.command,);
}

#[tokio::test]
async fn policy_hover() {
    let backend = Backend::new(MockClient::new());

    let uri = Url::parse("file:///test/document.cedar").unwrap();
    let src = "permit(prin|caret|cipal, action, resource);";
    let (src, position) = remove_caret_marker(src);
    let open_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "cedar".to_string(),
            version: 1,
            text: src.clone(),
        },
    };

    backend.did_open(open_params).await;

    let hover_params = HoverParams {
        text_document_position_params: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
            position,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
    };

    // Don't bother checking the exact hover content, just that we get one.
    backend.hover(hover_params).await.unwrap().unwrap();
}

#[tokio::test]
async fn policy_completion() {
    let backend = Backend::new(MockClient::new());

    let uri = Url::parse("file:///test/document.cedar").unwrap();
    let src = "permit(p|caret|rincipal, action, resource);";
    let (src, position) = remove_caret_marker(src);
    let open_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "cedar".to_string(),
            version: 1,
            text: src.clone(),
        },
    };

    backend.did_open(open_params).await;

    let completion_params = CompletionParams {
        text_document_position: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
            position,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
        context: None,
    };

    assert_matches!(
        backend.completion(completion_params).await.unwrap().unwrap(),
        CompletionResponse::Array(a) => assert!(!a.is_empty())
    );
}

#[tokio::test]
async fn schema_completion() {
    let backend = Backend::new(MockClient::new());

    let uri = Url::parse("file:///test/document.cedarschema").unwrap();
    let src = "a|caret|";
    let (src, position) = remove_caret_marker(src);
    let open_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "cedarschema".to_string(),
            version: 1,
            text: src.clone(),
        },
    };

    backend.did_open(open_params).await;

    let completion_params = CompletionParams {
        text_document_position: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
            position,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
        context: None,
    };

    assert_matches!(
        backend.completion(completion_params).await.unwrap().unwrap(),
        CompletionResponse::Array(a) => assert!(!a.is_empty())
    );
}

#[tokio::test]
async fn document_symbol() {
    let backend = Backend::new(MockClient::new());

    let uri = Url::parse("file:///test/document.cedar").unwrap();
    let open_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "cedar".to_string(),
            version: 1,
            text: "permit(principal, action, resource);".to_string(),
        },
    };

    backend.did_open(open_params).await;

    let symbol_params = DocumentSymbolParams {
        text_document: TextDocumentIdentifier { uri: uri.clone() },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };

    backend
        .document_symbol(symbol_params)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn folding_range() {
    let backend = Backend::new(MockClient::new());

    let uri = Url::parse("file:///test/document.cedar").unwrap();
    let open_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "cedar".to_string(),
            version: 1,
            text: "//comment\npermit(\n    principal,\n    action,\n    resource\n);\n\n//comment"
                .to_string(),
        },
    };

    backend.did_open(open_params).await;

    let folding_params = FoldingRangeParams {
        text_document: TextDocumentIdentifier { uri: uri.clone() },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };

    let range = &backend
        .folding_range(folding_params)
        .await
        .unwrap()
        .unwrap()[0];
    assert_eq!(range.start_line, 1);
    assert_eq!(range.end_line, 5);
}

#[tokio::test]
async fn goto_definition() {
    let backend = Backend::new(MockClient::new());

    let uri = Url::parse("file:///test/document.cedarschema").unwrap();
    let src = "entity Entity; action act appliesTo {principal: Ent|caret|ity, resource: Entity};";
    let (src, position) = remove_caret_marker(src);
    let open_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "cedarschema".to_string(),
            version: 1,
            text: src.clone(),
        },
    };

    backend.did_open(open_params).await;

    let definition_params = GotoDefinitionParams {
        text_document_position_params: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
            position,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };

    let def = backend
        .goto_definition(definition_params)
        .await
        .unwrap()
        .unwrap();
    assert_matches!(def, GotoDefinitionResponse::Scalar(def) => {
        assert_eq!("entity Entity;", slice_range(src.as_str(), def.range));
    })
}

#[tokio::test]
async fn did_save() {
    let backend = Backend::new(MockClient::new());

    let uri = Url::parse("file:///test/document.cedar").unwrap();
    let open_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "cedar".to_string(),
            version: 1,
            text: "permit(principal, action, resource);".to_string(),
        },
    };

    backend.did_open(open_params).await;

    let save_params = DidSaveTextDocumentParams {
        text_document: TextDocumentIdentifier { uri: uri.clone() },
        text: Some("forbid(principal, action, resource);".to_string()),
    };

    backend.did_save(save_params).await;

    let doc = backend.documents.get(&uri).unwrap();
    assert_eq!(
        doc.content().to_string(),
        "forbid(principal, action, resource);"
    );
}

#[tokio::test]
async fn execute_command_associate_schema() {
    let backend = Backend::new(MockClient::new());

    let doc_uri = Url::parse("file:///test/document.cedar").unwrap();
    let schema_uri = Url::parse("file:///test/schema.cedarschema").unwrap();
    let src = "permit(principal, action, resource) when { principal.fob == 0 };";

    let open_doc_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: doc_uri.clone(),
            language_id: "cedar".to_string(),
            version: 1,
            text: src.to_string(),
        },
    };
    backend.did_open(open_doc_params).await;

    let open_schema_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: schema_uri.clone(),
            language_id: "cedarschema".to_string(),
            version: 1,
            text: "entity E {foo: Long}; action A appliesTo {principal: E, resource: E};"
                .to_string(),
        },
    };
    backend.did_open(open_schema_params).await;

    let command_params = ExecuteCommandParams {
        command: "cedar.associateSchema".to_string(),
        arguments: vec![serde_json::json!({
            "document_uri": doc_uri.to_string(),
            "schema_uri": schema_uri.to_string()
        })],
        work_done_progress_params: WorkDoneProgressParams::default(),
    };

    backend.execute_command(command_params).await.unwrap();

    let doc = backend.documents.get(&doc_uri).unwrap();
    assert_eq!(doc.schema_url(), Some(&schema_uri));

    let diagnostic = &backend.client.diagnostics.get(doc_uri.as_str()).unwrap()[0];
    assert_eq!(
        "for policy `policy0`, attribute `fob` on entity type `E` not found. did you mean `foo`?",
        diagnostic.message
    );
    assert_eq!("principal.fob", slice_range(src, diagnostic.range));
}

#[tokio::test]
async fn goto_definition_in_schema_from_policy() {
    let backend = Backend::new(MockClient::new());

    let policy_uri = Url::parse("file:///test/document.cedar").unwrap();
    let schema_uri = Url::parse("file:///test/schema.cedarschema").unwrap();
    let policy_src = "permit(principal is Us|caret|er, action, resource);";
    let (policy_src, position) = remove_caret_marker(policy_src);
    let schema_src = "entity User; action A appliesTo {principal: User, resource: User};";

    let open_doc_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: policy_uri.clone(),
            language_id: "cedar".to_string(),
            version: 1,
            text: policy_src.to_string(),
        },
    };
    backend.did_open(open_doc_params).await;

    let open_schema_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: schema_uri.clone(),
            language_id: "cedarschema".to_string(),
            version: 1,
            text: schema_src.to_string(),
        },
    };
    backend.did_open(open_schema_params).await;

    let command_params = ExecuteCommandParams {
        command: "cedar.associateSchema".to_string(),
        arguments: vec![serde_json::json!({
            "document_uri": policy_uri.to_string(),
            "schema_uri": schema_uri.to_string()
        })],
        work_done_progress_params: WorkDoneProgressParams::default(),
    };

    backend.execute_command(command_params).await.unwrap();

    let definition_params = GotoDefinitionParams {
        text_document_position_params: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier {
                uri: policy_uri.clone(),
            },
            position,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };

    let def = backend
        .goto_definition(definition_params)
        .await
        .unwrap()
        .unwrap();
    assert_matches!(def, GotoDefinitionResponse::Scalar(def) => {
        assert_eq!("entity User;", slice_range(schema_src, def.range));
    })
}

#[tokio::test]
async fn execute_command_associate_schema_with_entities() {
    let backend = Backend::new(MockClient::new());

    let entities_uri = Url::parse("file:///test/entities.cedarentities.json").unwrap();
    let schema_uri = Url::parse("file:///test/schema.cedarschema").unwrap();

    // Create entities with an invalid attribute
    let entities_json = r#"[
        {
            "uid": { "type": "E", "id": "alice" },
            "attrs": {
                "foo": "not_a_number"
            },
            "parents": []
        }
    ]"#;

    let open_entities_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: entities_uri.clone(),
            language_id: "cedarentities.json".to_string(),
            version: 1,
            text: entities_json.to_string(),
        },
    };
    backend.did_open(open_entities_params).await;

    let open_schema_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: schema_uri.clone(),
            language_id: "cedarschema".to_string(),
            version: 1,
            text: "entity E {foo: Long}; action A appliesTo {principal: E, resource: E};"
                .to_string(),
        },
    };
    backend.did_open(open_schema_params).await;

    let command_params = ExecuteCommandParams {
        command: "cedar.associateSchema".to_string(),
        arguments: vec![serde_json::json!({
            "document_uri": entities_uri.to_string(),
            "schema_uri": schema_uri.to_string()
        })],
        work_done_progress_params: WorkDoneProgressParams::default(),
    };

    backend.execute_command(command_params).await.unwrap();

    let doc = backend.documents.get(&entities_uri).unwrap();
    assert_eq!(doc.schema_url(), Some(&schema_uri));

    let diagnostic = &backend
        .client
        .diagnostics
        .get(entities_uri.as_str())
        .unwrap()[0];
    assert_eq!(
        diagnostic.message,
        r#"entity does not conform to the schema. in attribute `foo` on `E::"alice"`, type mismatch: value was expected to have type long, but it actually has type string: `"not_a_number"`"#
    )
}

#[tokio::test]
async fn execute_command_export_policy() {
    let backend = Backend::new(MockClient::new());

    let command_params = ExecuteCommandParams {
        command: "cedar.exportPolicy".to_string(),
        arguments: vec![serde_json::json!({
            "policy_text": "forbid(principal, action in Action::\"foo\", resource) when { false };"
        })],
        work_done_progress_params: WorkDoneProgressParams::default(),
    };

    let export = backend
        .execute_command(command_params)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::json!({
          "effect": "forbid",
          "principal": {
            "op": "All"
          },
          "action": {
            "op": "in",
            "entity": {"type": "Action", "id": "foo"}
          },
          "resource": {
            "op": "All"
          },
          "conditions": [{
            "kind": "when",
            "body": {"Value": false},
          }]
        }),
        export
    );
}

#[tokio::test]
async fn execute_command_get_policies_picks() {
    let backend = Backend::new(MockClient::new());

    let command_params = ExecuteCommandParams {
        command: "cedar.getPoliciesPicks".to_string(),
        arguments: vec![serde_json::json!({
            "policy_text": "permit(principal, action, resource);",
            "selected_range": {
                "start": {"line": 0, "character": 0},
                "end": {"line": 0, "character": 33}
            }
        })],
        work_done_progress_params: WorkDoneProgressParams::default(),
    };

    let pick = backend
        .execute_command(command_params)
        .await
        .unwrap()
        .unwrap();
    let pick = pick[0]["label"].as_str().unwrap();
    assert_eq!("policy0", pick);
}

#[tokio::test]
async fn schema_to_json() {
    let backend = Backend::new(MockClient::new());

    let schema_uri = Url::parse("file:///test/schema.cedarschema").unwrap();
    let open_schema_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: schema_uri.clone(),
            language_id: "cedarschema".to_string(),
            version: 1,
            text: "entity E;".to_string(),
        },
    };
    backend.did_open(open_schema_params).await;

    let command_params = ExecuteCommandParams {
        command: "cedar.transformSchema".to_string(),
        arguments: vec![serde_json::json!({
            "schema_uri": schema_uri.to_string()
        })],
        work_done_progress_params: WorkDoneProgressParams::default(),
    };

    let transformed = backend
        .execute_command(command_params)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        r#"{
  "": {
    "entityTypes": {
      "E": {}
    },
    "actions": {}
  }
}"#,
        transformed["text"].as_str().unwrap()
    );
}

#[tokio::test]
async fn schema_to_cedar() {
    let backend = Backend::new(MockClient::new());

    let schema_uri = Url::parse("file:///test/schema.cedarschema.json").unwrap();
    let open_schema_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: schema_uri.clone(),
            language_id: "cedarschema.json".to_string(),
            version: 1,
            text: r#"{"ns": {"entityTypes": {"E": {}}, "actions":{}}}"#.to_string(),
        },
    };
    backend.did_open(open_schema_params).await;

    let command_params = ExecuteCommandParams {
        command: "cedar.transformSchema".to_string(),
        arguments: vec![serde_json::json!({
            "schema_uri": schema_uri.to_string()
        })],
        work_done_progress_params: WorkDoneProgressParams::default(),
    };

    let transformed = backend
        .execute_command(command_params)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        "namespace ns {\n  entity E;\n}\n",
        transformed["text"].as_str().unwrap()
    );
}

#[tokio::test]
async fn will_rename_files() {
    let backend = Backend::new(MockClient::new());

    let old_uri = Url::parse("file:///test/old_schema.cedarschema").unwrap();
    let new_uri = Url::parse("file:///test/new_schema.cedarschema").unwrap();

    let open_schema_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: old_uri.clone(),
            language_id: "cedarschema".to_string(),
            version: 1,
            text: "entity E".to_string(),
        },
    };
    backend.did_open(open_schema_params).await;

    let rename_params = RenameFilesParams {
        files: vec![FileRename {
            old_uri: old_uri.to_string(),
            new_uri: new_uri.to_string(),
        }],
    };

    backend.will_rename_files(rename_params).await.unwrap();
}

#[tokio::test]
async fn will_delete_files() {
    let backend = Backend::new(MockClient::new());

    let schema_uri = Url::parse("file:///test/schema.cedarschema").unwrap();
    let open_schema_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: schema_uri.clone(),
            language_id: "cedarschema".to_string(),
            version: 1,
            text: "entity E;".to_string(),
        },
    };
    backend.did_open(open_schema_params).await;

    let delete_params = DeleteFilesParams {
        files: vec![FileDelete {
            uri: schema_uri.to_string(),
        }],
    };

    backend.will_delete_files(delete_params).await.unwrap();
    assert!(!backend.documents.contains_key(&schema_uri));
}

#[tokio::test]
async fn code_action_for_misspelled_entity() {
    let backend = Backend::new(MockClient::new());

    // First, create and open a schema document
    let schema_uri = Url::parse("file:///test/schema.cedarschema").unwrap();
    let schema_text = "entity User;\nentity Resource;\naction Action appliesTo { principal: User, resource: Resource };";
    let open_schema_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: schema_uri.clone(),
            language_id: "cedarschema".to_string(),
            version: 1,
            text: schema_text.to_string(),
        },
    };
    backend.did_open(open_schema_params).await;

    // Then create and open a policy document with a misspelled entity type
    let policy_uri = Url::parse("file:///test/policy.cedar").unwrap();
    let policy_text = "permit(principal == Usr::\"alice\", action, resource);";
    let open_policy_params = DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: policy_uri.clone(),
            language_id: "cedar".to_string(),
            version: 1,
            text: policy_text.to_string(),
        },
    };
    backend.did_open(open_policy_params).await;

    // Associate the schema with the policy
    let command_params = ExecuteCommandParams {
        command: "cedar.associateSchema".to_string(),
        arguments: vec![serde_json::json!({
            "document_uri": policy_uri.to_string(),
            "schema_uri": schema_uri.to_string()
        })],
        work_done_progress_params: WorkDoneProgressParams::default(),
    };
    backend.execute_command(command_params).await.unwrap();

    // Verify that we have a diagnostic for the misspelled entity
    let diagnostic = &backend.client.diagnostics.get(policy_uri.as_str()).unwrap()[0];

    // Request code actions for the diagnostic
    let code_action_params = CodeActionParams {
        text_document: TextDocumentIdentifier {
            uri: policy_uri.clone(),
        },
        range: diagnostic.range,
        context: CodeActionContext {
            diagnostics: vec![diagnostic.clone()],
            only: None,
            trigger_kind: None,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };

    let action = &backend
        .code_action(code_action_params)
        .await
        .unwrap()
        .unwrap()[0];
    assert_matches!(
        action,
        CodeActionOrCommand::CodeAction(action) =>  {
            let edit = &action.edit.as_ref().unwrap().changes.as_ref().unwrap().get(&policy_uri).unwrap()[0];
            assert_eq!("User", edit.new_text);
            assert_eq!("Usr", slice_range(policy_text, edit.range))
        }
    )
}
