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

use std::str::FromStr;
use std::sync::Arc;

use crate::document::{CedarUriKind, Document, Documents};
use crate::policy::quickpick_list;
use crate::schema::SchemaInfo;
use dashmap::DashMap;
use ropey::Rope;
use serde::Deserialize;
use serde_json::Value;
use tower_lsp_server::jsonrpc::{Error, Result};
#[allow(clippy::wildcard_imports)]
use tower_lsp_server::lsp_types::*;
use tower_lsp_server::LanguageServer;
use tracing::info;

mod test;

#[derive(Debug, Deserialize)]
struct AssociateSchemaParams {
    document_uri: Uri,
    schema_uri: Option<Uri>,
}

#[derive(Debug, Deserialize)]
struct ExportPolicyParams {
    policy_text: String,
}

#[derive(Debug, Deserialize)]
struct GetPoliciesPickParams {
    policy_text: String,
    selected_range: Range,
}

#[derive(Debug, Deserialize)]
struct TransformSchemaFormatParams {
    schema_uri: Uri,
}

pub trait Client: Clone + Send + Sync {
    fn log_message(
        &self,
        typ: MessageType,
        message: impl std::fmt::Display + Send,
    ) -> impl std::future::Future<Output = ()> + Send;

    fn publish_diagnostics(
        &self,
        uri: Uri,
        diagnostics: Vec<Diagnostic>,
        _: Option<i32>,
    ) -> impl std::future::Future<Output = ()> + Send;

    fn code_lens_refresh(
        &self,
    ) -> impl std::future::Future<Output = tower_lsp_server::jsonrpc::Result<()>> + Send;
}

impl Client for tower_lsp_server::Client {
    async fn log_message(&self, typ: MessageType, message: impl std::fmt::Display + Send) {
        self.log_message(typ, message).await;
    }

    async fn publish_diagnostics(
        &self,
        uri: Uri,
        diagnostics: Vec<Diagnostic>,
        version: Option<i32>,
    ) {
        self.publish_diagnostics(uri, diagnostics, version).await;
    }

    async fn code_lens_refresh(&self) -> tower_lsp_server::jsonrpc::Result<()> {
        self.code_lens_refresh().await
    }
}

#[derive(Debug, Clone)]
pub struct Backend<Client> {
    pub(crate) client: Client,
    pub(crate) documents: Documents,
}

impl<ClientT: Client> Backend<ClientT> {
    pub fn new(client: ClientT) -> Self {
        Self {
            client,
            documents: Arc::new(DashMap::new()),
        }
    }

    async fn send_diagnostics(&self, document: &Document) {
        if let Some(schema) = document.as_schema() {
            if let Some(linked_diagnostics) = schema.get_linked_document_diagnostics() {
                for (doc_uri, fragment) in linked_diagnostics {
                    let client = self.client.clone();
                    client
                        .publish_diagnostics(
                            doc_uri.clone(),
                            fragment.diagnostics,
                            Some(fragment.version),
                        )
                        .await;
                }
            }
        }

        let diagnostics = document.get_diagnostics();

        if let Ok(ds) = diagnostics {
            self.client
                .publish_diagnostics(document.uri().clone(), ds, document.version().into())
                .await;
        } else {
            self.client
                .log_message(MessageType::ERROR, "Failed to validate syntax")
                .await;
        }
    }

    async fn associate_schema(&self, document_uri: Uri, schema_uri: Option<Uri>) {
        // If schema_uri is None, we're removing the association
        if let Some(uri) = schema_uri {
            // Try to load the schema document if it's not already loaded
            if self.documents.get(&uri).is_none() {
                let Ok(document) = Document::new_uri(&uri, 1, &self.documents) else {
                    return;
                };
                self.documents.insert(uri.clone(), document);
            }

            info!("Associating schema! {}", uri.path());
            self.client
                .log_message(
                    MessageType::INFO,
                    format!(
                        "Associated schema {} with document {}",
                        uri.path(),
                        document_uri.path()
                    ),
                )
                .await;

            // Set the schema URI using our new method
            if let Some(mut guard) = self.documents.get_mut(&document_uri) {
                guard.value_mut().set_schema_uri(Some(uri));
                let document = guard.clone();
                drop(guard);
                self.send_diagnostics(&document).await;
            }
        } else {
            // Remove schema association
            info!("Removing schema association");
            if let Some(mut guard) = self.documents.get_mut(&document_uri) {
                guard.value_mut().set_schema_uri(None);
                let document = guard.clone();
                drop(guard);
                self.send_diagnostics(&document).await;
            }
        }
    }

    fn convert_schema_format(&self, schema_uri: &Uri) -> anyhow::Result<SchemaInfo> {
        // Get the schema document
        let schema_document = self
            .documents
            .get(schema_uri)
            .ok_or_else(|| anyhow::anyhow!("Schema document not found"))?;

        if schema_document.as_schema().is_none() {
            return Err(anyhow::anyhow!("Not a schema document"));
        }

        // Get the schema content
        let schema_content = schema_document.content().to_string();
        drop(schema_document);

        // Determine the current schema type
        let schema_info = match CedarUriKind::uri_kind(schema_uri) {
            Some(CedarUriKind::Schema) => SchemaInfo::cedar_schema(schema_content),
            Some(CedarUriKind::JsonSchema) => SchemaInfo::json_schema(schema_content),
            _ => {
                return Err(anyhow::anyhow!("Unexpected schema document uri"));
            }
        };

        // Convert the schema to the other format
        let converted = schema_info.swap_format()?;

        // Return the converted schema
        Ok(converted)
    }
}

fn initialize() -> InitializeResult {
    InitializeResult {
        capabilities: ServerCapabilities {
            document_formatting_provider: Some(OneOf::Left(true)),
            text_document_sync: Some(TextDocumentSyncCapability::Kind(
                TextDocumentSyncKind::INCREMENTAL,
            )),
            rename_provider: Some(OneOf::Left(true)),
            code_lens_provider: Some(CodeLensOptions {
                resolve_provider: Some(true),
            }),
            execute_command_provider: Some(ExecuteCommandOptions {
                commands: vec![
                    "cedar.associateSchema".to_string(),
                    "cedar.removeSchemaAssociation".to_string(),
                    "cedar.findWorkspaceSchema".to_string(),
                    "cedar.transformSchema".to_string(),
                ],
                ..ExecuteCommandOptions::default()
            }),
            completion_provider: Some(CompletionOptions {
                resolve_provider: None,
                trigger_characters: Option::Some(vec![
                    " ".to_string(),
                    "(".to_string(),
                    ":".to_string(),
                    ".".to_string(),
                    "\"".to_string(),
                ]),
                all_commit_characters: Option::Some(vec!["\n".to_string()]),
                work_done_progress_options: WorkDoneProgressOptions::default(),
                completion_item: None,
            }),
            code_action_provider: Some(CodeActionProviderCapability::Options(CodeActionOptions {
                code_action_kinds: Some(vec![CodeActionKind::QUICKFIX]),
                resolve_provider: Some(false),
                work_done_progress_options: WorkDoneProgressOptions::default(),
            })),
            hover_provider: Some(HoverProviderCapability::Simple(true)),
            folding_range_provider: Some(FoldingRangeProviderCapability::Simple(true)),
            document_symbol_provider: Some(OneOf::Left(true)),
            definition_provider: Some(OneOf::Left(true)),
            workspace: Some(WorkspaceServerCapabilities {
                workspace_folders: None,
                file_operations: Some(WorkspaceFileOperationsServerCapabilities {
                    did_create: None,
                    will_create: None,
                    will_rename: Some(FileOperationRegistrationOptions {
                        filters: vec![FileOperationFilter {
                            scheme: "file".to_string().into(),
                            pattern: FileOperationPattern {
                                glob: "**/*.cedarschema".to_string(),
                                matches: Some(FileOperationPatternKind::File),
                                options: None,
                            },
                        }],
                    }),
                    did_rename: None,
                    will_delete: Some(FileOperationRegistrationOptions {
                        filters: vec![FileOperationFilter {
                            scheme: "file".to_string().into(),
                            pattern: FileOperationPattern {
                                glob: "**/*.cedarschema".to_string(),
                                matches: Some(FileOperationPatternKind::File),
                                options: None,
                            },
                        }],
                    }),
                    did_delete: None,
                }),
            }),
            ..ServerCapabilities::default()
        },
        ..Default::default()
    }
}

impl<T: Client + Send + Sync + 'static> LanguageServer for Backend<T> {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(initialize())
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.client
            .log_message(
                MessageType::INFO,
                format!("File opened: {}", params.text_document.uri.path()),
            )
            .await;

        let Ok(mut document) = Document::new(
            &params.text_document.text,
            &params.text_document.uri,
            params.text_document.version,
            &self.documents,
        ) else {
            self.client
                .log_message(
                    MessageType::ERROR,
                    format!(
                        "Failed to parse document: {}",
                        params.text_document.uri.path()
                    ),
                )
                .await;
            return;
        };

        // Handle existing schema associations for both policy and entity files
        if let Some(guard) = self.documents.get(&params.text_document.uri) {
            let schema_uri = guard.schema_uri().cloned();
            drop(guard);

            document.set_schema_uri(schema_uri);
        }

        self.send_diagnostics(&document).await;

        self.documents.insert(params.text_document.uri, document);
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let version = params.text_document.version;

        if let Some(mut guard) = self.documents.get_mut(&uri) {
            for change in params.content_changes {
                guard.change(change.range, &change.text);
            }
            guard.set_version(version);
            let document = guard.clone();
            drop(guard);

            self.send_diagnostics(&document).await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        self.client
            .log_message(
                MessageType::INFO,
                format!("File closed: {}", params.text_document.uri.path()),
            )
            .await;
    }

    async fn will_rename_files(&self, params: RenameFilesParams) -> Result<Option<WorkspaceEdit>> {
        for file in params.files {
            let Ok(old_uri) = file.old_uri.parse::<Uri>() else {
                continue;
            };
            let Some(doc) = self.documents.get(&old_uri) else {
                continue;
            };
            let Some(schema) = doc.clone().into_schema() else {
                continue;
            };
            drop(doc);
            let Ok(new_uri) = file.new_uri.parse::<Uri>() else {
                continue;
            };
            let _ = schema.update_linked_documents(Some(&new_uri));
        }

        let _ = self.client.code_lens_refresh().await;
        Ok(None)
    }

    async fn will_delete_files(&self, params: DeleteFilesParams) -> Result<Option<WorkspaceEdit>> {
        for file in params.files {
            let Ok(uri) = file.uri.parse::<Uri>() else {
                continue;
            };
            let Some(guard) = self.documents.get(&uri) else {
                continue;
            };
            let doc = guard.clone();
            drop(guard);

            let Some(schema) = doc.as_schema() else {
                continue;
            };

            let updated_docs = schema.update_linked_documents(None);
            self.documents.remove(&uri);

            // update diagnostics for linked documents
            for doc_uri in updated_docs {
                let Some(guard) = self.documents.get(&doc_uri) else {
                    continue;
                };
                let doc = guard.clone();
                drop(guard);
                let () = self.send_diagnostics(&doc).await;
            }
        }

        let _ = self.client.code_lens_refresh().await;
        Ok(None)
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        self.client
            .log_message(
                MessageType::INFO,
                format!(
                    "Autocomplete requested: {}",
                    params.text_document_position.text_document.uri.path()
                ),
            )
            .await;

        let document = self
            .documents
            .get(&params.text_document_position.text_document.uri)
            .ok_or_else(Error::invalid_request)?;

        Ok(document.completion(params.text_document_position.position))
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        self.client
            .log_message(
                MessageType::INFO,
                format!("File saved: {}", params.text_document.uri.path()),
            )
            .await;

        let Some(text) = params.text else {
            return;
        };
        let content = Rope::from_str(&text);

        if let Some(mut guard) = self.documents.get_mut(&params.text_document.uri) {
            if guard.content() != &content {
                guard.set_content(content);
                let document = guard.clone();
                drop(guard);

                self.send_diagnostics(&document).await;
            }
        }
    }

    async fn formatting(&self, params: DocumentFormattingParams) -> Result<Option<Vec<TextEdit>>> {
        self.client
            .log_message(
                MessageType::INFO,
                format!("Formatting: {}", params.text_document.uri.path()),
            )
            .await;
        let document = self
            .documents
            .get(&params.text_document.uri)
            .ok_or_else(Error::invalid_request)?;
        Ok(document.format())
    }

    async fn code_lens(&self, params: CodeLensParams) -> Result<Option<Vec<CodeLens>>> {
        let uri = params.text_document.uri;
        // Handle both policy and entity files
        if matches!(
            CedarUriKind::uri_kind(&uri),
            Some(CedarUriKind::Cedar | CedarUriKind::Entities)
        ) {
            if let Some(doc) = self.documents.get(&uri) {
                let mut lenses = Vec::new();
                let schema_uri = doc.schema_uri().cloned();

                // Add code lenses at the top of the file to manage schema association
                let schema_association_lens = match schema_uri {
                    Some(schema_uri) => CodeLens {
                        range: Range {
                            start: Position::new(0, 0),
                            end: Position::new(0, 0),
                        },
                        command: Some(Command {
                            title: format!(
                                "Schema: {} (click to change or remove)",
                                schema_uri.path()
                            ),
                            command: "cedar.schemaOptions".to_string(),
                            arguments: Some(vec![serde_json::json!({
                                "document_uri": uri.to_string()
                            })]),
                        }),
                        data: None,
                    },
                    None => CodeLens {
                        range: Range {
                            start: Position::new(0, 0),
                            end: Position::new(0, 0),
                        },
                        command: Some(Command {
                            title: "Click to associate schema".to_string(),
                            command: "cedar.schemaOptions".to_string(),
                            arguments: Some(vec![serde_json::json!({
                                "document_uri": uri.to_string()
                            })]),
                        }),
                        data: None,
                    },
                };

                lenses.push(schema_association_lens);
                return Ok(Some(lenses));
            }
        }
        Ok(None)
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_command(&self, params: ExecuteCommandParams) -> Result<Option<Value>> {
        match params.command.as_str() {
            "cedar.associateSchema" => {
                if let Some(args) = params.arguments.first() {
                    if let Ok(associate_params) =
                        serde_json::from_value::<AssociateSchemaParams>(args.clone())
                    {
                        self.associate_schema(
                            associate_params.document_uri,
                            associate_params.schema_uri,
                        )
                        .await;
                    }
                }
            }
            "cedar.removeSchemaAssociation" => {
                if let Some(args) = params.arguments.first() {
                    if let Ok(document_uri) = serde_json::from_value::<Uri>(args.clone()) {
                        self.associate_schema(document_uri, None).await;
                    }
                }
            }
            "cedar.findWorkspaceSchema" => {
                if let Some(args) = params.arguments.first() {
                    if serde_json::from_value::<Uri>(args.clone()).is_ok() {
                        // The actual schema finding is done on the client side
                        // Here we just wait for the client to call associateSchema with the found schema
                        self.client
                            .log_message(
                                MessageType::INFO,
                                "Searching for schema in workspace...".to_string(),
                            )
                            .await;
                    }
                }
            }
            "cedar.exportPolicy" => {
                if let Some(args) = params.arguments.first() {
                    if let Ok(export_params) =
                        serde_json::from_value::<ExportPolicyParams>(args.clone())
                    {
                        let policy_json =
                            cedar_policy::Policy::from_str(&export_params.policy_text)
                                .map_err(anyhow::Error::new)
                                .and_then(|p| Ok(p.to_json()?));
                        match policy_json {
                            Ok(json_value) => {
                                // Return the JSON representation of the policy
                                return Ok(Some(json_value));
                            }
                            Err(err) => {
                                self.client
                                    .log_message(
                                        MessageType::ERROR,
                                        format!("Failed to export policy to JSON: {err}"),
                                    )
                                    .await;
                            }
                        }
                    }
                }
            }
            "cedar.getPoliciesPicks" => {
                if let Some(args) = params.arguments.first() {
                    if let Ok(policy_picks_params) =
                        serde_json::from_value::<GetPoliciesPickParams>(args.clone())
                    {
                        match quickpick_list(
                            &policy_picks_params.policy_text,
                            policy_picks_params.selected_range,
                        ) {
                            Ok(items) => {
                                // Return the list of quick pick items
                                let value = serde_json::to_value(items)
                                    .map_err(|_| Error::internal_error())?;
                                return Ok(Some(value));
                            }
                            Err(err) => {
                                self.client
                                    .log_message(
                                        MessageType::ERROR,
                                        format!("Failed to get policy picks: {err}"),
                                    )
                                    .await;
                            }
                        }
                    }
                }
            }
            "cedar.transformSchema" => {
                if let Some(args) = params.arguments.first() {
                    if let Ok(convert_params) =
                        serde_json::from_value::<TransformSchemaFormatParams>(args.clone())
                    {
                        match self.convert_schema_format(&convert_params.schema_uri) {
                            Ok(result) => {
                                return Ok(Some(
                                    serde_json::to_value(result)
                                        .map_err(|_| Error::internal_error())?,
                                ));
                            }
                            Err(err) => {
                                self.client
                                    .log_message(
                                        MessageType::ERROR,
                                        format!("Failed to convert schema format: {err}"),
                                    )
                                    .await;
                                return Ok(None);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(None)
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let document = self
            .documents
            .get(&params.text_document_position_params.text_document.uri)
            .ok_or_else(Error::invalid_request)?;

        Ok(document.hover(params.text_document_position_params.position))
    }

    async fn folding_range(&self, params: FoldingRangeParams) -> Result<Option<Vec<FoldingRange>>> {
        let document = self
            .documents
            .get(&params.text_document.uri)
            .ok_or_else(Error::invalid_request)?;

        Ok(document.fold())
    }

    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
        let document = self
            .documents
            .get(&params.text_document.uri)
            .ok_or_else(Error::invalid_request)?;

        Ok(document.symbols().map(DocumentSymbolResponse::Nested))
    }

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let document = self
            .documents
            .get(&params.text_document_position_params.text_document.uri)
            .ok_or_else(Error::invalid_request)?;

        Ok(document.definition(params.text_document_position_params.position))
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let document = self
            .documents
            .get(&params.text_document.uri)
            .ok_or_else(Error::invalid_request)?;

        Ok(document.code_actions(params))
    }
}
