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

use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};

use anyhow::Ok;
use dashmap::DashMap;
use itertools::Itertools;
use ropey::Rope;
use tower_lsp_server::lsp_types::{
    CodeActionOrCommand, CodeActionParams, CodeActionResponse, CompletionResponse, Diagnostic,
    DocumentSymbol, FoldingRange, GotoDefinitionResponse, Hover, Position, Range, TextEdit, Uri,
};

use crate::{
    entities::entities_diagnostics,
    policy::{
        fold_policy_set, format_policy, policy_completions, policy_goto_definition, policy_hover,
        policy_quickfix_code_actions, policy_set_symbols, validate_policyset,
        PolicyLanguageFeatures,
    },
    schema::{
        fold_schema, schema_completions, schema_goto_definition, schema_symbols,
        validate_entire_schema, SchemaInfo, SchemaType,
    },
};

pub(crate) enum CedarUriKind {
    Cedar,
    Schema,
    JsonSchema,
    Entities,
}

impl CedarUriKind {
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    pub(crate) fn uri_kind(uri: &Uri) -> Option<Self> {
        if uri.path().as_str().ends_with(".cedar") {
            Some(Self::Cedar)
        } else if uri.path().as_str().ends_with(".cedarschema") {
            Some(Self::Schema)
        } else if uri.path().as_str().ends_with(".cedarschema.json") {
            Some(Self::JsonSchema)
        } else if uri.path().as_str().ends_with(".cedarentities.json") {
            Some(Self::Entities)
        } else {
            None
        }
    }
}

pub(crate) type Documents = Arc<DashMap<Uri, Document>>;

#[derive(Debug, Clone)]
pub(crate) enum Document {
    Policy(PolicyDocument),
    Schema(SchemaDocument),
    Entities(EntitiesDocument),
}

impl Document {
    pub(crate) fn try_from_state(state: DocumentState) -> Result<Self, anyhow::Error> {
        match CedarUriKind::uri_kind(&state.uri) {
            Some(CedarUriKind::Cedar) => Ok(Self::Policy(PolicyDocument {
                state,
                schema_uri: None,
            })),
            Some(CedarUriKind::Schema) => Ok(Self::Schema(SchemaDocument {
                state,
                schema_type: SchemaType::CedarSchema,
            })),
            Some(CedarUriKind::JsonSchema) => Ok(Self::Schema(SchemaDocument {
                state,
                schema_type: SchemaType::Json,
            })),
            Some(CedarUriKind::Entities) => Ok(Self::Entities(EntitiesDocument {
                state,
                schema_uri: None,
            })),
            None => Err(anyhow::anyhow!("Unknown document type")),
        }
    }

    pub(crate) fn new(
        text: &str,
        uri: &Uri,
        version: i32,
        documents: &Documents,
    ) -> Result<Self, anyhow::Error> {
        let state = DocumentState::from_content(text, uri, version, documents);
        Self::try_from_state(state)
    }

    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    pub(crate) fn new_uri(
        uri: &Uri,
        version: i32,
        documents: &Documents,
    ) -> Result<Self, anyhow::Error> {
        let state = DocumentState::from_uri(uri, version, documents)?;
        Self::try_from_state(state)
    }

    #[must_use]
    pub(crate) fn into_schema(self) -> Option<SchemaDocument> {
        match self {
            Self::Schema(schema) => Some(schema),
            _ => None,
        }
    }

    #[must_use]
    pub(crate) fn as_schema(&self) -> Option<&SchemaDocument> {
        match self {
            Self::Schema(schema) => Some(schema),
            _ => None,
        }
    }

    pub(crate) fn get_diagnostics(&self) -> anyhow::Result<Vec<Diagnostic>> {
        match self {
            Self::Policy(policy) => policy.get_diagnostics(),
            Self::Schema(schema) => Ok(schema.get_diagnostics()),
            Self::Entities(entities) => entities.get_diagnostics(),
        }
    }

    #[must_use]
    pub(crate) fn state(&self) -> &DocumentState {
        match self {
            Self::Policy(policy) => &policy.state,
            Self::Schema(schema) => &schema.state,
            Self::Entities(entities) => &entities.state,
        }
    }

    pub(crate) fn state_mut(&mut self) -> &mut DocumentState {
        match self {
            Self::Policy(policy) => &mut policy.state,
            Self::Schema(schema) => &mut schema.state,
            Self::Entities(entities) => &mut entities.state,
        }
    }

    pub(crate) fn change(&mut self, range: Option<Range>, text: &str) {
        let state = self.state_mut();
        state.change(range, text);
    }

    pub(crate) fn set_content(&mut self, content: Rope) {
        let state = self.state_mut();
        state.content = content;
    }

    pub(crate) fn set_version(&mut self, version: i32) {
        let state = self.state_mut();
        state.version = version;
    }

    #[must_use]
    pub(crate) fn content(&self) -> &Rope {
        &self.state().content
    }

    #[must_use]
    pub(crate) fn uri(&self) -> &Uri {
        &self.state().uri
    }

    #[must_use]
    pub(crate) fn format(&self) -> Option<Vec<TextEdit>> {
        if let Self::Policy(policy) = self {
            format_policy(&policy.state.content.to_string())
        } else {
            None
        }
    }

    #[must_use]
    pub(crate) fn fold(&self) -> Option<Vec<FoldingRange>> {
        match self {
            Self::Policy(ref policy) => fold_policy_set(&policy.state.content.to_string()),
            Self::Schema(schema) => fold_schema(&schema.into()),
            Self::Entities(_) => None,
        }
    }

    #[must_use]
    pub(crate) fn symbols(&self) -> Option<Vec<DocumentSymbol>> {
        match self {
            Self::Policy(ref policy) => policy_set_symbols(&policy.state.content.to_string()),
            Self::Schema(schema) => schema_symbols(&schema.into()),
            Self::Entities(_) => None,
        }
    }

    #[must_use]
    pub(crate) fn definition(&self, position: Position) -> Option<GotoDefinitionResponse> {
        match self {
            Self::Policy(policy_document) => {
                let schema = policy_document.get_schema_info();
                policy_goto_definition(
                    position,
                    &self.text(),
                    schema,
                    policy_document.schema_uri.as_ref(),
                )
            }
            Self::Schema(schema_document) => schema_goto_definition(
                position,
                &schema_document.into(),
                &schema_document.state.uri,
            ),
            Self::Entities(_) => None,
        }
    }

    #[must_use]
    pub(crate) fn completion(&self, position: Position) -> Option<CompletionResponse> {
        match self {
            Self::Policy(policy) => {
                let completions = policy_completions(
                    position,
                    &self.text(),
                    policy.get_schema_info(),
                    PolicyLanguageFeatures::default(),
                )?;
                CompletionResponse::Array(completions).into()
            }
            Self::Schema(schema_document) => {
                let schema = SchemaInfo::new(schema_document.schema_type, self.text());
                schema_completions(position, &schema)
            }
            Self::Entities(_) => None,
        }
    }

    #[must_use]
    pub(crate) fn hover(&self, position: Position) -> Option<Hover> {
        match self {
            Self::Policy(policy_document) => {
                let schema = policy_document.get_schema_info();
                policy_hover(position, &self.text(), schema)
            }
            Self::Schema(_) | Self::Entities(_) => None,
        }
    }

    pub(crate) fn code_actions(&self, params: CodeActionParams) -> Option<CodeActionResponse> {
        match self {
            Self::Policy(policy_document) => {
                let code_actions =
                    policy_quickfix_code_actions(&policy_document.state.uri, params.context)?;
                code_actions
                    .into_iter()
                    .map(CodeActionOrCommand::CodeAction)
                    .collect_vec()
                    .into()
            }
            _ => None,
        }
    }

    #[must_use]
    fn text(&self) -> String {
        self.state().content.to_string()
    }

    #[must_use]
    pub(crate) fn version(&self) -> i32 {
        self.state().version
    }

    #[must_use]
    pub(crate) fn schema_uri(&self) -> Option<&Uri> {
        match self {
            Self::Policy(policy) => policy.schema_uri.as_ref(),
            Self::Entities(entities) => entities.schema_uri.as_ref(),
            Self::Schema(_) => None,
        }
    }

    pub(crate) fn set_schema_uri(&mut self, schema_uri: Option<Uri>) {
        match self {
            Self::Policy(policy) => policy.schema_uri = schema_uri,
            Self::Entities(entities) => entities.schema_uri = schema_uri,
            Self::Schema(_) => {}
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PolicyDocument {
    state: DocumentState,
    schema_uri: Option<Uri>,
}

impl PolicyDocument {
    fn get_diagnostics(&self) -> anyhow::Result<Vec<Diagnostic>> {
        let schema = self
            .schema_uri
            .as_ref()
            .and_then(|schema_uri| self.state.get_document_or_else_read(schema_uri))
            .and_then(Document::into_schema)
            .map(|s| SchemaInfo::new(s.schema_type, s.state.content.to_string()));

        validate_policyset(&self.state.content.to_string(), schema)
    }

    fn get_diagnostics_with_schema(
        &self,
        schema: &SchemaDocument,
    ) -> anyhow::Result<Vec<Diagnostic>> {
        let schema = Some(schema.into());

        let diagnostics = validate_policyset(&self.state.content.to_string(), schema)?;
        Ok(diagnostics)
    }

    #[must_use]
    fn get_schema_info(&self) -> Option<SchemaInfo> {
        self.schema_uri
            .as_ref()
            .and_then(|schema_uri| self.state.get_document_or_else_read(schema_uri))
            .and_then(Document::into_schema)
            .map(|s| SchemaInfo::new(s.schema_type, s.state.content.to_string()))
    }
}

impl From<PolicyDocument> for Document {
    fn from(value: PolicyDocument) -> Self {
        Self::Policy(value)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SchemaDocument {
    state: DocumentState,
    schema_type: SchemaType,
}

#[derive(Debug, Clone)]
pub(crate) struct DiagnosticFragment {
    pub(crate) version: i32,
    pub(crate) diagnostics: Vec<Diagnostic>,
}

impl SchemaDocument {
    fn get_diagnostics(&self) -> Vec<Diagnostic> {
        validate_entire_schema(&self.into())
    }

    #[must_use]
    pub(crate) fn get_linked_document_diagnostics(
        &self,
    ) -> Option<HashMap<Uri, DiagnosticFragment>> {
        let documents = self.state.documents.upgrade()?;
        let mut diagnostics = HashMap::new();
        let doc_list = documents
            .iter()
            .map(|guard| guard.value().clone())
            .collect_vec();

        for doc in doc_list {
            match &doc {
                Document::Policy(policy) => {
                    if let Some(schema_uri) = &policy.schema_uri {
                        if schema_uri == &self.state.uri {
                            let d = policy.get_diagnostics_with_schema(self).ok()?;
                            let frag = DiagnosticFragment {
                                version: policy.state.version,
                                diagnostics: d,
                            };
                            diagnostics.insert(policy.state.uri.clone(), frag);
                        }
                    }
                }
                Document::Entities(entities) => {
                    if let Some(schema_uri) = &entities.schema_uri {
                        if schema_uri == &self.state.uri {
                            let d = entities.get_diagnostics_with_schema(self).ok()?;
                            let frag = DiagnosticFragment {
                                version: entities.state.version,
                                diagnostics: d,
                            };
                            diagnostics.insert(entities.state.uri.clone(), frag);
                        }
                    }
                }
                Document::Schema(_) => {}
            }
        }

        if diagnostics.is_empty() {
            return None;
        }

        Some(diagnostics)
    }

    #[must_use]
    pub(crate) fn update_linked_documents(&self, new_uri: Option<&Uri>) -> Vec<Uri> {
        let Some(documents) = self.state.documents.upgrade() else {
            return vec![];
        };
        let mut updated_doc_uris = vec![];
        documents
            .iter_mut()
            .for_each(|mut doc| match doc.value_mut() {
                Document::Policy(policy) => {
                    if let Some(schema_uri) = &policy.schema_uri {
                        if schema_uri == &self.state.uri {
                            policy.schema_uri = new_uri.cloned();
                            updated_doc_uris.push(policy.state.uri.clone());
                        }
                    }
                }
                Document::Entities(entities) => {
                    if let Some(schema_uri) = &entities.schema_uri {
                        if schema_uri == &self.state.uri {
                            entities.schema_uri = new_uri.cloned();
                            updated_doc_uris.push(entities.state.uri.clone());
                        }
                    }
                }
                Document::Schema(_) => {}
            });
        updated_doc_uris
    }
}

impl From<SchemaDocument> for Document {
    fn from(value: SchemaDocument) -> Self {
        Self::Schema(value)
    }
}

impl From<&SchemaDocument> for SchemaInfo {
    fn from(value: &SchemaDocument) -> Self {
        Self::new(value.schema_type, value.state.content.to_string())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EntitiesDocument {
    state: DocumentState,
    schema_uri: Option<Uri>,
}

impl EntitiesDocument {
    fn get_diagnostics(&self) -> anyhow::Result<Vec<Diagnostic>> {
        let schema = self
            .schema_uri
            .as_ref()
            .and_then(|schema_uri| self.state.get_document_or_else_read(schema_uri))
            .and_then(Document::into_schema)
            .map(|s| SchemaInfo::new(s.schema_type, s.state.content.to_string()));

        Ok(entities_diagnostics(&self.state.content.to_string(), schema).unwrap_or_default())
    }

    fn get_diagnostics_with_schema(
        &self,
        schema: &SchemaDocument,
    ) -> anyhow::Result<Vec<Diagnostic>> {
        let schema = Some(schema.into());

        let diagnostics =
            entities_diagnostics(&self.state.content.to_string(), schema).unwrap_or_default();
        Ok(diagnostics)
    }
}

impl From<EntitiesDocument> for Document {
    fn from(value: EntitiesDocument) -> Self {
        Self::Entities(value)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DocumentState {
    content: Rope,
    uri: Uri,
    version: i32,
    documents: Weak<DashMap<Uri, Document>>,
}

impl DocumentState {
    #[must_use]
    fn from_content(content: &str, uri: &Uri, version: i32, documents: &Documents) -> Self {
        let uri = uri.clone();
        let content = Rope::from_str(content);
        Self {
            content,
            version,
            uri,
            documents: Arc::downgrade(documents),
        }
    }

    fn from_uri(uri: &Uri, version: i32, documents: &Documents) -> Result<Self, anyhow::Error> {
        let uri = uri.clone();
        let content = Rope::from_reader(std::fs::File::open(uri.path().as_str())?)?;
        Ok(Self {
            content,
            version,
            uri,
            documents: Arc::downgrade(documents),
        })
    }

    #[must_use]
    fn get_document_or_else_read(&self, other: &Uri) -> Option<Document> {
        let documents = self.documents.upgrade()?;
        if let Some(document) = documents.get(other) {
            return Some(document.value().clone());
        }

        // Read uri from disk
        let document = std::fs::read_to_string(other.path().as_str()).ok()?;
        let document = Document::new(&document, other, 0, &documents).ok()?;
        documents.insert(other.clone(), document.clone());
        Some(document)
    }

    fn change(&mut self, range: Option<Range>, text: &str) {
        if let Some(range) = range {
            let start_idx = self.position_to_char_idx(range.start);
            let end_idx = self.position_to_char_idx(range.end);
            self.content.remove(start_idx..end_idx);
            self.content.insert(start_idx, text);
        } else {
            self.content = Rope::from_str(text);
        }
    }

    fn position_to_char_idx(&self, position: Position) -> usize {
        let line_idx = position.line as usize;
        if line_idx >= self.content.len_lines() {
            return self.content.len_chars();
        }

        let line_start = self.content.line_to_char(line_idx);
        let line = self.content.line(line_idx);
        // The default encoding for positions which servers support utf16. We
        // will need to update this if we support other encoding in the future.
        // https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#positionEncodingKind
        let char_idx_from_utf16_cu = line.utf16_cu_to_char(position.character as usize);
        line_start + char_idx_from_utf16_cu
    }
}
