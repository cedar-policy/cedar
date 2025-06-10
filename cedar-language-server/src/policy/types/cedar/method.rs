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

use cedar_policy_core::ast::{Extension, ExtensionFunction};
use lsp_types::{
    CompletionItem, CompletionItemKind, CompletionItemLabelDetails, Documentation,
    InsertTextFormat, MarkupContent,
};

use crate::markdown::{ExtensionName, ToDocumentationString};

/// Represents information about a method available on a Cedar type.
///
/// Methods are operations that can be performed on specific Cedar types,
/// such as `contains()` on sets or `isIpv4()` on IP addresses. This structure
/// captures the metadata needed to provide intelligent code completion and
/// documentation for these methods in the language server.
///
/// Methods appear in Cedar policies in expressions like:
/// ```cedar
/// [1, 2, 3].contains(2)
/// ip("192.168.1.1").isIpv4()
/// ```
#[derive(Debug, Clone)]
pub(crate) struct MethodInfo {
    /// The name of the method.
    ///
    /// This is the identifier used when calling the method, such as `contains` or `isIpv4`.
    name: String,

    /// Optional documentation describing the method's purpose and behavior.
    ///
    /// This will be displayed in IDE tooltips and completion details to help
    /// users understand what the method does.
    documentation: Option<String>,

    /// The parameters accepted by the method.
    ///
    /// Each tuple contains:
    /// - The parameter name (for generating snippets and documentation)
    /// - The parameter type (for displaying type information)
    ///
    /// The receiver (`self`) parameter is not included in this list.
    args: Vec<(String, String)>, // (arg_name, arg_type)

    /// The type returned by the method.
    ///
    /// This helps users understand what kind of value the method produces,
    /// which is important for type checking and further method chaining.
    return_type: String,
}

impl MethodInfo {
    #[must_use]
    pub(crate) fn new(
        name: &str,
        documentation: Option<String>,
        args: Vec<(String, String)>,
        return_type: &str,
    ) -> Self {
        Self {
            name: name.to_string(),
            documentation,
            args,
            return_type: return_type.to_string(),
        }
    }

    #[must_use]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub(crate) fn documentation(&self) -> Option<Documentation> {
        let d = self.documentation.as_ref()?;
        Some(Documentation::MarkupContent(MarkupContent {
            kind: lsp_types::MarkupKind::Markdown,
            value: d.to_string(),
        }))
    }

    #[must_use]
    pub(crate) fn to_detail_string(&self) -> String {
        let args = self
            .args
            .iter()
            .map(|(name, typ)| format!("{name}: {typ}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{}({}) -> {}", self.name, args, self.return_type)
    }

    #[must_use]
    pub(crate) fn to_snippet_text(&self) -> String {
        if self.args.is_empty() {
            format!("{}()", self.name)
        } else {
            let args = self
                .args
                .iter()
                .enumerate()
                .map(|(i, (arg_name, _))| format!("${{{}:{}}}", i + 1, arg_name))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{}({})", self.name, args)
        }
    }

    pub(crate) fn from_extension(ext: &Extension) -> Vec<Self> {
        ext.funcs()
            .filter(|f| !f.is_constructor())
            .map(Self::from)
            .collect()
    }
}

impl From<&ExtensionFunction> for MethodInfo {
    fn from(value: &ExtensionFunction) -> Self {
        Self {
            name: value.name().to_string(),
            documentation: Some(
                ExtensionName(&value.name().to_string()).to_documentation_string(None),
            ),
            args: value
                .arg_types()
                .iter()
                .skip(1) // skip self
                .map(|ty| (ty.to_string(), ty.to_string()))
                .collect(),
            return_type: value
                .return_type()
                .map_or("void".to_string(), std::string::ToString::to_string),
        }
    }
}

impl From<MethodInfo> for CompletionItem {
    fn from(value: MethodInfo) -> Self {
        Self {
            kind: Some(CompletionItemKind::METHOD),
            detail: Some(value.to_detail_string()),
            label_details: Some(CompletionItemLabelDetails {
                description: Some(value.to_detail_string()),
                detail: None,
            }),
            documentation: value.documentation(),
            insert_text: Some(value.to_snippet_text()),
            insert_text_format: Some(InsertTextFormat::SNIPPET),
            label: value.name().to_string(),
            ..Default::default()
        }
    }
}
