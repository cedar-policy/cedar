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

use lsp_types::{Documentation, MarkupContent};

use crate::{
    documentation::{
        ActionDocumentation, BoolDocumentation, ContextDocumentation, PrincipalDocumentation,
        ResourceDocumentation, ToDocumentationString,
    },
    policy::DocumentContext,
};

pub(crate) struct PrincipalCompletionItem<'a> {
    cx: &'a DocumentContext<'a>,
    template: bool,
}

impl<'a> PrincipalCompletionItem<'a> {
    pub(crate) fn template(cx: &'a DocumentContext<'_>) -> Self {
        Self { cx, template: true }
    }
}

impl<'a, T> From<T> for PrincipalCompletionItem<'a>
where
    T: Into<&'a DocumentContext<'a>>,
{
    fn from(cx: T) -> Self {
        Self {
            cx: cx.into(),
            template: false,
        }
    }
}

impl From<&PrincipalCompletionItem<'_>> for PrincipalDocumentation {
    fn from(value: &PrincipalCompletionItem<'_>) -> Self {
        Self::from(value.cx)
    }
}

impl From<PrincipalCompletionItem<'_>> for lsp_types::CompletionItem {
    fn from(value: PrincipalCompletionItem<'_>) -> Self {
        let label = if value.template {
            "?principal"
        } else {
            "principal"
        }
        .to_string();

        Self {
            label,
            kind: lsp_types::CompletionItemKind::VARIABLE.into(),
            documentation: Documentation::MarkupContent(MarkupContent {
                kind: lsp_types::MarkupKind::Markdown,
                value: PrincipalDocumentation::from(&value)
                    .to_documentation_string(value.cx.schema())
                    .into_owned(),
            })
            .into(),
            ..Self::default()
        }
    }
}

pub(crate) struct ActionCompletionItem<'a> {
    cx: &'a DocumentContext<'a>,
}

impl<'a, T> From<T> for ActionCompletionItem<'a>
where
    T: Into<&'a DocumentContext<'a>>,
{
    fn from(cx: T) -> Self {
        Self { cx: cx.into() }
    }
}

impl<'a> From<&'a ActionCompletionItem<'a>> for ActionDocumentation<'a> {
    fn from(value: &'a ActionCompletionItem<'_>) -> Self {
        ActionDocumentation::new(Some(value.cx.policy.action_constraint()))
    }
}

impl From<ActionCompletionItem<'_>> for lsp_types::CompletionItem {
    fn from(value: ActionCompletionItem<'_>) -> Self {
        Self {
            label: "action".to_string(),
            kind: lsp_types::CompletionItemKind::VARIABLE.into(),
            documentation: Documentation::MarkupContent(MarkupContent {
                kind: lsp_types::MarkupKind::Markdown,
                value: ActionDocumentation::from(&value)
                    .to_documentation_string(value.cx.schema())
                    .into_owned(),
            })
            .into(),
            ..Self::default()
        }
    }
}

pub(crate) struct ResourceCompletionItem<'a> {
    cx: &'a DocumentContext<'a>,
    template: bool,
}

impl<'a> ResourceCompletionItem<'a> {
    pub(crate) fn template(cx: &'a DocumentContext<'_>) -> Self {
        Self { cx, template: true }
    }
}

impl<'a, T> From<T> for ResourceCompletionItem<'a>
where
    T: Into<&'a DocumentContext<'a>>,
{
    fn from(cx: T) -> Self {
        Self {
            cx: cx.into(),
            template: false,
        }
    }
}

impl From<&ResourceCompletionItem<'_>> for ResourceDocumentation {
    fn from(value: &ResourceCompletionItem<'_>) -> Self {
        Self::from(value.cx)
    }
}

impl From<ResourceCompletionItem<'_>> for lsp_types::CompletionItem {
    fn from(value: ResourceCompletionItem<'_>) -> Self {
        let label = if value.template {
            "?resource"
        } else {
            "resource"
        }
        .to_string();

        Self {
            label,
            kind: lsp_types::CompletionItemKind::VARIABLE.into(),
            documentation: Documentation::MarkupContent(MarkupContent {
                kind: lsp_types::MarkupKind::Markdown,
                value: ResourceDocumentation::from(&value)
                    .to_documentation_string(value.cx.schema())
                    .into_owned(),
            })
            .into(),
            ..Self::default()
        }
    }
}

pub(crate) struct ContextCompletionIem<'a> {
    cx: &'a DocumentContext<'a>,
}

impl<'a, T> From<T> for ContextCompletionIem<'a>
where
    T: Into<&'a DocumentContext<'a>>,
{
    fn from(cx: T) -> Self {
        Self { cx: cx.into() }
    }
}

impl From<&ContextCompletionIem<'_>> for ContextDocumentation {
    fn from(value: &ContextCompletionIem<'_>) -> Self {
        Self::from(value.cx)
    }
}

impl From<ContextCompletionIem<'_>> for lsp_types::CompletionItem {
    fn from(value: ContextCompletionIem<'_>) -> Self {
        Self {
            label: "context".to_string(),
            kind: lsp_types::CompletionItemKind::VARIABLE.into(),
            documentation: Documentation::MarkupContent(MarkupContent {
                kind: lsp_types::MarkupKind::Markdown,
                value: ContextDocumentation::from(&value)
                    .to_documentation_string(value.cx.schema())
                    .into_owned(),
            })
            .into(),
            ..Self::default()
        }
    }
}

pub(crate) struct BoolCompletionItem(pub(crate) bool);

impl From<BoolCompletionItem> for lsp_types::CompletionItem {
    fn from(value: BoolCompletionItem) -> Self {
        Self {
            label: value.0.to_string(),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: lsp_types::MarkupKind::Markdown,
                value: BoolDocumentation.to_documentation_string(None).into_owned(),
            })),
            kind: Some(lsp_types::CompletionItemKind::CONSTANT),
            ..Self::default()
        }
    }
}
