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

use std::fmt::Write as _;

pub(crate) struct MarkdownBuilder {
    content: String,
}

impl MarkdownBuilder {
    pub(crate) fn new() -> Self {
        Self {
            content: String::new(),
        }
    }

    pub(crate) fn header(&mut self, text: &str) -> &mut Self {
        let _ = write!(self.content, "**{text}**\n\n");
        self
    }

    pub(crate) fn paragraph(&mut self, text: &str) -> &mut Self {
        self.content.push_str(text);
        self.content.push_str("\n\n");
        self
    }

    pub(crate) fn code_block(&mut self, language: &str, code: &str) -> &mut Self {
        let _ = write!(self.content, "```{language}\n{code}\n```\n\n");
        self
    }

    pub(crate) fn push_with_new_line(&mut self, text: &str) -> &mut Self {
        self.content.push('\n');
        self.content.push_str(text);
        self.content.push('\n');
        self
    }

    pub(crate) fn build(&mut self) -> String {
        std::mem::take(&mut self.content)
    }
}
