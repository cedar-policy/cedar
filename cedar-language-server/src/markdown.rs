use cedar_policy_core::validator::ValidatorSchema;
use std::fmt::Write as _;

mod documentation;
pub(crate) use documentation::*;

pub(crate) trait ToDocumentationString {
    fn to_documentation_string(&self, schema: Option<&ValidatorSchema>) -> String;
}

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

    pub(crate) fn bullet_list(&mut self, items: &[&str]) -> &mut Self {
        for item in items {
            let _ = writeln!(self.content, "* {item}");
        }
        self.content.push('\n');
        self
    }

    pub(crate) fn push_with_new_line(&mut self, text: &str) -> &mut Self {
        self.content.push('\n');
        self.content.push_str(text);
        self.content.push('\n');
        self
    }

    pub(crate) fn build(&self) -> String {
        self.content.clone()
    }
}
