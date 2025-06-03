use cedar_policy_core::parser::Loc;
use miette::{SourceOffset, SourceSpan};

pub(crate) struct SchemaActionLoc<'a>(&'a Loc);

impl<'a> SchemaActionLoc<'a> {
    pub(crate) fn new(loc: &'a Loc) -> Self {
        Self(loc)
    }

    pub(crate) fn context_loc(&self) -> Option<Loc> {
        // Get the full text within this location
        let text = &self.0.src[self.0.span.offset()..self.0.span.offset() + self.0.span.len()];

        // First find if we're inside an appliesTo block
        if let Some(applies_to_pos) = text.find("appliesTo") {
            // Extract everything from "appliesTo" forward
            let applies_to_text = &text[applies_to_pos..];

            // Find "context:" within the appliesTo block
            if let Some(context_pos) = applies_to_text.find("context:") {
                let absolute_context_pos = applies_to_pos + context_pos;
                let after_context = absolute_context_pos + "context:".len();

                // Skip whitespace
                let mut content_start = after_context;
                while content_start < text.len()
                    && (text.as_bytes()[content_start] as char).is_whitespace()
                {
                    content_start += 1;
                }

                if content_start < text.len() {
                    let first_char = text.as_bytes()[content_start] as char;

                    if first_char == '{' {
                        // Anonymous record - find matching closing brace
                        let mut depth = 1;
                        let mut pos = content_start + 1;

                        while pos < text.len() && depth > 0 {
                            match text.as_bytes()[pos] as char {
                                '{' => depth += 1,
                                '}' => depth -= 1,
                                _ => {}
                            }
                            pos += 1;
                        }

                        if depth == 0 {
                            // We found the complete context block
                            let context_end = pos;

                            // Calculate the absolute position in the source
                            let absolute_start = self.0.span.offset() + absolute_context_pos;
                            let length = context_end - absolute_context_pos;

                            return Some(Loc {
                                span: SourceSpan::new(SourceOffset::from(absolute_start), length),
                                src: self.0.src.clone(),
                            });
                        }
                    } else {
                        // Named type - find the end (comma, semicolon, line break or closing brace)
                        let mut pos = content_start;
                        while pos < text.len() {
                            let c = text.as_bytes()[pos] as char;
                            if c == ',' || c == ';' || c == '\n' || c == '}' {
                                break;
                            }
                            pos += 1;
                        }

                        // Trim any trailing whitespace
                        let mut end_pos = pos;
                        while end_pos > content_start
                            && (text.as_bytes()[end_pos - 1] as char).is_whitespace()
                        {
                            end_pos -= 1;
                        }

                        // Calculate the absolute position in the source
                        let absolute_start = self.0.span.offset() + absolute_context_pos;
                        let length = end_pos - absolute_context_pos;

                        return Some(Loc {
                            span: SourceSpan::new(SourceOffset::from(absolute_start), length),
                            src: self.0.src.clone(),
                        });
                    }
                }
            }
        }
        None
    }
}
