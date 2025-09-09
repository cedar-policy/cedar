/* * Copyright Cedar Contributors
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

use std::borrow::Cow;

use cedar_policy_core::validator::ValidatorSchema;

use crate::{impl_documentation_from_markdown_file, policy::cedar::CedarTypeKind};

use super::ToDocumentationString;

#[derive(Default)]
pub(crate) struct SetDocumentation(Option<CedarTypeKind>);

impl SetDocumentation {
    pub(crate) fn new(set_type: CedarTypeKind) -> Self {
        Self(Some(set_type))
    }
}

impl ToDocumentationString for SetDocumentation {
    fn to_documentation_string(&self, _schema: Option<&ValidatorSchema>) -> Cow<'static, str> {
        let content = include_str!("markdown/hierarchy/set.md");
        match &self.0 {
            Some(elem_type) => content.replace('?', &elem_type.to_string()).into(),
            None => content.into(),
        }
    }
}

impl_documentation_from_markdown_file!(InDocumentation, "markdown/hierarchy/in.md");
impl_documentation_from_markdown_file!(HasDocumentation, "markdown/hierarchy/has.md");
impl_documentation_from_markdown_file!(IsDocumentation, "markdown/hierarchy/is.md");
impl_documentation_from_markdown_file!(ContainsDocumentation, "markdown/hierarchy/contains.md");
impl_documentation_from_markdown_file!(
    ContainsAllDocumentation,
    "markdown/hierarchy/contains_all.md"
);
impl_documentation_from_markdown_file!(
    ContainsAnyDocumentation,
    "markdown/hierarchy/contains_any.md"
);
impl_documentation_from_markdown_file!(IsEmptyDocumentation, "markdown/hierarchy/is_empty.md");

#[cfg(test)]
mod test {
    use std::{collections::BTreeMap, sync::Arc};

    use insta::assert_snapshot;
    use smol_str::ToSmolStr;

    use crate::{
        documentation::{SetDocumentation, ToDocumentationString},
        policy::cedar::{Attribute, CedarTypeKind, Record},
    };

    #[test]
    fn test_set() {
        let docs = SetDocumentation::new(CedarTypeKind::String);
        assert_snapshot!(docs.to_documentation_string(None));
        let docs = SetDocumentation::new(CedarTypeKind::Record(Record {
            attrs: Arc::new(BTreeMap::from([(
                "foo".to_smolstr(),
                Attribute::new("foo".to_smolstr(), true, Some(CedarTypeKind::Bool)),
            )])),
        }));
        assert_snapshot!(docs.to_documentation_string(None));
    }
}
