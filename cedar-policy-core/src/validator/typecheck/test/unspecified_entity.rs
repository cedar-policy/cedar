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

use crate::validator::{json_schema, RawName};
use cool_asserts::assert_matches;

fn schema_with_unspecified() -> &'static str {
    r#"
{
    "entityTypes": {
        "Entity": {
            "shape": {
                "type": "Record",
                "attributes": {
                    "name": { "type": "String" }
                }
            }
        }
    },
    "actions": {
        "act1": {
            "appliesTo": {
                "principalTypes": ["Entity"],
                "resourceTypes": null
            }
        },
        "act2": {
            "appliesTo": {
                "principalTypes": null,
                "resourceTypes": ["Entity"]
            }
        },
        "act3": {
            "appliesTo": null
        }
    }
}
    "#
}

#[test]
fn unspecified_does_not_parse() {
    assert_matches!(
        serde_json::from_str::<json_schema::NamespaceDefinition<RawName>>(schema_with_unspecified()),
        Err(_)
    );
}
