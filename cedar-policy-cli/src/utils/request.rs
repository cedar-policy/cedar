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

use cedar_policy::{Context, Request, Schema};
use clap::{ArgAction, Args};
use miette::{miette, IntoDiagnostic, Result, WrapErr};
use serde::Deserialize;

/// This struct contains the arguments that together specify a request.
#[derive(Args, Debug)]
pub struct RequestArgs {
    /// Principal for the request, e.g., User::"alice"
    #[arg(short = 'l', long)]
    pub principal: Option<String>,
    /// Action for the request, e.g., Action::"view"
    #[arg(short, long)]
    pub action: Option<String>,
    /// Resource for the request, e.g., File::"myfile.txt"
    #[arg(short, long)]
    pub resource: Option<String>,
    /// File containing a JSON object representing the context for the request.
    /// Should be a (possibly empty) map from keys to values.
    #[arg(short, long = "context", value_name = "FILE")]
    pub context_json_file: Option<String>,
    /// File containing a JSON object representing the entire request. Must have
    /// fields "principal", "action", "resource", and "context", where "context"
    /// is a (possibly empty) map from keys to values. This option replaces
    /// --principal, --action, etc.
    #[arg(long = "request-json", value_name = "FILE", conflicts_with_all = &["principal", "action", "resource", "context_json_file"])]
    pub request_json_file: Option<String>,
    /// Whether to enable request validation. This has no effect if a schema is
    /// not provided.
    #[arg(long = "request-validation", action = ArgAction::Set, default_value_t = true)]
    pub request_validation: bool,
}

impl RequestArgs {
    /// Turn this `RequestArgs` into the appropriate `Request` object
    ///
    /// `schema` will be used for schema-based parsing of the context, and also
    /// (if `self.request_validation` is `true`) for request validation.
    ///
    /// `self.request_validation` has no effect if `schema` is `None`.
    pub(crate) fn get_request(&self, schema: Option<&Schema>) -> Result<Request> {
        fn missing_req_var() -> miette::Report {
            miette!("All three (`principal`, `action`, `resource`) variables must be specified")
        }
        match &self.request_json_file {
            Some(jsonfile) => {
                let jsonstring = std::fs::read_to_string(jsonfile)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to open request-json file {jsonfile}"))?;
                let qjson: RequestJSON = serde_json::from_str(&jsonstring)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to parse request-json file {jsonfile}"))?;
                let principal = qjson
                    .principal
                    .ok_or_else(missing_req_var)?
                    .parse()
                    .wrap_err_with(|| {
                        format!("failed to parse principal in {jsonfile} as entity Uid")
                    })?;
                let action = qjson
                    .action
                    .ok_or_else(missing_req_var)?
                    .parse()
                    .wrap_err_with(|| {
                        format!("failed to parse action in {jsonfile} as entity Uid")
                    })?;
                let resource = qjson
                    .resource
                    .ok_or_else(missing_req_var)?
                    .parse()
                    .wrap_err_with(|| {
                        format!("failed to parse resource in {jsonfile} as entity Uid")
                    })?;
                let context = Context::from_json_value(qjson.context, schema.map(|s| (s, &action)))
                    .wrap_err_with(|| format!("failed to create a context from {jsonfile}"))?;
                Request::new(
                    principal,
                    action,
                    resource,
                    context,
                    if self.request_validation {
                        schema
                    } else {
                        None
                    },
                )
                .map_err(|e| miette!("{e}"))
            }
            None => {
                let principal = self
                    .principal
                    .as_ref()
                    .map(|s| {
                        s.parse().wrap_err_with(|| {
                            format!("failed to parse principal {s} as entity Uid")
                        })
                    })
                    .transpose()?;
                let action = self
                    .action
                    .as_ref()
                    .map(|s| {
                        s.parse()
                            .wrap_err_with(|| format!("failed to parse action {s} as entity Uid"))
                    })
                    .transpose()?;
                let resource = self
                    .resource
                    .as_ref()
                    .map(|s| {
                        s.parse()
                            .wrap_err_with(|| format!("failed to parse resource {s} as entity Uid"))
                    })
                    .transpose()?;
                let context: Context = match &self.context_json_file {
                    None => Context::empty(),
                    Some(jsonfile) => match std::fs::OpenOptions::new().read(true).open(jsonfile) {
                        Ok(f) => Context::from_json_file(
                            f,
                            schema.and_then(|s| Some((s, action.as_ref()?))),
                        )
                        .wrap_err_with(|| format!("failed to create a context from {jsonfile}"))?,
                        Err(e) => Err(e).into_diagnostic().wrap_err_with(|| {
                            format!("error while loading context from {jsonfile}")
                        })?,
                    },
                };
                match (principal, action, resource) {
                    (Some(principal), Some(action), Some(resource)) => Request::new(
                        principal,
                        action,
                        resource,
                        context,
                        if self.request_validation {
                            schema
                        } else {
                            None
                        },
                    )
                    .map_err(|e| miette!("{e}")),
                    _ => Err(missing_req_var()),
                }
            }
        }
    }
}

/// This struct is the serde structure expected for --request-json
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct RequestJSON {
    /// Principal for the request
    #[serde(default)]
    pub principal: Option<String>,
    /// Action for the request
    #[serde(default)]
    pub action: Option<String>,
    /// Resource for the request
    #[serde(default)]
    pub resource: Option<String>,
    /// Context for the request
    pub context: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{render_err, TEMPFILE_FILTER};
    use std::io::Write;

    fn mk_request(
        principal: Option<&str>,
        action: Option<&str>,
        resource: Option<&str>,
        context_file: Option<&str>,
        request_json_file: Option<&str>,
    ) -> RequestArgs {
        RequestArgs {
            principal: principal.map(String::from),
            action: action.map(String::from),
            resource: resource.map(String::from),
            context_json_file: context_file.map(String::from),
            request_json_file: request_json_file.map(String::from),
            request_validation: false,
        }
    }

    #[test]
    fn request_missing_args() {
        let args = mk_request(Some(r#"User::"alice""#), None, None, None, None);
        let err = args.get_request(None).unwrap_err();
        insta::assert_snapshot!(render_err(&err), @r"× All three (`principal`, `action`, `resource`) variables must be specified");
    }

    #[test]
    fn request_bad_principal() {
        let args = mk_request(
            Some("not_an_euid"),
            Some(r#"Action::"view""#),
            Some(r#"Photo::"pic""#),
            None,
            None,
        );
        let err = args.get_request(None).unwrap_err();
        insta::assert_snapshot!(render_err(&err), @r"
         × failed to parse principal not_an_euid as entity Uid
         ╰─▶ unexpected end of input
          ╭────
        1 │ not_an_euid
          ╰────
        ");
    }

    #[test]
    fn request_from_json_file_invalid() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{"principal":"User::\"alice\"", "resource":"Photo::\"pic\"","context":{}}"#,
        )
        .unwrap();
        let args = mk_request(None, None, None, None, Some(f.path().to_str().unwrap()));
        let err = args.get_request(None).unwrap_err();
        insta::with_settings!({filters => vec![TEMPFILE_FILTER]}, {
            insta::assert_snapshot!(render_err(&err), @"  × All three (`principal`, `action`, `resource`) variables must be specified");
        });
    }

    #[test]
    fn request_from_missing_json_file() {
        let args = mk_request(
            None,
            None,
            None,
            None,
            Some("/tmp/nonexistent_request.json"),
        );
        let err = args.get_request(None).unwrap_err();
        insta::assert_snapshot!(render_err(&err), @r"
        × failed to open request-json file /tmp/nonexistent_request.json
        ╰─▶ No such file or directory (os error 2)
        ");
    }

    #[test]
    fn request_with_missing_context_file() {
        let args = mk_request(
            Some(r#"User::"alice""#),
            Some(r#"Action::"view""#),
            Some(r#"Photo::"pic""#),
            Some("/tmp/nonexistent_context.json"),
            None,
        );
        let err = args.get_request(None).unwrap_err();
        insta::assert_snapshot!(render_err(&err), @r"
        × error while loading context from /tmp/nonexistent_context.json
        ╰─▶ No such file or directory (os error 2)
        ");
    }
}
