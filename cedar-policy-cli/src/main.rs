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

#![forbid(unsafe_code)]

use clap::Parser;
use miette::ErrorHook;

use cedar_policy_cli::{
    authorize, check_parse, evaluate, format_policies, language_version, link, new,
    partial_authorize, serialization::write_drt_json, translate_policy, translate_schema, validate,
    visualize, CedarExitCode, Cli, Commands, ErrorFormat,
};

#[cfg(feature = "protobufs")]
use cedar_policy_cli::{
    serialization::protobuf::write_drt_proto, serialization::protobuf::write_drt_proto_from_json,
};

fn main() -> CedarExitCode {
    let cli = Cli::parse();

    let err_hook: Option<ErrorHook> = match cli.err_fmt {
        ErrorFormat::Human => None, // This is the default.
        ErrorFormat::Plain => Some(Box::new(|_| {
            Box::new(miette::NarratableReportHandler::new())
        })),
        ErrorFormat::Json => Some(Box::new(|_| Box::new(miette::JSONReportHandler::new()))),
    };
    if let Some(err_hook) = err_hook {
        // PANIC SAFETY: `set_hook` returns an error if a hook has already been installed. We have just entered `main`, so we know a hook has not been installed.
        #[allow(clippy::expect_used)]
        miette::set_hook(err_hook).expect("failed to install error-reporting hook");
    }

    match cli.command {
        Commands::Authorize(args) => authorize(&args),
        Commands::Evaluate(args) => evaluate(&args).0,
        Commands::CheckParse(args) => check_parse(&args),
        Commands::Validate(args) => validate(&args),
        Commands::Format(args) => format_policies(&args),
        Commands::Link(args) => link(&args),
        Commands::TranslatePolicy(args) => translate_policy(&args),
        Commands::Visualize(args) => visualize(&args),
        Commands::TranslateSchema(args) => translate_schema(&args),
        Commands::New(args) => new(&args),
        Commands::PartiallyAuthorize(args) => partial_authorize(&args),
        Commands::WriteDRTJson(acmd) => write_drt_json(acmd),
        #[cfg(feature = "protobufs")]
        Commands::WriteDRTProto(acmd) => write_drt_proto(acmd),
        #[cfg(feature = "protobufs")]
        Commands::WriteDRTProtoFromJSON(acmd) => write_drt_proto_from_json(acmd),
        Commands::LanguageVersion => language_version(),
    }
}

#[cfg(test)]
mod test {
    use cedar_policy_cli::serialization::AnalysisCommands;
    use cedar_policy_cli::serialization::EquivalenceArgs;
    use std::path::PathBuf;

    #[test]
    fn test_json_serialize() {
        let test_data_root = PathBuf::from(r"../sample-data/sandbox_b");
        let mut schema_file = test_data_root.clone();
        schema_file.push("schema.cedarschema");
        let mut old_policies_file = test_data_root.clone();
        old_policies_file.push("policies_4.cedar");
        let new_policies_file = old_policies_file.clone();

        let acmd = AnalysisCommands::Equivalence(EquivalenceArgs {
            schema_file,
            old_policies_file,
            new_policies_file,
        });
        super::write_drt_json(acmd);
    }

    #[cfg(feature = "protobufs")]
    #[test]
    fn test_proto_serialize() {
        let test_data_root = PathBuf::from(r"../sample-data/sandbox_b");
        let mut schema_file = test_data_root.clone();
        schema_file.push("schema.cedarschema");
        let mut old_policies_file = test_data_root.clone();
        old_policies_file.push("policies_4.cedar");
        let new_policies_file = old_policies_file.clone();

        let acmd = AnalysisCommands::Equivalence(EquivalenceArgs {
            schema_file,
            old_policies_file,
            new_policies_file,
        });
        super::write_drt_proto(acmd);
    }

    #[cfg(feature = "protobufs")]
    #[test]
    fn test_proto_serialize_from_json() {
        use cedar_policy_cli::serialization::AnalyzeCommandsFromJson;
        let data = r#"
        {
            "schema":"entity Team, UserGroup in [UserGroup];\r\nentity Issue  = {\r\n  \"repo\": Repository,\r\n  \"reporter\": User,\r\n};\r\nentity Org  = {\r\n  \"members\": UserGroup,\r\n  \"owners\": UserGroup,\r\n};\r\nentity Repository  = {\r\n  \"admins\": UserGroup,\r\n  \"maintainers\": UserGroup,\r\n  \"readers\": UserGroup,\r\n  \"triagers\": UserGroup,\r\n  \"writers\": UserGroup,\r\n};\r\nentity User in [UserGroup, Team] = {\r\n  \"is_intern\": Bool,\r\n};\r\nentity File  = {\r\n  \"filename\": String,\r\n  \"owner\": User,\r\n  \"private\": Bool,\r\n};\r\n\r\naction push, pull, fork appliesTo {\r\n  principal: [User],\r\n  resource: [Repository]\r\n};\r\naction assign_issue, delete_issue, edit_issue appliesTo {\r\n  principal: [User],\r\n  resource: [Issue]\r\n};\r\naction add_reader, add_writer, add_maintainer, add_admin, add_triager appliesTo {\r\n  principal: [User],\r\n  resource: [Repository]\r\n};\r\naction view, comment appliesTo {\r\n  principal: [User],\r\n  resource: [File]\r\n};",
            "old_policy_set": "permit(principal, action in [Action::\"view\", Action::\"comment\"], resource)\r\n            when {\r\n                principal == resource.owner ||\r\n                ((resource.filename like \"*.png\" ||\r\n                resource.filename like \"*.jpg\") && !resource.private)\r\n            };\r\n",
            "new_policy_set": "permit(principal, action in [Action::\"view\", Action::\"comment\"], resource)\r\n            when {\r\n                principal == resource.owner ||\r\n                ((resource.filename like \"*.png\" ||\r\n                resource.filename like \"*.jpg\") && !resource.private)\r\n            };\r\n",
            "assumptions": ""
        }
        "#.to_string();
        let output_path = PathBuf::from("/tmp/tmp.binpb");

        let acmd = AnalyzeCommandsFromJson::Equivalence(
            cedar_policy_cli::serialization::AnalyzeCommandsFromJsonArgs { data, output_path },
        );
        super::write_drt_proto_from_json(acmd);
    }
}
