/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

use std::collections::HashMap;

use cedar_policy::EntityUid;
use cedar_policy::Value;
use cedar_policy::SlotId;
use cedar_policy_cli::check_parse;
use cedar_policy_cli::{
    authorize, evaluate, link, validate, Arguments, AuthorizeArgs, CedarExitCode, CheckParseArgs,
    EvaluateArgs, LinkArgs, RequestArgs, ValidateArgs,
};

fn run_check_parse_test(policies_file: impl Into<String>, expected_exit_code: CedarExitCode) {
    let cmd = CheckParseArgs {
        policies_file: Some(policies_file.into()),
    };
    let output = check_parse(&cmd);
    assert_eq!(output, expected_exit_code, "{:#?}", cmd);
}

fn run_authorize_test(
    policies_file: &str,
    entities_file: &str,
    principal: &str,
    action: &str,
    resource: &str,
    exit_code: CedarExitCode,
) {
    run_authorize_test_with_linked_policies(
        policies_file,
        entities_file,
        None,
        principal,
        action,
        resource,
        exit_code,
    );
}

fn run_authorize_test_with_linked_policies(
    policies_file: &str,
    entities_file: &str,
    links_file: Option<&str>,
    principal: &str,
    action: &str,
    resource: &str,
    exit_code: CedarExitCode,
) {
    let cmd = AuthorizeArgs {
        request: RequestArgs {
            principal: Some(principal.into()),
            action: Some(action.into()),
            resource: Some(resource.into()),
            context_json_file: None,
            request_json_file: None,
        },
        policies_file: policies_file.into(),
        template_linked_file: links_file.map(|x| x.to_string()),
        schema_file: None,
        entities_file: entities_file.into(),
        verbose: true,
        timing: false,
    };
    let output = authorize(&cmd);
    assert_eq!(exit_code, output, "{:#?}", cmd,);
}

fn run_link_test(
    policies_file: &str,
    links_file: &str,
    template_id: &str,
    linked_id: &str,
    env: HashMap<SlotId, String>,
    expected: CedarExitCode,
) {
    let cmd = LinkArgs {
        policies_file: policies_file.into(),
        template_linked_file: links_file.into(),
        template_id: template_id.into(),
        new_id: linked_id.into(),
        arguments: Arguments { data: env },
    };
    let output = link(&cmd);
    assert_eq!(output, expected);
}

fn run_format_test(policies_file: &str) {
    let format_cmd = assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("format")
        .arg(policies_file)
        .assert();
    assert_eq!(
        std::str::from_utf8(&format_cmd.get_output().stdout).expect("output should be decodable"),
        std::fs::read_to_string(policies_file).unwrap()
    );
}

fn run_authorize_test_context(
    policies_file: &str,
    entities_file: &str,
    principal: &str,
    action: &str,
    resource: &str,
    context_file: &str,
    exit_code: CedarExitCode,
) {
    let cmd = AuthorizeArgs {
        request: RequestArgs {
            principal: Some(principal.into()),
            action: Some(action.into()),
            resource: Some(resource.into()),
            context_json_file: Some(context_file.into()),
            request_json_file: None,
        },
        policies_file: policies_file.into(),
        template_linked_file: None,
        schema_file: None,
        entities_file: entities_file.into(),
        verbose: true,
        timing: false,
    };
    let output = authorize(&cmd);
    assert_eq!(exit_code, output, "{:#?}", cmd,);
}

fn run_authorize_test_json(
    policies_file: &str,
    entities_file: &str,
    request_json: &str,
    exit_code: CedarExitCode,
) {
    let cmd = AuthorizeArgs {
        request: RequestArgs {
            principal: None,
            action: None,
            resource: None,
            context_json_file: None,
            request_json_file: Some(request_json.into()),
        },
        policies_file: policies_file.into(),
        template_linked_file: None,
        schema_file: None,
        entities_file: entities_file.into(),
        verbose: true,
        timing: false,
    };
    let output = authorize(&cmd);
    assert_eq!(exit_code, output, "{:#?}", cmd,);
}

#[test]
fn test_authorize_samples() {
    run_check_parse_test(
        "sample-data/sandbox_a/policies_1.cedar",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_1.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"alice\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Success,
    );
    run_check_parse_test(
        "sample-data/sandbox_a/policies_2.cedar",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_2.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"alice\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_2.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"alice\"",
        "Action::\"edit\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_2.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"alice\"",
        "Action::\"delete\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_2.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"alice\"",
        "Action::\"comment\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::AuthorizeDeny,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_2.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"bob\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_2.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"bob\"",
        "Action::\"edit\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::AuthorizeDeny,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_2.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"bob\"",
        "Action::\"delete\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::AuthorizeDeny,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_2.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"bob\"",
        "Action::\"comment\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::AuthorizeDeny,
    );
    run_check_parse_test(
        "sample-data/sandbox_a/policies_3.cedar",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_3.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"alice\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_3.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"bob\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_3.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"tim\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_3.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"alice\"",
        "Action::\"listPhotos\"",
        "Album::\"jane_vacation\"",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_3.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"bob\"",
        "Action::\"listPhotos\"",
        "Album::\"jane_vacation\"",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_a/policies_3.cedar",
        "sample-data/sandbox_a/entities.json",
        "User::\"tim\"",
        "Action::\"listPhotos\"",
        "Album::\"jane_vacation\"",
        CedarExitCode::Success,
    );

    run_check_parse_test(
        "sample-data/sandbox_b/policies_4.cedar",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_b/policies_4.cedar",
        "sample-data/sandbox_b/entities.json",
        "User::\"alice\"",
        "Action::\"view\"",
        "Photo::\"prototype_v0.jpg\"",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_b/policies_4.cedar",
        "sample-data/sandbox_b/entities.json",
        "User::\"stacey\"",
        "Action::\"view\"",
        "Photo::\"prototype_v0.jpg\"",
        CedarExitCode::AuthorizeDeny,
    );
    run_authorize_test(
        "sample-data/sandbox_b/policies_4.cedar",
        "sample-data/sandbox_b/entities.json",
        "User::\"ahmad\"",
        "Action::\"view\"",
        "Photo::\"prototype_v0.jpg\"",
        CedarExitCode::AuthorizeDeny,
    );
    run_authorize_test(
        "sample-data/sandbox_b/policies_5.cedar",
        "sample-data/sandbox_b/entities.json",
        "User::\"stacey\"",
        "Action::\"view\"",
        "Photo::\"alice_w2.jpg\"",
        CedarExitCode::AuthorizeDeny,
    );
    run_check_parse_test(
        "sample-data/sandbox_b/policies_5.cedar",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_b/policies_5.cedar",
        "sample-data/sandbox_b/entities.json",
        "User::\"alice\"",
        "Action::\"view\"",
        "Photo::\"alice_w2.jpg\"",
        CedarExitCode::Success,
    );
    run_authorize_test(
        "sample-data/sandbox_b/policies_5.cedar",
        "sample-data/sandbox_b/entities.json",
        "User::\"stacey\"",
        "Action::\"view\"",
        "Photo::\"vacation.jpg\"",
        CedarExitCode::Success,
    );
    run_authorize_test_context(
        "sample-data/sandbox_b/policies_6.cedar",
        "sample-data/sandbox_b/entities.json",
        "User::\"alice\"",
        "Action::\"view\"",
        "Photo::\"vacation.jpg\"",
        "sample-data/sandbox_b/doesnotexist.json",
        CedarExitCode::Failure,
    );
    run_authorize_test_context(
        "sample-data/sandbox_b/policies_6.cedar",
        "sample-data/sandbox_b/entities.json",
        "User::\"alice\"",
        "Action::\"view\"",
        "Photo::\"vacation.jpg\"",
        "sample-data/sandbox_b/context.json",
        CedarExitCode::Success,
    );

    run_authorize_test_json(
        "sample-data/tiny_sandboxes/sample1/policy.cedar",
        "sample-data/tiny_sandboxes/sample1/entity.json",
        "sample-data/tiny_sandboxes/sample1/request.json",
        CedarExitCode::Success,
    );
    run_authorize_test_json(
        "sample-data/tiny_sandboxes/sample2/policy.cedar",
        "sample-data/tiny_sandboxes/sample2/entity.json",
        "sample-data/tiny_sandboxes/sample2/request.json",
        CedarExitCode::Success,
    );
    run_authorize_test_json(
        "sample-data/tiny_sandboxes/sample3/policy.cedar",
        "sample-data/tiny_sandboxes/sample3/entity.json",
        "sample-data/tiny_sandboxes/sample3/request.json",
        CedarExitCode::AuthorizeDeny,
    );
    run_authorize_test_json(
        "sample-data/tiny_sandboxes/sample4/policy.cedar",
        "sample-data/tiny_sandboxes/sample4/entity.json",
        "sample-data/tiny_sandboxes/sample4/request.json",
        CedarExitCode::Success,
    );
    run_authorize_test_json(
        "sample-data/tiny_sandboxes/sample5/policy.cedar",
        "sample-data/tiny_sandboxes/sample5/entity.json",
        "sample-data/tiny_sandboxes/sample5/request.json",
        CedarExitCode::Success,
    );
    run_authorize_test_json(
        "sample-data/tiny_sandboxes/sample6/policy.cedar",
        "sample-data/tiny_sandboxes/sample6/entity.json",
        "sample-data/tiny_sandboxes/sample6/request.json",
        CedarExitCode::AuthorizeDeny,
    );
    run_authorize_test_json(
        "sample-data/tiny_sandboxes/sample7/policy.cedar",
        "sample-data/tiny_sandboxes/sample7/entity.json",
        "sample-data/tiny_sandboxes/sample7/request.json",
        CedarExitCode::Success,
    );
}

fn run_validate_test(policies_file: &str, schema_file: &str, exit_code: CedarExitCode) {
    let cmd = ValidateArgs {
        schema_file: schema_file.into(),
        policies_file: policies_file.into(),
    };
    let output = validate(&cmd);
    assert_eq!(exit_code, output, "{:#?}", cmd);
}

#[test]
fn test_validate_samples() {
    run_validate_test(
        "sample-data/doesnotexist.cedar",
        "sample-data/sandbox_a/schema.cedarschema.json",
        CedarExitCode::Failure,
    );
    run_validate_test(
        "sample-data/sandbox_a/policies_1.cedar",
        "sample-data/doesnotexist.json",
        CedarExitCode::Failure,
    );
    run_validate_test(
        "sample-data/sandbox_a/policies_1.cedar",
        "sample-data/sandbox_a/schema.cedarschema.json",
        CedarExitCode::Success,
    );
    // Contains misspelled entity type.
    run_validate_test(
        "sample-data/sandbox_a/policies_1_bad.cedar",
        "sample-data/sandbox_a/schema.cedarschema.json",
        CedarExitCode::ValidationFailure,
    );
    run_validate_test(
        "sample-data/sandbox_a/policies_2.cedar",
        "sample-data/sandbox_a/schema.cedarschema.json",
        CedarExitCode::Success,
    );
    run_validate_test(
        "sample-data/sandbox_a/policies_3.cedar",
        "sample-data/sandbox_a/schema.cedarschema.json",
        CedarExitCode::Success,
    );
    run_validate_test(
        "sample-data/sandbox_b/policies_4.cedar",
        "sample-data/sandbox_b/schema.cedarschema.json",
        CedarExitCode::Success,
    );
    // Contains an access to an optional attribute without a `has` check.
    run_validate_test(
        "sample-data/sandbox_b/policies_5_bad.cedar",
        "sample-data/sandbox_b/schema.cedarschema.json",
        CedarExitCode::ValidationFailure,
    );
    run_validate_test(
        "sample-data/sandbox_b/policies_5.cedar",
        "sample-data/sandbox_b/schema.cedarschema.json",
        CedarExitCode::Success,
    );
    run_validate_test(
        "sample-data/sandbox_b/policies_6.cedar",
        "sample-data/sandbox_b/schema.cedarschema.json",
        CedarExitCode::Success,
    );
    run_validate_test(
        "sample-data/tiny_sandboxes/sample1/policy.cedar",
        "sample-data/tiny_sandboxes/sample1/schema.cedarschema.json",
        CedarExitCode::Success,
    );
    run_validate_test(
        "sample-data/tiny_sandboxes/sample2/policy.cedar",
        "sample-data/tiny_sandboxes/sample2/schema.cedarschema.json",
        CedarExitCode::Success,
    );
    run_validate_test(
        "sample-data/tiny_sandboxes/sample3/policy.cedar",
        "sample-data/tiny_sandboxes/sample3/schema.cedarschema.json",
        CedarExitCode::Success,
    );
    run_validate_test(
        "sample-data/tiny_sandboxes/sample4/policy.cedar",
        "sample-data/tiny_sandboxes/sample4/schema.cedarschema.json",
        CedarExitCode::Success,
    );
    run_validate_test(
        "sample-data/tiny_sandboxes/sample5/policy.cedar",
        "sample-data/tiny_sandboxes/sample5/schema.cedarschema.json",
        CedarExitCode::Success,
    );
    run_validate_test(
        "sample-data/tiny_sandboxes/sample6/policy.cedar",
        "sample-data/tiny_sandboxes/sample6/schema.cedarschema.json",
        CedarExitCode::Success,
    );
    run_validate_test(
        "sample-data/tiny_sandboxes/sample7/policy.cedar",
        "sample-data/tiny_sandboxes/sample7/schema.cedarschema.json",
        CedarExitCode::Success,
    );
}

fn run_evaluate_test(
    request_json_file: &str,
    entities_file: &str,
    expression: &str,
    exit_code: CedarExitCode,
    expected: Value,
) {
    let cmd = EvaluateArgs {
        schema_file: None,
        entities_file: Some(entities_file.into()),
        request: RequestArgs {
            principal: None,
            action: None,
            resource: None,
            context_json_file: None,
            request_json_file: Some(request_json_file.into()),
        },
        expression: expression.to_owned(),
    };
    let output = evaluate(&cmd);
    assert_eq!(exit_code, output.0, "{:#?}", cmd,);
    assert_eq!(expected, output.1, "{:#?}", cmd,);
}

#[test]
fn test_evaluate_samples() {
    run_evaluate_test(
        "sample-data/tiny_sandboxes/sample1/doesnotexist.json",
        "sample-data/tiny_sandboxes/sample1/entity.json",
        "principal in UserGroup::\"jane_friends\"",
        CedarExitCode::Failure,
        false.into(),
    );

    run_evaluate_test(
        "sample-data/tiny_sandboxes/sample1/request.json",
        "sample-data/tiny_sandboxes/sample1/doesnotexist.json",
        "principal in UserGroup::\"jane_friends\"",
        CedarExitCode::Failure,
        false.into(),
    );

    run_evaluate_test(
        "sample-data/tiny_sandboxes/sample1/request.json",
        "sample-data/tiny_sandboxes/sample1/entity.json",
        "parse error",
        CedarExitCode::Failure,
        false.into(),
    );

    run_evaluate_test(
        "sample-data/tiny_sandboxes/sample1/request.json",
        "sample-data/tiny_sandboxes/sample1/entity.json",
        "1 + \"type error\"",
        CedarExitCode::Failure,
        false.into(),
    );

    run_evaluate_test(
        "sample-data/tiny_sandboxes/sample1/request.json",
        "sample-data/tiny_sandboxes/sample1/entity.json",
        "principal in UserGroup::\"jane_friends\"",
        CedarExitCode::Success,
        true.into(),
    );

    run_evaluate_test(
        "sample-data/tiny_sandboxes/sample1/request.json",
        "sample-data/tiny_sandboxes/sample1/entity.json",
        "[\"a\",true,10].contains(10)",
        CedarExitCode::Success,
        true.into(),
    );

    run_evaluate_test(
        "sample-data/tiny_sandboxes/sample1/request.json",
        "sample-data/tiny_sandboxes/sample1/entity.json",
        "principal.age >= 17",
        CedarExitCode::Success,
        true.into(),
    );

    let v: EntityUid = "User::\"bob\"".parse().unwrap();

    run_evaluate_test(
        "sample-data/tiny_sandboxes/sample2/request.json",
        "sample-data/tiny_sandboxes/sample2/entity.json",
        "resource.owner",
        CedarExitCode::Success,
        v.into(),
    );

    run_evaluate_test(
        "sample-data/tiny_sandboxes/sample3/request.json",
        "sample-data/tiny_sandboxes/sample3/entity.json",
        "if 10 > 5 then \"good\" else \"bad\"",
        CedarExitCode::Success,
        "good".into(),
    );

    run_evaluate_test(
        "sample-data/tiny_sandboxes/sample4/request.json",
        "sample-data/tiny_sandboxes/sample4/entity.json",
        "resource.owner == User::\"bob\"",
        CedarExitCode::Success,
        true.into(),
    );

    run_evaluate_test(
        "sample-data/tiny_sandboxes/sample5/request.json",
        "sample-data/tiny_sandboxes/sample5/entity.json",
        "principal.addr.isLoopback()",
        CedarExitCode::Success,
        true.into(),
    );

    run_evaluate_test(
        "sample-data/tiny_sandboxes/sample6/request.json",
        "sample-data/tiny_sandboxes/sample6/entity.json",
        "principal.account.age >= 17",
        CedarExitCode::Success,
        true.into(),
    );

    run_evaluate_test(
        "sample-data/tiny_sandboxes/sample7/request.json",
        "sample-data/tiny_sandboxes/sample7/entity.json",
        "context.role.contains(\"admin\")",
        CedarExitCode::Success,
        true.into(),
    );
}

#[test]
fn test_link_samples() {
    run_authorize_test(
        "sample-data/sandbox_c/doesnotexist.cedar",
        "sample-data/sandbox_c/entities.json",
        "User::\"alice\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Failure,
    );

    run_authorize_test(
        "sample-data/sandbox_c/policies.cedar",
        "sample-data/sandbox_c/doesnotexist.json",
        "User::\"alice\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Failure,
    );

    run_authorize_test(
        "sample-data/sandbox_c/policies.cedar",
        "sample-data/sandbox_c/entities.json",
        "invalid",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Failure,
    );

    run_authorize_test(
        "sample-data/sandbox_c/policies.cedar",
        "sample-data/sandbox_c/entities.json",
        "User::\"alice\"",
        "invalid",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Failure,
    );

    run_authorize_test(
        "sample-data/sandbox_c/policies.cedar",
        "sample-data/sandbox_c/entities.json",
        "User::\"alice\"",
        "Action::\"view\"",
        "invalid",
        CedarExitCode::Failure,
    );

    run_authorize_test(
        "sample-data/sandbox_c/policies.cedar",
        "sample-data/sandbox_c/entities.json",
        "User::\"alice\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::AuthorizeDeny,
    );

    run_authorize_test(
        "sample-data/sandbox_c/policies.cedar",
        "sample-data/sandbox_c/entities.json",
        "User::\"bob\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::AuthorizeDeny,
    );

    let linked_file = tempfile::NamedTempFile::new().expect("Failed to create linked file");
    let linked_file_name = linked_file.path().as_os_str().to_string_lossy().to_string();

    run_link_test(
        "sample-data/sandbox_c/doesnotexist.cedar",
        &linked_file_name,
        "AccessVacation",
        "AliceAccess",
        [(SlotId::principal(), "User::\"alice\"".to_string())]
            .into_iter()
            .collect(),
        CedarExitCode::Failure,
    );

    run_link_test(
        "sample-data/sandbox_c/policies.cedar",
        &linked_file_name,
        "AccessVacation",
        "AliceAccess",
        [(SlotId::principal(), "invalid".to_string())]
            .into_iter()
            .collect(),
        CedarExitCode::Failure,
    );

    run_link_test(
        "sample-data/sandbox_c/policies.cedar",
        &linked_file_name,
        "AccessVacation",
        "AliceAccess",
        [(SlotId::principal(), "User::\"alice\"".to_string())]
            .into_iter()
            .collect(),
        CedarExitCode::Success,
    );

    run_authorize_test_with_linked_policies(
        "sample-data/sandbox_c/policies.cedar",
        "sample-data/sandbox_c/entities.json",
        Some(&linked_file_name),
        "User::\"alice\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Success,
    );

    run_authorize_test_with_linked_policies(
        "sample-data/sandbox_c/policies.cedar",
        "sample-data/sandbox_c/entities.json",
        Some(&linked_file_name),
        "User::\"bob\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::AuthorizeDeny,
    );

    run_link_test(
        "sample-data/sandbox_c/policies.cedar",
        &linked_file_name,
        "AccessVacation",
        "BobAccess",
        [(SlotId::principal(), "User::\"bob\"".to_string())]
            .into_iter()
            .collect(),
        CedarExitCode::Success,
    );

    run_authorize_test_with_linked_policies(
        "sample-data/sandbox_c/policies.cedar",
        "sample-data/sandbox_c/entities.json",
        Some(&linked_file_name),
        "User::\"alice\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Success,
    );

    run_authorize_test_with_linked_policies(
        "sample-data/sandbox_c/policies.cedar",
        "sample-data/sandbox_c/entities.json",
        Some(&linked_file_name),
        "User::\"bob\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Success,
    );

    run_authorize_test_with_linked_policies(
        "sample-data/sandbox_c/policies_edited.cedar",
        "sample-data/sandbox_c/entities.json",
        Some(&linked_file_name),
        "User::\"alice\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::AuthorizeDeny,
    );

    run_authorize_test_with_linked_policies(
        "sample-data/sandbox_c/policies_edited.cedar",
        "sample-data/sandbox_c/entities.json",
        Some(&linked_file_name),
        "User::\"bob\"",
        "Action::\"view\"",
        "Photo::\"VacationPhoto94.jpg\"",
        CedarExitCode::Success,
    );
}

#[test]
fn test_format_samples() {
    use glob::glob;
    let ps_files = glob("sample-data/**/polic*.cedar").unwrap();
    ps_files.for_each(|ps_file| run_format_test(ps_file.unwrap().to_str().unwrap()));
}
