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

// PANIC SAFETY tests
#![allow(clippy::expect_used)]
// PANIC SAFETY tests
#![allow(clippy::unwrap_used)]
use std::collections::HashMap;
use std::path::PathBuf;

use cedar_policy::EvalResult;
use cedar_policy::SlotId;
use cedar_policy_cli::check_parse;
use cedar_policy_cli::SchemaFormat;
use cedar_policy_cli::{
    authorize, evaluate, link, validate, Arguments, AuthorizeArgs, CedarExitCode, CheckParseArgs,
    EvaluateArgs, LinkArgs, PoliciesArgs, PolicyFormat, RequestArgs, ValidateArgs,
};

use predicates::prelude::*;
use rstest::rstest;

fn run_check_parse_test(policies_file: impl Into<String>, expected_exit_code: CedarExitCode) {
    let cmd = CheckParseArgs {
        policies: PoliciesArgs {
            policies_file: Some(policies_file.into()),
            policy_format: PolicyFormat::Human,
            template_linked_file: None,
        },
    };
    let output = check_parse(&cmd);
    assert_eq!(output, expected_exit_code, "{:#?}", cmd);
}

fn run_authorize_test(
    policies_file: impl Into<String>,
    entities_file: impl Into<String>,
    principal: impl Into<String>,
    action: impl Into<String>,
    resource: impl Into<String>,
    exit_code: CedarExitCode,
) {
    run_authorize_test_with_linked_policies(
        policies_file,
        entities_file,
        None::<String>,
        principal,
        action,
        resource,
        exit_code,
    );
}

fn run_authorize_test_with_linked_policies(
    policies_file: impl Into<String>,
    entities_file: impl Into<String>,
    links_file: Option<impl Into<String>>,
    principal: impl Into<String>,
    action: impl Into<String>,
    resource: impl Into<String>,
    exit_code: CedarExitCode,
) {
    let cmd = AuthorizeArgs {
        request: RequestArgs {
            principal: Some(principal.into()),
            action: Some(action.into()),
            resource: Some(resource.into()),
            context_json_file: None,
            request_json_file: None,
            request_validation: true,
        },
        policies: PoliciesArgs {
            policies_file: Some(policies_file.into()),
            policy_format: PolicyFormat::Human,
            template_linked_file: links_file.map(Into::into),
        },
        schema_file: None,
        schema_format: SchemaFormat::default(),
        entities_file: entities_file.into(),
        verbose: true,
        timing: false,
    };
    let output = authorize(&cmd);
    assert_eq!(exit_code, output, "{:#?}", cmd,);
}

fn run_link_test(
    policies_file: impl Into<String>,
    links_file: impl Into<String>,
    template_id: impl Into<String>,
    linked_id: impl Into<String>,
    env: HashMap<SlotId, String>,
    expected: CedarExitCode,
) {
    let cmd = LinkArgs {
        policies: PoliciesArgs {
            policies_file: Some(policies_file.into()),
            policy_format: PolicyFormat::Human,
            template_linked_file: Some(links_file.into()),
        },
        template_id: template_id.into(),
        new_id: linked_id.into(),
        arguments: Arguments { data: env },
    };
    let output = link(&cmd);
    assert_eq!(output, expected);
}

fn run_authorize_test_context(
    policies_file: impl Into<String>,
    entities_file: impl Into<String>,
    principal: impl Into<String>,
    action: impl Into<String>,
    resource: impl Into<String>,
    context_file: impl Into<String>,
    exit_code: CedarExitCode,
) {
    let cmd = AuthorizeArgs {
        request: RequestArgs {
            principal: Some(principal.into()),
            action: Some(action.into()),
            resource: Some(resource.into()),
            context_json_file: Some(context_file.into()),
            request_json_file: None,
            request_validation: true,
        },
        policies: PoliciesArgs {
            policies_file: Some(policies_file.into()),
            policy_format: PolicyFormat::Human,
            template_linked_file: None,
        },
        schema_file: None,
        schema_format: SchemaFormat::default(),
        entities_file: entities_file.into(),
        verbose: true,
        timing: false,
    };
    let output = authorize(&cmd);
    assert_eq!(exit_code, output, "{:#?}", cmd,);
}

fn run_authorize_test_json(
    policies_file: impl Into<String>,
    entities_file: impl Into<String>,
    request_json_file: impl Into<String>,
    exit_code: CedarExitCode,
) {
    let cmd = AuthorizeArgs {
        request: RequestArgs {
            principal: None,
            action: None,
            resource: None,
            context_json_file: None,
            request_json_file: Some(request_json_file.into()),
            request_validation: true,
        },
        policies: PoliciesArgs {
            policies_file: Some(policies_file.into()),
            policy_format: PolicyFormat::Human,
            template_linked_file: None,
        },
        schema_file: None,
        schema_format: SchemaFormat::default(),
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
    run_authorize_test_json(
        "sample-data/tiny_sandboxes/sample8/policy.cedar",
        "sample-data/tiny_sandboxes/sample8/entity.json",
        "sample-data/tiny_sandboxes/sample8/request.json",
        CedarExitCode::Success,
    );
    run_authorize_test_json(
        "sample-data/tiny_sandboxes/sample9/policy.cedar",
        "sample-data/tiny_sandboxes/sample9/entity.json",
        "sample-data/tiny_sandboxes/sample9/request.json",
        CedarExitCode::Success,
    );
}

#[rstest]
#[case(
    "sample-data/doesnotexist.cedar",
    "sample-data/sandbox_a/schema.cedarschema.json",
    CedarExitCode::Failure
)]
#[case(
    "sample-data/sandbox_a/policies_1.cedar",
    "sample-data/doesnotexist.json",
    CedarExitCode::Failure
)]
#[case(
    "sample-data/sandbox_a/policies_1.cedar",
    "sample-data/sandbox_a/schema.cedarschema.json",
    CedarExitCode::Success
)]
// Contains misspelled entity type.
#[case(
    "sample-data/sandbox_a/policies_1_bad.cedar",
    "sample-data/sandbox_a/schema.cedarschema.json",
    CedarExitCode::ValidationFailure
)]
#[case(
    "sample-data/sandbox_a/policies_2.cedar",
    "sample-data/sandbox_a/schema.cedarschema.json",
    CedarExitCode::Success
)]
#[case(
    "sample-data/sandbox_a/policies_3.cedar",
    "sample-data/sandbox_a/schema.cedarschema.json",
    CedarExitCode::Success
)]
#[case(
    "sample-data/sandbox_b/policies_4.cedar",
    "sample-data/sandbox_b/schema.cedarschema.json",
    CedarExitCode::Success
)]
// Contains an access to an optional attribute without a `has` check.
#[case(
    "sample-data/sandbox_b/policies_5_bad.cedar",
    "sample-data/sandbox_b/schema.cedarschema.json",
    CedarExitCode::ValidationFailure
)]
#[case(
    "sample-data/sandbox_b/policies_5.cedar",
    "sample-data/sandbox_b/schema.cedarschema.json",
    CedarExitCode::Success
)]
#[case(
    "sample-data/sandbox_b/policies_6.cedar",
    "sample-data/sandbox_b/schema.cedarschema.json",
    CedarExitCode::Success
)]
#[case(
    "sample-data/tiny_sandboxes/sample1/policy.cedar",
    "sample-data/tiny_sandboxes/sample1/schema.cedarschema.json",
    CedarExitCode::Success
)]
#[case(
    "sample-data/tiny_sandboxes/sample2/policy.cedar",
    "sample-data/tiny_sandboxes/sample2/schema.cedarschema.json",
    CedarExitCode::Success
)]
#[case(
    "sample-data/tiny_sandboxes/sample3/policy.cedar",
    "sample-data/tiny_sandboxes/sample3/schema.cedarschema.json",
    CedarExitCode::Success
)]
#[case(
    "sample-data/tiny_sandboxes/sample4/policy.cedar",
    "sample-data/tiny_sandboxes/sample4/schema.cedarschema.json",
    CedarExitCode::Success
)]
#[case(
    "sample-data/tiny_sandboxes/sample5/policy.cedar",
    "sample-data/tiny_sandboxes/sample5/schema.cedarschema.json",
    CedarExitCode::Success
)]
#[case(
    "sample-data/tiny_sandboxes/sample6/policy.cedar",
    "sample-data/tiny_sandboxes/sample6/schema.cedarschema.json",
    CedarExitCode::Success
)]
#[case(
    "sample-data/tiny_sandboxes/sample7/policy.cedar",
    "sample-data/tiny_sandboxes/sample7/schema.cedarschema.json",
    CedarExitCode::Success
)]
#[case(
    "sample-data/tiny_sandboxes/sample8/policy.cedar",
    "sample-data/tiny_sandboxes/sample8/schema.cedarschema.json",
    CedarExitCode::Success
)]
#[case(
    "sample-data/tiny_sandboxes/sample9/policy.cedar",
    "sample-data/tiny_sandboxes/sample9/schema.cedarschema.json",
    CedarExitCode::Success
)]
#[case(
    "sample-data/tiny_sandboxes/sample9/policy_bad.cedar",
    "sample-data/tiny_sandboxes/sample9/schema.cedarschema.json",
    CedarExitCode::ValidationFailure
)]
#[track_caller]
fn test_validate_samples(
    #[case] policies_file: impl Into<String>,
    #[case] schema_file: impl Into<String>,
    #[case] exit_code: CedarExitCode,
) {
    let policies_file = policies_file.into();
    let schema_file = schema_file.into();

    // Run with JSON schema
    let cmd = ValidateArgs {
        schema_file: schema_file.clone(),
        policies: PoliciesArgs {
            policies_file: Some(policies_file.clone()),
            policy_format: PolicyFormat::Human,
            template_linked_file: None,
        },
        deny_warnings: false,
        validation_mode: cedar_policy_cli::ValidationMode::Strict,
        schema_format: SchemaFormat::Json,
    };
    let output = validate(&cmd);
    assert_eq!(exit_code, output, "{:#?}", cmd);

    // Run with human schema
    let cmd = ValidateArgs {
        schema_file: schema_file
            .strip_suffix(".json")
            .expect("`schema_file` should be the JSON schema")
            .to_string(),
        policies: PoliciesArgs {
            policies_file: Some(policies_file),
            policy_format: PolicyFormat::Human,
            template_linked_file: None,
        },
        deny_warnings: false,
        validation_mode: cedar_policy_cli::ValidationMode::Strict,
        schema_format: SchemaFormat::Human,
    };
    let output = validate(&cmd);
    assert_eq!(exit_code, output, "{:#?}", cmd)
}

#[rstest]
#[case(
    "sample-data/tiny_sandboxes/sample1/doesnotexist.json",
    "sample-data/tiny_sandboxes/sample1/entity.json",
    "principal in UserGroup::\"jane_friends\"",
    CedarExitCode::Failure,
    EvalResult::Bool(false)
)]
#[case(
    "sample-data/tiny_sandboxes/sample1/request.json",
    "sample-data/tiny_sandboxes/sample1/doesnotexist.json",
    "principal in UserGroup::\"jane_friends\"",
    CedarExitCode::Failure,
    EvalResult::Bool(false)
)]
#[case(
    "sample-data/tiny_sandboxes/sample1/request.json",
    "sample-data/tiny_sandboxes/sample1/entity.json",
    "parse error",
    CedarExitCode::Failure,
    EvalResult::Bool(false)
)]
#[case(
    "sample-data/tiny_sandboxes/sample1/request.json",
    "sample-data/tiny_sandboxes/sample1/entity.json",
    "1 + \"type error\"",
    CedarExitCode::Failure,
    EvalResult::Bool(false)
)]
#[case(
    "sample-data/tiny_sandboxes/sample1/request.json",
    "sample-data/tiny_sandboxes/sample1/entity.json",
    "principal in UserGroup::\"jane_friends\"",
    CedarExitCode::Success,
    EvalResult::Bool(true)
)]
#[case(
    "sample-data/tiny_sandboxes/sample1/request.json",
    "sample-data/tiny_sandboxes/sample1/entity.json",
    "[\"a\",true,10].contains(10)",
    CedarExitCode::Success,
    EvalResult::Bool(true)
)]
#[case(
    "sample-data/tiny_sandboxes/sample1/request.json",
    "sample-data/tiny_sandboxes/sample1/entity.json",
    "principal.age >= 17",
    CedarExitCode::Success,
    EvalResult::Bool(true)
)]
#[case("sample-data/tiny_sandboxes/sample2/request.json",
        "sample-data/tiny_sandboxes/sample2/entity.json",
        "resource.owner",
        CedarExitCode::Success,
        EvalResult::EntityUid("User::\"bob\"".parse().unwrap()),)]
#[case("sample-data/tiny_sandboxes/sample3/request.json",
        "sample-data/tiny_sandboxes/sample3/entity.json",
        "if 10 > 5 then \"good\" else \"bad\"",
        CedarExitCode::Success,
        EvalResult::String("good".to_owned()),)]
#[case(
    "sample-data/tiny_sandboxes/sample4/request.json",
    "sample-data/tiny_sandboxes/sample4/entity.json",
    "resource.owner == User::\"bob\"",
    CedarExitCode::Success,
    EvalResult::Bool(true)
)]
#[case(
    "sample-data/tiny_sandboxes/sample5/request.json",
    "sample-data/tiny_sandboxes/sample5/entity.json",
    "principal.addr.isLoopback()",
    CedarExitCode::Success,
    EvalResult::Bool(true)
)]
#[case(
    "sample-data/tiny_sandboxes/sample6/request.json",
    "sample-data/tiny_sandboxes/sample6/entity.json",
    "principal.account.age >= 17",
    CedarExitCode::Success,
    EvalResult::Bool(true)
)]
#[case(
    "sample-data/tiny_sandboxes/sample7/request.json",
    "sample-data/tiny_sandboxes/sample7/entity.json",
    "context.role.contains(\"admin\")",
    CedarExitCode::Success,
    EvalResult::Bool(true)
)]
fn test_evaluate_samples(
    #[case] request_json_file: impl Into<String>,
    #[case] entities_file: impl Into<String>,
    #[case] expression: impl Into<String>,
    #[case] exit_code: CedarExitCode,
    #[case] expected: EvalResult,
) {
    let cmd = EvaluateArgs {
        schema_file: None,
        schema_format: SchemaFormat::default(),
        entities_file: Some(entities_file.into()),
        request: RequestArgs {
            principal: None,
            action: None,
            resource: None,
            context_json_file: None,
            request_json_file: Some(request_json_file.into()),
            request_validation: true,
        },
        expression: expression.into(),
    };
    let output = evaluate(&cmd);
    assert_eq!(exit_code, output.0, "{:#?}", cmd,);
    assert_eq!(expected, output.1, "{:#?}", cmd,);
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

#[rstest]
// PANIC SAFETY: this is all test code
#[allow(clippy::expect_used)]
// PANIC SAFETY: this is all test code
#[allow(clippy::unwrap_used)]
#[track_caller]
fn test_format_samples(#[files("sample-data/**/polic*.cedar")] path: PathBuf) {
    let policies_file = path.to_str().unwrap();
    let original = std::fs::read_to_string(policies_file).unwrap();
    let format_cmd = assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("format")
        .arg("-p")
        .arg(policies_file)
        .assert();
    let formatted =
        std::str::from_utf8(&format_cmd.get_output().stdout).expect("output should be decodable");
    assert_eq!(
        original, formatted,
        "\noriginal:\n{original}\n\nformatted:\n{formatted}",
    );
}

#[test]
fn test_format_write() {
    const POLICY_SOURCE: &str = "sample-data/tiny_sandboxes/format/unformatted.cedar";
    // See https://doc.rust-lang.org/cargo/reference/environment-variables.html for the
    // CARGO_TARGET_TMPDIR environment variable.
    let tmp_dir = env!("CARGO_TARGET_TMPDIR");
    let unformatted_file = format!("{}/unformatted.cedar", tmp_dir);
    std::fs::copy(POLICY_SOURCE, &unformatted_file).unwrap();
    let original = std::fs::read_to_string(&unformatted_file).unwrap();

    assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("format")
        .arg("-p")
        .arg(&unformatted_file)
        .assert()
        .success();
    let formatted = std::fs::read_to_string(&unformatted_file).unwrap();
    assert_eq!(
        original, formatted,
        "original and formatted should be the same without -w\noriginal:{original}\n\nformatted:{formatted}"
    );

    assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("format")
        .arg("-p")
        .arg(&unformatted_file)
        .arg("-w")
        .assert()
        .success();
    let formatted = std::fs::read_to_string(&unformatted_file).unwrap();
    assert_ne!(
        original, formatted,
        "original and formatted should differ under -w\noriginal:{original}\n\nformatted:{formatted}"
    );
}

#[test]
fn test_format_check() {
    const POLICY_REQUIRING_FORMAT: &str = "sample-data/tiny_sandboxes/format/unformatted.cedar";
    const POLICY_ALREADY_FORMATTED: &str = "sample-data/tiny_sandboxes/format/formatted.cedar";

    assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("format")
        .arg("-p")
        .arg(POLICY_REQUIRING_FORMAT)
        .arg("-c")
        .assert()
        .code(1);

    assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("format")
        .arg("-p")
        .arg(POLICY_ALREADY_FORMATTED)
        .arg("-c")
        .assert()
        .code(0);
}

#[test]
fn test_write_check_are_mutually_exclusive() {
    const POLICY_SOURCE: &str = "sample-data/tiny_sandboxes/format/unformatted.cedar";
    assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("format")
        .arg("-p")
        .arg(POLICY_SOURCE)
        .arg("-w")
        .arg("-c")
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "the argument '--write' cannot be used with '--check'",
        ));
}

#[test]
fn test_require_policies_for_write() {
    assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("format")
        .arg("-w")
        .write_stdin("permit (principal, action, resource);")
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "the following required arguments were not provided:\n  --policies <FILE>",
        ));
}

#[test]
fn test_check_parse_json_static_policy() {
    let json_policy: &str = "sample-data/tiny_sandboxes/json-check-parse/static_policy.cedar.json";

    assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("check-parse")
        .arg("--policy-format")
        .arg("json")
        .arg("-p")
        .arg(json_policy)
        .assert()
        .code(0);
}

#[test]
fn test_check_parse_json_policy_template() {
    let json_policy: &str =
        "sample-data/tiny_sandboxes/json-check-parse/policy_template.cedar.json";

    assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("check-parse")
        .arg("--policy-format")
        .arg("json")
        .arg("-p")
        .arg(json_policy)
        .assert()
        .code(0);
}

#[test]
fn test_check_parse_json_policy_set() {
    let json_policy: &str = "sample-data/tiny_sandboxes/json-check-parse/policy_set.cedar.json";

    assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("check-parse")
        .arg("--policy-format")
        .arg("json")
        .arg("-p")
        .arg(json_policy)
        .assert()
        .code(0);
}

#[test]
fn test_check_parse_json_policy_mixed_properties() {
    let json_policy: &str =
        "sample-data/tiny_sandboxes/json-check-parse/policy_mixed_properties.cedar.json";

    assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("check-parse")
        .arg("--policy-format")
        .arg("json")
        .arg("-p")
        .arg(json_policy)
        .assert()
        .code(1)
        .stdout(predicate::str::contains(
            "matching properties from both formats",
        ));
}

#[test]
fn test_check_parse_json_policy_no_matching_properties() {
    let json_policy: &str =
        "sample-data/tiny_sandboxes/json-check-parse/policy_no_matching_properties.cedar.json";

    assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("check-parse")
        .arg("--policy-format")
        .arg("json")
        .arg("-p")
        .arg(json_policy)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("no matching properties"));
}

#[test]
fn test_authorize_json_policy() {
    let json_policy: &str = "sample-data/tiny_sandboxes/json-authorize/policy.cedar.json";
    let entities: &str = "sample-data/tiny_sandboxes/json-authorize/entity.json";

    assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("authorize")
        .arg("--policy-format")
        .arg("json")
        .arg("-p")
        .arg(json_policy)
        .arg("--entities")
        .arg(entities)
        .arg("--principal")
        .arg(r#"User::"bob""#)
        .arg("--action")
        .arg(r#"Action::"view""#)
        .arg("--resource")
        .arg(r#"Photo::"VacationPhoto94.jpg""#)
        .assert()
        .code(0);
}

#[test]
fn test_translate_policy() {
    let human_filename = "sample-data/tiny_sandboxes/translate-policy/policy.cedar";
    let json_filename = "sample-data/tiny_sandboxes/translate-policy/policy.cedar.json";
    let human = std::fs::read_to_string(human_filename).unwrap();
    let json = std::fs::read_to_string(json_filename).unwrap();
    let translate_cmd = assert_cmd::Command::cargo_bin("cedar")
        .expect("bin exists")
        .arg("translate-policy")
        .arg("--direction")
        .arg("human-to-json")
        .arg("-p")
        .arg(human_filename)
        .assert();

    let translated = std::str::from_utf8(&translate_cmd.get_output().stdout)
        .expect("output should be decodable");

    assert_eq!(
        translated, json,
        "\noriginal:\n{human}\n\ttranslated:\n{translated}",
    );
}
