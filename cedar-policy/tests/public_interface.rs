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

use cedar_policy::*;

use std::{error::Error, str::FromStr};

#[test]
fn authorize_custom_request() -> Result<(), Box<dyn Error>> {
    // Startup the Authorizer with all extensions
    let auth = Authorizer::new();

    // Policies can be loaded together
    let mut policies = PolicySet::from_str(
        r#"
        forbid(principal,action,resource)
        when{ context has suspicion };

        permit(
            principal == Account::"jane",
            action,
            resource in Album::"jane_vacation"
        );
    "#,
    )?;

    // Or individually
    // Note the id!
    let alice_view = Policy::parse(
        Some("added policy".to_string()),
        r#"
        permit(
            principal == User::"alice",
            action == Action::"view",
            resource == Photo::"VacationPhoto94.jpg"
        );"#,
    )?;
    let alice_view_id = alice_view.id().clone();
    policies.add(alice_view)?;

    // Entities must be added together because of some post-processing
    let entity_json = r#"
    [
        {
            "uid": { "__expr" :  "User::\"alice\""},
            "attrs": {},
            "parents": [ { "__expr" :"UserGroup::\"jane_friends\"" }]
        },
        {
            "uid":  { "__expr" :"UserGroup::\"jane_friends\"" },
            "attrs": {},
            "parents": []
        },
        {
            "uid":  { "__expr" :"Action::\"view\"" },
            "attrs": {},
            "parents": []
        },
        {
            "uid":  { "__expr" :"Photo::\"VacationPhoto94.jpg\"" },
            "attrs": {},
            "parents": [ { "__expr" :"Album::\"jane_vacation\"" }]
        },
        {
            "uid":  { "__expr" :"Album::\"jane_vacation\"" },
            "attrs": {},
            "parents": [ { "__expr" :"Account::\"jane\"" }]
        },
        {
            "uid":  { "__expr" :"Account::\"jane\""},
            "attrs": {},
            "parents": []
        }
    ]
    "#;
    let entities = Entities::from_json_str(entity_json, None)?;

    // Set up request entity refs
    let principal = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("User").unwrap(),
        EntityId::from_str("alice").unwrap(),
    );
    let action = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Action").unwrap(),
        EntityId::from_str("view").unwrap(),
    );
    let resource = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Photo").unwrap(),
        EntityId::from_str("VacationPhoto94.jpg").unwrap(),
    );

    let context = Context::from_pairs([
        (
            "host_os".to_string(),
            RestrictedExpression::from_str(r#""Windows 10""#)?,
        ),
        (
            "suspicion".to_string(),
            RestrictedExpression::from_str("4")?,
        ),
    ]);

    // Combine into request
    let request = Request::new(
        Some(principal.clone()),
        Some(action.clone()),
        Some(resource.clone()),
        context,
    );

    // Check that we got the "Deny" result
    assert_eq!(
        auth.is_authorized(&request, &policies, &entities)
            .decision(),
        Decision::Deny
    );

    // Same request with empty context
    let request2 = Request::new(
        Some(principal),
        Some(action.clone()),
        Some(resource.clone()),
        Context::empty(),
    );

    // Check that we got the "Allow" result and it was based on the added policy
    assert_eq!(
        auth.is_authorized(&request2, &policies, &entities),
        Response::new(Decision::Allow, [alice_view_id].into(), Vec::new())
    );

    // request with Account::"jane" and an unspecified action
    let principal = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Account").unwrap(),
        EntityId::from_str("jane").unwrap(),
    );
    let request3 = Request::new(
        Some(principal.clone()),
        None,
        Some(resource.clone()),
        Context::empty(),
    );

    // Check that we got an "Allow" result
    assert_eq!(
        auth.is_authorized(&request3, &policies, &entities)
            .decision(),
        Decision::Allow
    );

    // Requesting with an unspecified principal or resource will return Deny (but not fail)
    let request4 = Request::new(None, Some(action.clone()), Some(resource), Context::empty());
    assert_eq!(
        auth.is_authorized(&request4, &policies, &entities)
            .decision(),
        Decision::Deny
    );
    let request5 = Request::new(Some(principal), Some(action), None, Context::empty());
    assert_eq!(
        auth.is_authorized(&request5, &policies, &entities)
            .decision(),
        Decision::Deny
    );

    // Try an evaluation
    let result = eval_expression(&request2, &entities, &Expression::from_str(r#"10 < 100"#)?)?;
    assert_eq!(result, true.into());

    Ok(())
}

#[test]
fn expression_eval_1() -> Result<(), Box<dyn Error>> {
    let entity_json = r#"[ ]"#;
    let entities = Entities::from_json_str(entity_json, None)?;

    // Set up request entity refs
    let principal = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("User").unwrap(),
        EntityId::from_str("alice").unwrap(),
    );
    let action = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Action").unwrap(),
        EntityId::from_str("view").unwrap(),
    );
    let resource = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Photo").unwrap(),
        EntityId::from_str("trip.jpg").unwrap(),
    );

    // Combine into request
    let request = Request::new(
        Some(principal),
        Some(action),
        Some(resource),
        Context::empty(),
    );

    //try an evaluation
    let result = eval_expression(
        &request,
        &entities,
        &Expression::from_str("if 301 > 10 then 100 else 200")?,
    )?;

    assert_eq!(result, 100.into());

    Ok(())
}

#[test]
fn expression_eval_attr() -> Result<(), Box<dyn Error>> {
    let entity_json = r#"[
        {
        "uid": { "__expr" :  "User::\"alice\"" },
        "attrs": {"age":19},
        "parents": []
        }
    ]"#;
    let entities = Entities::from_json_str(entity_json, None)?;

    // Set up request entity refs
    let principal = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("User").unwrap(),
        EntityId::from_str("alice").unwrap(),
    );
    let action = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Action").unwrap(),
        EntityId::from_str("view").unwrap(),
    );
    let resource = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Photo").unwrap(),
        EntityId::from_str("trip.jpg").unwrap(),
    );

    // Combine into request
    let request = Request::new(
        Some(principal),
        Some(action),
        Some(resource),
        Context::empty(),
    );

    //try an evaluation
    let result = eval_expression(
        &request,
        &entities,
        &Expression::from_str("if principal.age > 18 then 100 else 200")?,
    )?;
    assert_eq!(result, 100.into());

    Ok(())
}

#[test]
fn expression_eval_context() -> Result<(), Box<dyn Error>> {
    let entity_json = r#"[
        {
        "uid": { "__expr" :  "User::\"alice\"" },
        "attrs": {"age":19},
        "parents": []
        }
    ]"#;
    let entities = Entities::from_json_str(entity_json, None)?;

    // Set up request entity refs
    let principal = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("User").unwrap(),
        EntityId::from_str("alice").unwrap(),
    );
    let action = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Action").unwrap(),
        EntityId::from_str("view").unwrap(),
    );
    let resource = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Photo").unwrap(),
        EntityId::from_str("trip.jpg").unwrap(),
    );

    let context = Context::from_pairs([
        (
            "location".to_string(),
            RestrictedExpression::from_str(r#""VA""#)?,
        ),
        (
            "suspicion".to_string(),
            RestrictedExpression::from_str("4")?,
        ),
    ]);

    // Combine into request
    let request = Request::new(Some(principal), Some(action), Some(resource), context);

    //try an evaluation
    let result = eval_expression(
        &request,
        &entities,
        &Expression::from_str(
            "if principal.age > 18 && context.location == \"VA\" then 100 else 200",
        )?,
    )?;
    assert_eq!(result, 100.into());

    Ok(())
}

#[test]
fn policy_annotations() {
    // just make sure it is available
    let p: Policy = r#"@anno("good annotation")permit(principal, action, resource);"#
        .parse()
        .unwrap();
    assert_eq!(p.annotation("anno"), Some("good annotation"));
    assert_eq!(p.annotations().next(), Some(("anno", "good annotation")));

    // and on templates
    let t: Template = r#"@tanno("good annotation")permit(principal, action, resource);"#
        .parse()
        .unwrap();
    // need a new id to include in set
    let t = t.new_id(PolicyId::from_str("new_template_id").unwrap());
    assert_eq!(t.annotation("tanno"), Some("good annotation"));
    assert_eq!(t.annotations().next(), Some(("tanno", "good annotation")));

    let pid = p.id().clone();
    let tid = t.id().clone();

    // and on policy sets
    let mut s = PolicySet::new();
    s.add(p).unwrap();
    s.add_template(t).unwrap();

    assert_eq!(s.annotation(&pid, "anno"), Some("good annotation"));
    assert_eq!(
        s.template_annotation(&tid, "tanno"),
        Some("good annotation".to_string())
    );
}

#[test]
fn change_ids() {
    let ps: PolicySet = r#"
        @id("first")
        permit(principal, action, resource);
        @id("second")
        permit(principal, action, resource);
    "#
    .parse()
    .unwrap();
    let mut new_ps = PolicySet::new();
    for p in ps
        .policies()
        .map(|p| p.new_id(p.annotation("id").unwrap().parse().unwrap()))
    {
        new_ps.add(p).expect("valid policy choice");
    }
    // find a policy with new id
    assert!(new_ps.policy(&"first".parse().unwrap()).is_some());
}
