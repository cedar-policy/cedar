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
// PANIC SAFETY unit tests
#![allow(clippy::unwrap_used)]
// PANIC SAFETY unit tests
#![allow(clippy::expect_used)]

use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Entities, EntityId, EntityTypeName, EntityUid, Policy, PolicySet, Request,
    RestrictedExpression,
};

use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    let auth = Authorizer::new();

    let mut multiple_policies = PolicySet::from_str(
        r#"
        forbid(principal,action,resource)
        when{ context has suspicion };

        permit(
            principal == Account::"jane",
            action,
            resource == Album::"jane_vacation"
        );
    "#,
    )
    .unwrap();

    let single_policy = Policy::from_str(
        r#"
        permit(
            principal == User::"alice",
            action == Action::"view",
            resource == Photo::"VacationPhoto94.jpg"
        );"#,
    )
    .unwrap()
    .new_id("single_policy".parse().unwrap());

    multiple_policies.add(single_policy).unwrap();

    let entity_json = r#"
    [
        {
            "uid": { "type" : "User", "id": "alice"},
            "attrs": {},
            "parents": [ { "__entity" : {"type": "UserGroup", "id": "jane_friends"}} ]
        },
        {
            "uid": {"type": "UserGroup", "id": "jane_friends"},
            "attrs": {},
            "parents": []
        },
        {
            "uid": {"type": "Action", "id": "view"},
            "attrs": {},
            "parents": []
        },
        {
            "uid": {"type": "Photo", "id": "VacationPhoto94.jpg"},
            "attrs": {},
            "parents": [ { "__entity": {"type": "Album", "id": "jane_vacation"}} ]
        },
        {
            "uid": {"type": "Album", "id": "jane_vacation"},
            "attrs": {},
            "parents": [ { "__entity" : {"type": "Account", "id": "jane"}} ]
        },
        {
            "uid": {"type": "Account", "id": "jane"},
            "attrs": {},
            "parents": []
        }
    ]
    "#;

    let entities = Entities::from_json_str(entity_json, None).unwrap();

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

    let context = vec![
        (
            "host_os".to_string(),
            RestrictedExpression::from_str(r#""Windows 10""#).unwrap(),
        ),
        (
            "suspicion".to_string(),
            RestrictedExpression::from_str("4").unwrap(),
        ),
    ];

    let request_a = Request::new(
        principal.clone(),
        action.clone(),
        resource.clone(),
        Context::from_pairs(context.clone()).expect("no duplicate keys in this context"),
        None,
    )
    .unwrap();

    c.bench_function("request_new", |b| {
        b.iter(|| {
            Request::new(
                black_box(principal.clone()),
                black_box(action.clone()),
                black_box(resource.clone()),
                black_box(
                    Context::from_pairs(context.clone())
                        .expect("no duplicate keys in this context"),
                ),
                None,
            )
            .unwrap()
        })
    });

    c.bench_function("is_authorized", |b| {
        b.iter(|| {
            auth.is_authorized(
                black_box(&request_a),
                black_box(&multiple_policies),
                black_box(&entities),
            )
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
