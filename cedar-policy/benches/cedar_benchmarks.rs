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
        "added policy"
        permit(
            principal == User::"alice",
            action == PhotoOp::"view",
            resource == Photo::"VacationPhoto94.jpg"
        );"#,
    )
    .unwrap();

    if multiple_policies.add(single_policy).is_err() {
        Err("Failed to add policy".to_string()).unwrap()
    };

    let entity_json = r#"
    [
        {
            "uid": { "__expr" : "User::\"alice\"" },
            "attrs": {},
            "parents": [ { "__expr" : "UserGroup::\"jane_friends\"" } ]
        },
        {
            "uid": { "__expr" : "UserGroup::\"jane_friends\"" },
            "attrs": {},
            "parents": []
        },
        {
            "uid": { "__expr" : "PhotoOp::\"view\"" },
            "attrs": {},
            "parents": []
        },
        {
            "uid": { "__expr" : "Photo::\"VacationPhoto94.jpg\"" },
            "attrs": {},
            "parents": [ { "__expr" : "Album::\"jane_vacation\"" } ]
        },
        {
            "uid": { "__expr" : "Album::\"jane_vacation\"" },
            "attrs": {},
            "parents": [ { "__expr" : "Account::\"jane\"" } ]
        },
        {
            "uid": { "__expr" : "Account::\"jane\"" },
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
        EntityTypeName::from_str("PhotoOp").unwrap(),
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
        Some(principal.clone()),
        Some(action.clone()),
        Some(resource.clone()),
        Context::from_pairs(context.clone()),
    );

    c.bench_function("request_new", |b| {
        b.iter(|| {
            Request::new(
                Some(black_box(principal.clone())),
                Some(black_box(action.clone())),
                Some(black_box(resource.clone())),
                black_box(Context::from_pairs(context.clone())),
            )
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
