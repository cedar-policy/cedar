use cedar_policy_core::{
    ast::{Eid, EntityUID},
    extensions::Extensions,
    parser::parse_policyset,
    tpe::{
        entities::PartialEntities,
        request::{PartialEntityUID, PartialRequest},
    },
    validator::ValidatorSchema,
};
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};

mod tpe_with_analysis;
use tpe_with_analysis::is_authorized_with_analysis;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policies = parse_policyset(
        r#"
        @id("policy0")
        permit (principal, action == Action::"view", resource)
        when { resource.isPublic };

        @id("policy1")
        permit (principal, action == Action::"view", resource)
        when { resource.owner == principal };

        @id("policy2")
        permit (principal == User::"alice", action == Action::"view", resource);

        @id("policy3")
        forbid (principal, action == Action::"delete", resource);

        @id("policy4")
        forbid (principal == User::"bob", action == Action::"view", resource);

        @id("policy5")
        permit (principal, action == Action::"view", resource)
        when { resource.tags.containsAll(["public", "draft"]) && resource.tags.containsAll(["private"]) };

        @id("policy6")
        permit (principal, action == Action::"view", resource)
        when { resource.size > 1000 && resource.size < 500 };

        @id("policy7")
        permit (principal, action == Action::"view", resource)
        when { resource.tags.containsAny(["admin"]) && !resource.tags.containsAny(["admin"]) };

        @id("policy8")
        permit (principal, action == Action::"view", resource)
        when { resource.tags.containsAll(["temp"]) || !resource.tags.containsAll(["temp"]) };

        @id("policy9")
        permit (principal, action == Action::"view", resource)
        when { resource.size >= 0 || resource.size < 0 };

        @id("policy10")
        permit (principal, action == Action::"view", resource)
        when { resource.tags.containsAny(resource.tags) || !resource.tags.containsAny(resource.tags) };

        @id("policy11")
        permit (principal, action == Action::"view", resource)
        when { resource.tags.containsAll(["public"]) && resource.tags.containsAll(["private"]) && resource.tags.containsAll(["secret"]) };

        @id("policy12")
        permit (principal, action == Action::"view", resource)
        when { resource.size == resource.size || resource.size != resource.size };
    "#,
    )?;

    let schema = ValidatorSchema::from_cedarschema_str(
        r#"
        entity User;
        entity Document = {
            "isPublic": Bool,
            "owner": User,
            "tags": Set<String>,
            "title": String,
            "createdAt": String,
            "size": Long
        };
        action view, delete appliesTo {
            principal: [User],
            resource: [Document]
        };
        "#,
        Extensions::all_available(),
    )?
    .0;

    let request = PartialRequest::new_unchecked(
        PartialEntityUID {
            ty: "User".parse()?,
            eid: Some(Eid::new("alice")),
        },
        PartialEntityUID {
            ty: "Document".parse()?,
            eid: None,
        },
        EntityUID::from_components("Action".parse()?, Eid::new("view"), None),
        Some(Arc::new(BTreeMap::new())),
    );

    let entities = PartialEntities::from_json_value(
        json!([{
            "uid": {"type": "User", "id": "alice"},
            "parents": []
        }]),
        &schema,
    )?;

    let response = is_authorized_with_analysis(&policies, &request, &entities, &schema).await?;

    println!("Decision: {:?}\n", response.decision);

    println!("Residual Policies:");
    for (i, residual_policy) in response
        .residual_permits
        .iter()
        .chain(response.residual_forbids.iter())
        .enumerate()
    {
        let policy_id = format!("{:?}", residual_policy.get_policy_id())
            .replace("PolicyID(\"", "")
            .replace("\")", "");
        println!(
            "  {}. {} ({})",
            i + 1,
            policy_id,
            residual_policy.get_effect()
        );

        let residual = residual_policy.get_residual();
        let expr: cedar_policy_core::ast::Expr = (*residual).clone().into();
        println!("     -> {}\n", expr);
    }

    println!("Satisfied Policies:");
    for (i, residual_policy) in response
        .satisfied_permits
        .iter()
        .chain(response.satisfied_forbids.iter())
        .enumerate()
    {
        let policy_id = format!("{:?}", residual_policy.get_policy_id())
            .replace("PolicyID(\"", "")
            .replace("\")", "");
        println!(
            "  {}. {} ({})\n",
            i + 1,
            policy_id,
            residual_policy.get_effect()
        );
    }

    println!("False Policies:");
    for (i, residual_policy) in response
        .false_permits
        .iter()
        .chain(response.false_forbids.iter())
        .enumerate()
    {
        let policy_id = format!("{:?}", residual_policy.get_policy_id())
            .replace("PolicyID(\"", "")
            .replace("\")", "");
        println!(
            "  {}. {} ({})\n",
            i + 1,
            policy_id,
            residual_policy.get_effect()
        );
    }

    Ok(())
}
