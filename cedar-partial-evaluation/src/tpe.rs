use anyhow::anyhow;
use cedar_policy_core::{ast::Policy, extensions::Extensions};
use cedar_policy_validator::{
    typecheck::{PolicyCheck, Typechecker},
    ValidatorSchema,
};

use crate::{
    entities::PartialEntities, evaluator::Evaluator, request::PartialRequest, residual::Residual,
};

/// Type-aware partial-evaluation
pub fn tpe(
    p: &Policy,
    request: &PartialRequest,
    es: &PartialEntities,
    schema: &ValidatorSchema,
) -> anyhow::Result<Residual> {
    if !p.is_static() {
        return Err(anyhow!("policy must be static"));
    }
    if request.validate_request(schema).is_err() {
        return Err(anyhow!("request is not valid"));
    }
    let env = request.find_request_env(schema)?;
    let tc = Typechecker::new(schema, cedar_policy_validator::ValidationMode::Strict);
    let t = p.template();
    match tc.typecheck_by_single_request_env(t, &env) {
        PolicyCheck::Success(expr) => {
            let evaluator = Evaluator {
                request: request.clone(),
                entities: es,
                extensions: Extensions::all_available(),
            };
            Ok(evaluator.interpret(&expr))
        }
        PolicyCheck::Fail(errs) => Err(anyhow!("failed validation : {errs:#?}")),
        PolicyCheck::Irrelevant(errs, expr) => {
            if errs.is_empty() {
                let evaluator = Evaluator {
                    request: request.clone(),
                    entities: es,
                    extensions: Extensions::all_available(),
                };
                Ok(evaluator.interpret(&expr))
            } else {
                Err(anyhow!("failed validation : {errs:#?}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        sync::Arc,
    };

    use anyhow::Result;
    use cedar_policy_core::{
        ast::{Eid, EntityUID, Expr, PolicySet},
        extensions::Extensions,
        parser::parse_policyset,
    };
    use cedar_policy_validator::ValidatorSchema;

    use crate::{
        entities::{PartialEntities, PartialEntity},
        request::{PartialEntityUID, PartialRequest},
        residual::Residual,
    };

    use super::tpe;

    fn rfc_policies() -> PolicySet {
        parse_policyset(
            r#"
        // Users can view public documents.
permit (
  principal,
  action == Action::"View",
  resource
) when {
  resource.isPublic
};

// Users can view owned documents if they are mfa-authenticated.
permit (
  principal,
  action == Action::"View",
  resource
) when {
  context.hasMFA &&
  resource.owner == principal
};

// Users can delete owned documents if they are mfa-authenticated
// and on the company network.
permit (
  principal,
  action == Action::"Delete",
  resource
) when {
  context.hasMFA &&
  resource.owner == principal &&
  context.srcIP.isInRange(ip("1.1.1.0/24"))
};
        "#,
        )
        .unwrap()
    }

    fn rfc_schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"
        entity User;

entity Document  = {
  "isPublic": Bool,
  "owner": User
};

action View appliesTo {
  principal: [User],
  resource: [Document],
  context: {
    "hasMFA": Bool,
  }
};

action Delete appliesTo {
  principal: [User],
  resource: [Document],
  context: {
    "hasMFA": Bool,
    "srcIP": ipaddr
  }
};
        "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    fn rfc_request() -> PartialRequest {
        PartialRequest {
            principal: PartialEntityUID {
                ty: "User".parse().unwrap(),
                eid: Some(Eid::new("Alice")),
            },
            action: EntityUID::from_components("Action".parse().unwrap(), Eid::new("View"), None),
            resource: PartialEntityUID {
                ty: "Document".parse().unwrap(),
                eid: None,
            },
            context: Some(Arc::new(BTreeMap::from_iter(std::iter::once((
                "hasMFA".into(),
                true.into(),
            ))))),
        }
    }

    fn rfc_entities() -> PartialEntities {
        let uid = EntityUID::from_components("User".parse().unwrap(), Eid::new("Alice"), None);
        PartialEntities {
            entities: HashMap::from_iter([(
                uid.clone(),
                PartialEntity {
                    uid,
                    attrs: Some(BTreeMap::new()),
                    ancestors: Some(HashSet::new()),
                    tags: None,
                },
            )]),
        }
    }
    #[test]
    fn rfc_example() {
        let policies = rfc_policies();
        let schema = rfc_schema();
        let request = rfc_request();
        let entities = rfc_entities();
        let residuals: Vec<Residual> = policies
            .policies()
            .map(|p| tpe(p, &request, &entities, &schema))
            .collect::<Result<Vec<Residual>>>()
            .unwrap();
        for residual in residuals {
            println!("{}", Expr::try_from(residual).unwrap());
        }
    }
}
