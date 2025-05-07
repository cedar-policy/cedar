use cedar_policy_core::{ast::Expr, entities::json::err::Residual};
use cedar_policy_validator::{typecheck::Typechecker, ValidatorSchema};

use crate::{entities::PartialEntities, request::PartialRequest};

/// Type-aware partial-evaluation
pub fn tpe(
    expr: &Expr,
    request: &PartialRequest,
    es: &PartialEntities,
    schema: &ValidatorSchema,
) -> anyhow::Result<Residual> {
    let env = request.find_request_env(schema)?;
    let tc = Typechecker::new(schema, cedar_policy_validator::ValidationMode::Strict);
    todo!()
}
