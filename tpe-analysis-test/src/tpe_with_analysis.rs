use cedar_policy::{RequestEnv, Schema};
use cedar_policy_core::{
    ast::Effect,
    tpe::{
        entities::PartialEntities, is_authorized, request::PartialRequest, response::ResidualPolicy,
    },
    validator::ValidatorSchema,
};
use cedar_policy_symcc::{solver::LocalSolver, CedarSymCompiler, CompiledPolicy};

pub struct AnalyzedTPEResponse {
    pub decision: Option<cedar_policy_core::authorizer::Decision>,
    pub residual_permits: Vec<ResidualPolicy>,
    pub residual_forbids: Vec<ResidualPolicy>,
    pub satisfied_permits: Vec<ResidualPolicy>,
    pub satisfied_forbids: Vec<ResidualPolicy>,
    pub false_permits: Vec<ResidualPolicy>,
    pub false_forbids: Vec<ResidualPolicy>,
}

pub async fn is_authorized_with_analysis(
    policies: &cedar_policy_core::ast::PolicySet,
    request: &PartialRequest,
    entities: &PartialEntities,
    schema: &ValidatorSchema,
) -> Result<AnalyzedTPEResponse, Box<dyn std::error::Error>> {
    let response = is_authorized(policies, request, entities, schema)?;

    let cedar_schema = Schema::from(schema.clone());
    let req_env = RequestEnv::new(
        request.get_principal().ty.clone().into(),
        request.get_action().clone().into(),
        request.get_resource().ty.clone().into(),
    );

    let mut residual_permits = Vec::new();
    let mut residual_forbids = Vec::new();
    let mut satisfied_permits = response.satisfied_permits().cloned().collect::<Vec<_>>();
    let mut satisfied_forbids = response.satisfied_forbids().cloned().collect::<Vec<_>>();
    let mut false_permits = response.false_permits().cloned().collect::<Vec<_>>();
    let mut false_forbids = response.false_forbids().cloned().collect::<Vec<_>>();
    for residual_policy in response
        .residual_permits()
        .chain(response.residual_forbids())
    {
        let analysis_result =
            analyze_residual_policy(residual_policy.clone(), &cedar_schema, &req_env).await;
        match (analysis_result, residual_policy.get_effect()) {
            (AnalysisResult::AlwaysTrue, Effect::Permit) => {
                satisfied_permits.push(residual_policy.clone())
            }
            (AnalysisResult::AlwaysTrue, Effect::Forbid) => {
                satisfied_forbids.push(residual_policy.clone())
            }
            (AnalysisResult::AlwaysFalse, Effect::Permit) => {
                false_permits.push(residual_policy.clone())
            }
            (AnalysisResult::AlwaysFalse, Effect::Forbid) => {
                false_forbids.push(residual_policy.clone())
            }
            (AnalysisResult::Unknown, Effect::Permit) => {
                residual_permits.push(residual_policy.clone())
            }
            (AnalysisResult::Unknown, Effect::Forbid) => {
                residual_forbids.push(residual_policy.clone())
            }
        }
    }

    Ok(AnalyzedTPEResponse {
        decision: response.decision(),
        residual_permits,
        residual_forbids,
        satisfied_permits,
        satisfied_forbids,
        false_permits,
        false_forbids,
    })
}

#[derive(Debug)]
enum AnalysisResult {
    AlwaysTrue,
    AlwaysFalse,
    Unknown,
}

async fn analyze_residual_policy(
    residual_policy: ResidualPolicy,
    schema: &Schema,
    req_env: &RequestEnv,
) -> AnalysisResult {
    let core_policy: cedar_policy_core::ast::Policy = residual_policy.into();
    let compiled = CompiledPolicy::compile(&core_policy.into(), req_env, schema).unwrap();
    let solver = LocalSolver::cvc5().unwrap();
    let mut compiler = CedarSymCompiler::new(solver).unwrap();

    if compiler.check_always_matches_opt(&compiled).await.unwrap() {
        AnalysisResult::AlwaysTrue
    } else if compiler.check_never_matches_opt(&compiled).await.unwrap() {
        AnalysisResult::AlwaysFalse
    } else {
        AnalysisResult::Unknown
    }
}
