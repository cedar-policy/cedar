use crate::ast::{Effect, Policy};
use crate::extensions::Extensions;
use crate::parser::parse_expr;
use crate::tpe::request::{PartialEntityUID, PartialRequest};
use crate::tpe::residual::Residual;
use crate::validator::typecheck::{PolicyCheck, Typechecker};
use crate::validator::{ValidationMode, Validator, ValidatorSchema};

#[track_caller]
pub(crate) fn parse_residual(expr_str: &str) -> Residual {
    let expr = parse_expr(expr_str).unwrap();
    let policy_id = crate::ast::PolicyID::from_string("test");
    let policy = Policy::from_when_clause(Effect::Permit, expr, policy_id, None);
    let t = policy.template();

    let schema = ValidatorSchema::from_cedarschema_str(r#"
        entity User in Organization { foo: Bool, str: String, num: Long, period: __cedar::duration, set: Set<String> } tags String;
        entity Organization;
        entity Document in Organization; 
        action get appliesTo { principal: [User], resource: [Document] };"#,
        &Extensions::all_available(),
    )
    .unwrap()
    .0;

    let typechecker = Typechecker::new(&schema, ValidationMode::Strict);

    let request = PartialRequest::new(
        PartialEntityUID {
            ty: "User".parse().unwrap(),
            eid: None,
        },
        r#"Action::"get""#.parse().unwrap(),
        PartialEntityUID {
            ty: "Document".parse().unwrap(),
            eid: None,
        },
        None,
        &schema,
    )
    .unwrap();
    let env = request.find_request_env(&schema).unwrap();

    let errs: Vec<_> = Validator::validate_entity_types_and_literals(&schema, t).collect();
    if !errs.is_empty() {
        panic!("unexpected type error in expression");
    }
    match typechecker.typecheck_by_single_request_env(t, &env) {
        PolicyCheck::Success(expr) => Residual::try_from(&expr).unwrap(),
        PolicyCheck::Fail(errs) => {
            println!("got {} type errors", errs.len());
            for e in errs {
                println!("{:?}", miette::Report::new(e));
            }
            panic!("unexpected type error in expression")
        }
        PolicyCheck::Irrelevant(errs, expr) => {
            if errs.is_empty() {
                Residual::try_from(&expr).unwrap()
            } else {
                println!("got {} type errors", errs.len());
                for e in errs {
                    println!("{:?}", miette::Report::new(e));
                }
                panic!("unexpected type error in expression")
            }
        }
    }
}
