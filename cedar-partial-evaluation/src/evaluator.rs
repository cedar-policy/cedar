use std::sync::Arc;

use cedar_policy_core::{
    ast::{self, Expr, ExprKind, Literal, Value, ValueKind, Var},
    extensions::Extensions,
};
use cedar_policy_validator::types::{Primitive, Type};

use crate::{
    entities::PartialEntities,
    request::PartialRequest,
    residual::{Residual, ResidualKind},
};

#[derive(Debug)]
pub struct Evaluator<'e> {
    request: PartialRequest,
    entities: &'e PartialEntities,
    extensions: &'e Extensions<'e>,
}

impl<'e> Evaluator<'e> {
    pub fn interpret(&self, e: &Expr<Type>) -> Residual {
        let ty = e.data().clone();
        match e.expr_kind() {
            ExprKind::Lit(l) => Residual::Concrete {
                value: l.clone().into(),
                ty,
            },
            ExprKind::Var(Var::Action) => Residual::Concrete {
                value: self.request.action.clone().into(),
                ty,
            },
            ExprKind::Var(Var::Principal) => {
                if let Some(principal) = &self.request.principal {
                    Residual::Concrete {
                        value: principal.clone().into(),
                        ty,
                    }
                } else {
                    Residual::Partial {
                        kind: ResidualKind::Var(Var::Principal),
                        ty,
                    }
                }
            }
            ExprKind::Var(Var::Resource) => {
                if let Some(resource) = &self.request.resource {
                    Residual::Concrete {
                        value: resource.clone().into(),
                        ty,
                    }
                } else {
                    Residual::Partial {
                        kind: ResidualKind::Var(Var::Resource),
                        ty,
                    }
                }
            }
            ExprKind::Var(Var::Context) => {
                if let Some(context) = &self.request.context {
                    Residual::Concrete {
                        value: Value::record_arc(context.clone(), None),
                        ty,
                    }
                } else {
                    Residual::Partial {
                        kind: ResidualKind::Var(Var::Context),
                        ty,
                    }
                }
            }
            ExprKind::And { left, right } => {
                let left = self.interpret(left);
                match &left {
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::Bool(false)),
                                ..
                            },
                        ..
                    } => Residual::Concrete {
                        value: false.into(),
                        ty,
                    },
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::Bool(true)),
                                ..
                            },
                        ..
                    } => self.interpret(right),
                    Residual::Concrete { ty, .. } => Residual::Error(ty.clone()),
                    Residual::Partial { kind, .. } => Residual::Partial {
                        kind: ResidualKind::And {
                            left: Arc::new(left),
                            right: Arc::new(self.interpret(right)),
                        },
                        ty,
                    },
                    Residual::Error(_) => Residual::Error(ty),
                }
            }
            ExprKind::Or { left, right } => {
                let left = self.interpret(left);
                match &left {
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::Bool(true)),
                                ..
                            },
                        ..
                    } => Residual::Concrete {
                        value: true.into(),
                        ty,
                    },
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::Bool(false)),
                                ..
                            },
                        ..
                    } => self.interpret(right),
                    Residual::Concrete { ty, .. } => Residual::Error(ty.clone()),
                    Residual::Partial { kind, .. } => Residual::Partial {
                        kind: ResidualKind::Or {
                            left: Arc::new(left),
                            right: Arc::new(self.interpret(right)),
                        },
                        ty,
                    },
                    Residual::Error(_) => Residual::Error(ty),
                }
            }
            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                let cond = self.interpret(test_expr);
                match &cond {
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::Bool(b)),
                                ..
                            },
                        ..
                    } => {
                        if *b {
                            self.interpret(then_expr)
                        } else {
                            self.interpret(else_expr)
                        }
                    }
                    Residual::Concrete { ty, .. } => Residual::Error(ty.clone()),
                    Residual::Partial { kind, .. } => Residual::Partial {
                        kind: ResidualKind::If {
                            test_expr: Arc::new(cond),
                            then_expr: Arc::new(self.interpret(then_expr)),
                            else_expr: Arc::new(self.interpret(else_expr)),
                        },
                        ty,
                    },
                    Residual::Error(_) => Residual::Error(ty),
                }
            }
            ExprKind::Is { expr, entity_type } => {
                let r = self.interpret(expr);
                match &r {
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::EntityUID(uid)),
                                ..
                            },
                        ..
                    } => Residual::Concrete {
                        value: (uid.entity_type() == entity_type).into(),
                        ty,
                    },
                    Residual::Concrete { ty, .. } => Residual::Error(ty.clone()),
                    Residual::Partial { kind, .. } => Residual::Partial {
                        kind: ResidualKind::Is {
                            expr: Arc::new(r),
                            entity_type: entity_type.clone(),
                        },
                        ty,
                    },
                    Residual::Error(_) => Residual::Error(ty),
                }
            }
            ExprKind::Like { expr, pattern } => {
                let r = self.interpret(expr);
                match &r {
                    Residual::Concrete {
                        value:
                            Value {
                                value: ValueKind::Lit(ast::Literal::String(s)),
                                ..
                            },
                        ..
                    } => Residual::Concrete {
                        value: pattern.wildcard_match(&s).into(),
                        ty,
                    },
                    Residual::Concrete { ty, .. } => Residual::Error(ty.clone()),
                    Residual::Partial { kind, .. } => Residual::Partial {
                        kind: ResidualKind::Like {
                            expr: Arc::new(r),
                            pattern: pattern.clone(),
                        },
                        ty,
                    },
                    Residual::Error(_) => Residual::Error(ty),
                }
            }
            ExprKind::BinaryApp { op, arg1, arg2 } => todo!(""),
            ExprKind::ExtensionFunctionApp { fn_name, args } => todo!(""),
            ExprKind::GetAttr { expr, attr } => todo!(""),
            ExprKind::HasAttr { expr, attr } => todo!(""),
            ExprKind::Unknown { .. } => todo!(),
            ExprKind::Slot(_) => todo!(),
            ExprKind::UnaryApp { op, arg } => todo!(),
            ExprKind::Set(_) => todo!(),
            ExprKind::Record(_) => todo!(),
        }
    }
}
