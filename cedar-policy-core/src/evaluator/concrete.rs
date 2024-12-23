use super::{EvaluationError, Evaluator, Expr, PartialValue, Result, SlotEnv, Value};

impl Evaluator<'_> {
    /// Interpret an `Expr` into a `Value` in this evaluation environment.
    ///
    /// Ensures the result is not a residual.
    /// May return an error, for instance if the `Expr` tries to access an
    /// attribute that doesn't exist.
    pub fn interpret(&self, e: &Expr, slots: &SlotEnv) -> Result<Value> {
        match self.partial_interpret(e, slots)? {
            PartialValue::Value(v) => Ok(v),
            PartialValue::Residual(r) => Err(EvaluationError::non_value(r)),
        }
    }
}
