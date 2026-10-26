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

//! Abstraction of extension function arguments and results. Each extension
//! function `f` is specified as `ext_out_rel(f(args), model::ext::call(F, abs(args)))`.

use vstd::prelude::*;

use super::abs::{abs_lit, abs_name, abs_str, seq_to_list};
use super::model as m;
use super::model::ext as mext;
use super::ext_trusted::ext_of;
use super::trusted::smol_view;
use super::value_abs::{abs_record, abs_set, abs_value};
use crate::ast::*;
use crate::evaluator::EvaluationError;

verus! {

/// `abs_value(v)` unfolded one level (`lemma_ext_arg`)
pub open spec fn ext_arg(v: Value) -> m::value::Value {
    match v.value {
        ValueKind::Lit(l) => m::value::Value::Prim(abs_lit(l)),
        ValueKind::Set(s) => m::value::Value::Set(Box::new(abs_set(s))),
        ValueKind::Record(r) => m::value::Value::Record(Box::new(abs_record(*r))),
        ValueKind::ExtensionValue(ev) => m::value::Value::Ext(ext_of(*ev)),
    }
}

pub broadcast proof fn lemma_ext_arg(v: Value)
    ensures
        #[trigger] ext_arg(v) == abs_value(v),
{
    super::value_abs::lemma_abs_value(v.value);
}

pub open spec fn args1(a: Value) -> m::value::List<m::value::Value> {
    m::value::List::Cons(ext_arg(a), Box::new(m::value::List::Nil))
}

pub open spec fn args2(a: Value, b: Value) -> m::value::List<m::value::Value> {
    m::value::List::Cons(ext_arg(a), Box::new(m::value::List::Cons(ext_arg(b), Box::new(m::value::List::Nil))))
}

/// Both fail (with any error), or both return the same value
pub open spec fn ext_out_rel(
    r: Result<ExtensionOutputValue, EvaluationError>,
    mr: Result<mext::ExtRes, m::value::Error>,
) -> bool {
    match (r, mr) {
        (Err(_), Err(_)) => true,
        (Ok(ExtensionOutputValue::Known(v)), Ok(mext::ExtRes::Bool(b))) =>
            v.value == ValueKind::Lit(Literal::Bool(b)),
        (Ok(ExtensionOutputValue::Known(v)), Ok(mext::ExtRes::Int(i))) =>
            v.value == ValueKind::Lit(Literal::Long(i)),
        (Ok(ExtensionOutputValue::Known(v)), Ok(mext::ExtRes::Ext(e))) =>
            ext_arg(v) == m::value::Value::Ext(e),
        _ => false,
    }
}

/// The extension function of the model named `n` (by its unqualified name,
/// as production's extensions name them)
pub open spec fn ext_fun_of_name(n: Name) -> Option<mext::ExtFun> {
    let id = smol_view(n.spec_internal().spec_id().spec_smolstr());
    if n.spec_internal().spec_path().len() != 0 {
        None
    } else if id == "decimal"@ {
        Some(mext::ExtFun::Decimal)
    } else if id == "lessThan"@ {
        Some(mext::ExtFun::LessThan)
    } else if id == "lessThanOrEqual"@ {
        Some(mext::ExtFun::LessThanOrEqual)
    } else if id == "greaterThan"@ {
        Some(mext::ExtFun::GreaterThan)
    } else if id == "greaterThanOrEqual"@ {
        Some(mext::ExtFun::GreaterThanOrEqual)
    } else if id == "ip"@ {
        Some(mext::ExtFun::Ip)
    } else if id == "isIpv4"@ {
        Some(mext::ExtFun::IsIpv4)
    } else if id == "isIpv6"@ {
        Some(mext::ExtFun::IsIpv6)
    } else if id == "isLoopback"@ {
        Some(mext::ExtFun::IsLoopback)
    } else if id == "isMulticast"@ {
        Some(mext::ExtFun::IsMulticast)
    } else if id == "isInRange"@ {
        Some(mext::ExtFun::IsInRange)
    } else if id == "datetime"@ {
        Some(mext::ExtFun::Datetime)
    } else if id == "duration"@ {
        Some(mext::ExtFun::Duration)
    } else if id == "offset"@ {
        Some(mext::ExtFun::Offset)
    } else if id == "durationSince"@ {
        Some(mext::ExtFun::DurationSince)
    } else if id == "toDate"@ {
        Some(mext::ExtFun::ToDate)
    } else if id == "toTime"@ {
        Some(mext::ExtFun::ToTime)
    } else if id == "toMilliseconds"@ {
        Some(mext::ExtFun::ToMilliseconds)
    } else if id == "toSeconds"@ {
        Some(mext::ExtFun::ToSeconds)
    } else if id == "toMinutes"@ {
        Some(mext::ExtFun::ToMinutes)
    } else if id == "toHours"@ {
        Some(mext::ExtFun::ToHours)
    } else if id == "toDays"@ {
        Some(mext::ExtFun::ToDays)
    } else {
        None
    }
}

/// `ext_fun_of_name(n)`, with an arbitrary default
pub open spec fn ext_fun_of(n: Name) -> mext::ExtFun {
    match ext_fun_of_name(n) {
        Some(f) => f,
        None => mext::ExtFun::Decimal,
    }
}

} // verus!
