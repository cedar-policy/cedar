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

use crate::ast::*;
use crate::entities::SchemaType;
use crate::evaluator;
use std::any::Any;
use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::Arc;

/// Cedar extension.
///
/// An extension can define new types and functions on those types. (Currently,
/// there's nothing preventing an extension from defining new functions on
/// built-in types, either, although we haven't discussed whether we want to
/// allow this long-term.)
pub struct Extension {
    /// Name of the extension
    name: Name,
    /// Extension functions. These are legal to call in Cedar expressions.
    functions: HashMap<Name, ExtensionFunction>,
    /// Types with operator overloading
    types_with_operator_overloading: BTreeSet<Name>,
}

impl Extension {
    /// Create a new `Extension` with the given name and extension functions
    pub fn new(
        name: Name,
        functions: impl IntoIterator<Item = ExtensionFunction>,
        types_with_operator_overloading: impl IntoIterator<Item = Name>,
    ) -> Self {
        Self {
            name,
            functions: functions.into_iter().map(|f| (f.name.clone(), f)).collect(),
            types_with_operator_overloading: types_with_operator_overloading.into_iter().collect(),
        }
    }

    /// Get the name of the extension
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Look up a function by name, or return `None` if the extension doesn't
    /// provide a function with that name
    pub fn get_func(&self, name: &Name) -> Option<&ExtensionFunction> {
        self.functions.get(name)
    }

    /// Iterate over the functions
    pub fn funcs(&self) -> impl Iterator<Item = &ExtensionFunction> {
        self.functions.values()
    }

    /// Iterate over the extension types that can be produced by any functions
    /// in this extension
    pub fn ext_types(&self) -> impl Iterator<Item = &Name> + '_ {
        self.funcs().flat_map(|func| func.ext_types())
    }

    /// Iterate over extension types with operator overloading
    pub fn types_with_operator_overloading(&self) -> impl Iterator<Item = &Name> + '_ {
        self.types_with_operator_overloading.iter()
    }
}

impl std::fmt::Debug for Extension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<extension {}>", self.name())
    }
}

/// The output of an extension call, either a value or an unknown
#[derive(Debug, Clone)]
pub enum ExtensionOutputValue {
    /// A concrete value from an extension call
    Known(Value),
    /// An unknown returned from an extension call
    Unknown(Unknown),
}

impl<T> From<T> for ExtensionOutputValue
where
    T: Into<Value>,
{
    fn from(v: T) -> Self {
        ExtensionOutputValue::Known(v.into())
    }
}

/// Which "style" is a function call
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum CallStyle {
    /// Function-style, eg foo(a, b)
    FunctionStyle,
    /// Method-style, eg a.foo(b)
    MethodStyle,
}

// Note: we could use currying to make this a little nicer

macro_rules! extension_function_object {
    ( $( $tys:ty ), * ) => {
        Box<dyn Fn($($tys,)*) -> evaluator::Result<ExtensionOutputValue> + Sync + Send + 'static>
    }
}

/// Trait object that implements the extension function call accepting any number of arguments.
pub type ExtensionFunctionObject = extension_function_object!(&[Value]);
/// Trait object that implements the extension function call accepting exactly 0 arguments
pub type NullaryExtensionFunctionObject = extension_function_object!();
/// Trait object that implements the extension function call accepting exactly 1 arguments
pub type UnaryExtensionFunctionObject = extension_function_object!(&Value);
/// Trait object that implements the extension function call accepting exactly 2 arguments
pub type BinaryExtensionFunctionObject = extension_function_object!(&Value, &Value);
/// Trait object that implements the extension function call accepting exactly 3 arguments
pub type TernaryExtensionFunctionObject = extension_function_object!(&Value, &Value, &Value);
/// Trait object that implements the extension function call that takes one argument, followed by a variadic number of arguments.
pub type VariadicExtensionFunctionObject = extension_function_object!(&Value, &[Value]);

/// Extension function. These can be called by the given `name` in Ceder
/// expressions.
pub struct ExtensionFunction {
    /// Name of the function
    name: Name,
    /// Which `CallStyle` should be used when calling this function
    style: CallStyle,
    /// The actual function, which takes an `&[Value]` and returns a `Value`,
    /// or an evaluation error
    func: ExtensionFunctionObject,
    /// The return type of this function, as a `SchemaType`. We require that
    /// this be constant -- any given extension function must always return a
    /// value of this `SchemaType`.
    ///
    /// `return_type` is `None` if and only if this function represents an
    /// "unknown" value for partial evaluation. Such a function may only return
    /// a fully unknown residual and may never return a value.
    return_type: Option<SchemaType>,
    /// The argument types that this function expects, as `SchemaType`s.
    arg_types: Vec<SchemaType>,
    /// Whether this is a variadic function or not. If it is a variadic function it can accept 1 or more arguments
    /// of the last argument type.
    is_variadic: bool,
}

impl ExtensionFunction {
    /// Create a new `ExtensionFunction` taking any number of arguments
    fn new(
        name: Name,
        style: CallStyle,
        func: ExtensionFunctionObject,
        return_type: Option<SchemaType>,
        arg_types: Vec<SchemaType>,
        is_variadic: bool,
    ) -> Self {
        Self {
            name,
            style,
            func,
            return_type,
            arg_types,
            is_variadic,
        }
    }

    /// Create a new `ExtensionFunction` taking no arguments
    pub fn nullary(
        name: Name,
        style: CallStyle,
        func: NullaryExtensionFunctionObject,
        return_type: SchemaType,
    ) -> Self {
        Self::new(
            name.clone(),
            style,
            Box::new(move |args: &[Value]| {
                if args.is_empty() {
                    func()
                } else {
                    Err(evaluator::EvaluationError::wrong_num_arguments(
                        name.clone(),
                        0,
                        args.len(),
                        None, // evaluator will add the source location later
                    ))
                }
            }),
            Some(return_type),
            vec![],
            false,
        )
    }

    /// Create a new `ExtensionFunction` to represent a function which is an
    /// "unknown" in partial evaluation. Please don't use this for anything else.
    pub fn partial_eval_unknown(
        name: Name,
        style: CallStyle,
        func: UnaryExtensionFunctionObject,
        arg_type: SchemaType,
    ) -> Self {
        Self::new(
            name.clone(),
            style,
            Box::new(move |args: &[Value]| match args.first() {
                Some(arg) => func(arg),
                None => Err(evaluator::EvaluationError::wrong_num_arguments(
                    name.clone(),
                    1,
                    args.len(),
                    None, // evaluator will add the source location later
                )),
            }),
            None,
            vec![arg_type],
            false,
        )
    }

    /// Create a new `ExtensionFunction` taking one argument
    #[allow(clippy::type_complexity)]
    pub fn unary(
        name: Name,
        style: CallStyle,
        func: UnaryExtensionFunctionObject,
        return_type: SchemaType,
        arg_type: SchemaType,
    ) -> Self {
        Self::new(
            name.clone(),
            style,
            Box::new(move |args: &[Value]| match &args {
                &[arg] => func(arg),
                _ => Err(evaluator::EvaluationError::wrong_num_arguments(
                    name.clone(),
                    1,
                    args.len(),
                    None, // evaluator will add the source location later
                )),
            }),
            Some(return_type),
            vec![arg_type],
            false,
        )
    }

    /// Create a new `ExtensionFunction` taking two arguments
    #[allow(clippy::type_complexity)]
    pub fn binary(
        name: Name,
        style: CallStyle,
        func: BinaryExtensionFunctionObject,
        return_type: SchemaType,
        arg_types: (SchemaType, SchemaType),
    ) -> Self {
        Self::new(
            name.clone(),
            style,
            Box::new(move |args: &[Value]| match &args {
                &[first, second] => func(first, second),
                _ => Err(evaluator::EvaluationError::wrong_num_arguments(
                    name.clone(),
                    2,
                    args.len(),
                    None, // evaluator will add the source location later
                )),
            }),
            Some(return_type),
            vec![arg_types.0, arg_types.1],
            false,
        )
    }

    /// Create a new `ExtensionFunction` taking three arguments
    #[allow(clippy::type_complexity)]
    pub fn ternary(
        name: Name,
        style: CallStyle,
        func: TernaryExtensionFunctionObject,
        return_type: SchemaType,
        arg_types: (SchemaType, SchemaType, SchemaType),
    ) -> Self {
        Self::new(
            name.clone(),
            style,
            Box::new(move |args: &[Value]| match &args {
                &[first, second, third] => func(first, second, third),
                _ => Err(evaluator::EvaluationError::wrong_num_arguments(
                    name.clone(),
                    3,
                    args.len(),
                    None, // evaluator will add the source location later
                )),
            }),
            Some(return_type),
            vec![arg_types.0, arg_types.1, arg_types.2],
            false,
        )
    }

    /// Create a new variadic `ExtensionFunction` taking two or more argument.
    #[allow(clippy::type_complexity)]
    pub fn variadic(
        name: Name,
        style: CallStyle,
        func: VariadicExtensionFunctionObject,
        return_type: SchemaType,
        arg_types: (SchemaType, SchemaType),
    ) -> Self {
        Self::new(
            name.clone(),
            style,
            Box::new(move |args: &[Value]| match &args {
                &[first, rest @ ..] => func(first, rest),
                _ => Err(evaluator::EvaluationError::wrong_num_arguments(
                    name.clone(),
                    2,
                    args.len(),
                    None, // evaluator will add the source location later
                )),
            }),
            Some(return_type),
            vec![arg_types.0, arg_types.1],
            true,
        )
    }

    /// Get the `Name` of the `ExtensionFunction`
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Get the `CallStyle` of the `ExtensionFunction`
    pub fn style(&self) -> CallStyle {
        self.style
    }

    /// Get the return type of the `ExtensionFunction`
    /// `None` is returned exactly when this function represents an "unknown"
    /// for partial evaluation.
    pub fn return_type(&self) -> Option<&SchemaType> {
        self.return_type.as_ref()
    }

    /// Get the argument types of the `ExtensionFunction`.
    pub fn arg_types(&self) -> &[SchemaType] {
        &self.arg_types
    }

    /// Whether this is a variadic function.
    pub fn is_variadic(&self) -> bool {
        self.is_variadic
    }

    /// Returns `true` if this function is considered a single argument
    /// constructor.
    ///
    /// Only functions satisfying this predicate can have their names implicit
    /// during schema-based entity parsing
    pub fn is_single_arg_constructor(&self) -> bool {
        // return type is an extension type
        matches!(self.return_type(), Some(SchemaType::Extension { .. }))
        // the only argument is a string
        && matches!(self.arg_types(), [SchemaType::String])
    }

    /// Call the `ExtensionFunction` with the given args
    pub fn call(&self, args: &[Value]) -> evaluator::Result<PartialValue> {
        match (self.func)(args)? {
            ExtensionOutputValue::Known(v) => Ok(PartialValue::Value(v)),
            ExtensionOutputValue::Unknown(u) => Ok(PartialValue::Residual(Expr::unknown(u))),
        }
    }

    /// Iterate over the extension types that could be produced by this
    /// function, if any
    pub fn ext_types(&self) -> impl Iterator<Item = &Name> + '_ {
        self.return_type
            .iter()
            .flat_map(|ret_ty| ret_ty.contained_ext_types())
    }
}

impl std::fmt::Debug for ExtensionFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<extension function {}>", self.name())
    }
}

/// Extension value.
///
/// Anything implementing this trait can be used as a first-class value in
/// Cedar. For instance, the `ipaddr` extension uses this mechanism
/// to implement IPAddr as a Cedar first-class value.
pub trait ExtensionValue: Debug + Send + Sync + UnwindSafe + RefUnwindSafe {
    /// Get the name of the type of this value.
    ///
    /// Cedar has nominal typing, so two values have the same type iff they
    /// return the same typename here.
    fn typename(&self) -> Name;

    /// If it supports operator overloading
    fn supports_operator_overloading(&self) -> bool;
}

impl<V: ExtensionValue> StaticallyTyped for V {
    fn type_of(&self) -> Type {
        Type::Extension {
            name: self.typename(),
        }
    }
}

#[derive(Debug, Clone)]
/// Object container for extension values
/// An extension value must be representable by a [`RestrictedExpr`]
/// Specifically, it will be a function call `func` on `args`
/// Note that `func` may not be the constructor. A counterexample is that a
/// `datetime` is represented by an `offset` method call.
/// Nevertheless, an invariant is that `eval(<func>(<args>)) == value`
pub struct RepresentableExtensionValue {
    pub(crate) func: Name,
    pub(crate) args: Vec<RestrictedExpr>,
    pub(crate) value: Arc<dyn InternalExtensionValue>,
}

impl RepresentableExtensionValue {
    /// Create a new [`RepresentableExtensionValue`]
    pub fn new(
        value: Arc<dyn InternalExtensionValue + Send + Sync>,
        func: Name,
        args: Vec<RestrictedExpr>,
    ) -> Self {
        Self { func, args, value }
    }

    /// Get the internal value
    pub fn value(&self) -> &dyn InternalExtensionValue {
        self.value.as_ref()
    }

    /// Get the typename of this extension value
    pub fn typename(&self) -> Name {
        self.value.typename()
    }

    /// If this value supports operator overloading
    pub(crate) fn supports_operator_overloading(&self) -> bool {
        self.value.supports_operator_overloading()
    }
}

impl From<RepresentableExtensionValue> for RestrictedExpr {
    fn from(val: RepresentableExtensionValue) -> Self {
        RestrictedExpr::call_extension_fn(val.func, val.args)
    }
}

impl StaticallyTyped for RepresentableExtensionValue {
    fn type_of(&self) -> Type {
        self.value.type_of()
    }
}

impl PartialEq for RepresentableExtensionValue {
    fn eq(&self, other: &Self) -> bool {
        // Values that are equal are equal regardless of which arguments made them
        self.value.as_ref() == other.value.as_ref()
    }
}

impl Eq for RepresentableExtensionValue {}

impl PartialOrd for RepresentableExtensionValue {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RepresentableExtensionValue {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

/// Extensions provide a type implementing `ExtensionValue`, `Eq`, and `Ord`.
/// We automatically implement `InternalExtensionValue` for that type (with the
/// impl below).  Internally, we use `dyn InternalExtensionValue` instead of
/// `dyn ExtensionValue`.
///
/// You might wonder why we don't just have `ExtensionValue: Eq + Ord` and use
/// `dyn ExtensionValue` everywhere.  The answer is that the Rust compiler
/// doesn't let you because of
/// [object safety](https://doc.rust-lang.org/reference/items/traits.html#object-safety).
/// So instead we have this workaround where we define our own `equals_extvalue`
/// method that compares not against `&Self` but against `&dyn InternalExtensionValue`,
/// and likewise for `cmp_extvalue`.
pub trait InternalExtensionValue: ExtensionValue {
    /// convert to an `Any`
    fn as_any(&self) -> &dyn Any;
    /// this will be the basis for `PartialEq` on `InternalExtensionValue`; but
    /// note the `&dyn` (normal `PartialEq` doesn't have the `dyn`)
    fn equals_extvalue(&self, other: &dyn InternalExtensionValue) -> bool;
    /// this will be the basis for `Ord` on `InternalExtensionValue`; but note
    /// the `&dyn` (normal `Ord` doesn't have the `dyn`)
    fn cmp_extvalue(&self, other: &dyn InternalExtensionValue) -> std::cmp::Ordering;
}

impl<V: 'static + Eq + Ord + ExtensionValue + Send + Sync + Clone> InternalExtensionValue for V {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equals_extvalue(&self, other: &dyn InternalExtensionValue) -> bool {
        other
            .as_any()
            .downcast_ref::<V>()
            .map(|v| self == v)
            .unwrap_or(false) // if the downcast failed, values are different types, so equality is false
    }

    fn cmp_extvalue(&self, other: &dyn InternalExtensionValue) -> std::cmp::Ordering {
        other
            .as_any()
            .downcast_ref::<V>()
            .map(|v| self.cmp(v))
            .unwrap_or_else(|| {
                // downcast failed, so values are different types.
                // we fall back on the total ordering on typenames.
                self.typename().cmp(&other.typename())
            })
    }
}

impl PartialEq for dyn InternalExtensionValue {
    fn eq(&self, other: &Self) -> bool {
        self.equals_extvalue(other)
    }
}

impl Eq for dyn InternalExtensionValue {}

impl PartialOrd for dyn InternalExtensionValue {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for dyn InternalExtensionValue {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cmp_extvalue(other)
    }
}

impl StaticallyTyped for dyn InternalExtensionValue {
    fn type_of(&self) -> Type {
        Type::Extension {
            name: self.typename(),
        }
    }
}
