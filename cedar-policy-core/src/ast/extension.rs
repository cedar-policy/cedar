/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
use std::collections::HashMap;
use std::fmt::{Debug, Display};
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
}

impl Extension {
    /// Create a new `Extension` with the given name and extension functions
    pub fn new(name: Name, functions: impl IntoIterator<Item = ExtensionFunction>) -> Self {
        Self {
            name,
            functions: functions.into_iter().map(|f| (f.name.clone(), f)).collect(),
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

    /// Get an iterator over the function names
    pub fn funcs(&self) -> impl Iterator<Item = &ExtensionFunction> {
        self.functions.values()
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

/// Trait object that implements the extension function call.
pub type ExtensionFunctionObject =
    Box<dyn Fn(&[Value]) -> evaluator::Result<ExtensionOutputValue> + Sync + Send + 'static>;

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
    /// If `return_type` is `None`, the function may never return a value.
    /// (ie: it functions as the `Never` type)
    return_type: Option<SchemaType>,
    /// The argument types that this function expects, as `SchemaType`s. If any
    /// given argument type is not constant (function works with multiple
    /// `SchemaType`s) then this will be `None` for that argument.
    arg_types: Vec<Option<SchemaType>>,
}

impl ExtensionFunction {
    /// Create a new `ExtensionFunction` taking any number of arguments
    fn new(
        name: Name,
        style: CallStyle,
        func: ExtensionFunctionObject,
        return_type: Option<SchemaType>,
        arg_types: Vec<Option<SchemaType>>,
    ) -> Self {
        Self {
            name,
            func,
            style,
            return_type,
            arg_types,
        }
    }

    /// Create a new `ExtensionFunction` taking no arguments
    pub fn nullary(
        name: Name,
        style: CallStyle,
        func: Box<dyn Fn() -> evaluator::Result<ExtensionOutputValue> + Sync + Send + 'static>,
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
        )
    }

    /// Create a new `ExtensionFunction` taking one argument, that never returns a value
    pub fn unary_never(
        name: Name,
        style: CallStyle,
        func: Box<dyn Fn(Value) -> evaluator::Result<ExtensionOutputValue> + Sync + Send + 'static>,
        arg_type: Option<SchemaType>,
    ) -> Self {
        Self::new(
            name.clone(),
            style,
            Box::new(move |args: &[Value]| match args.first() {
                Some(arg) => func(arg.clone()),
                None => Err(evaluator::EvaluationError::wrong_num_arguments(
                    name.clone(),
                    1,
                    args.len(),
                    None, // evaluator will add the source location later
                )),
            }),
            None,
            vec![arg_type],
        )
    }

    /// Create a new `ExtensionFunction` taking one argument
    pub fn unary(
        name: Name,
        style: CallStyle,
        func: Box<dyn Fn(Value) -> evaluator::Result<ExtensionOutputValue> + Sync + Send + 'static>,
        return_type: SchemaType,
        arg_type: Option<SchemaType>,
    ) -> Self {
        Self::new(
            name.clone(),
            style,
            Box::new(move |args: &[Value]| match &args {
                &[arg] => func(arg.clone()),
                _ => Err(evaluator::EvaluationError::wrong_num_arguments(
                    name.clone(),
                    1,
                    args.len(),
                    None, // evaluator will add the source location later
                )),
            }),
            Some(return_type),
            vec![arg_type],
        )
    }

    /// Create a new `ExtensionFunction` taking two arguments
    pub fn binary(
        name: Name,
        style: CallStyle,
        func: Box<
            dyn Fn(Value, Value) -> evaluator::Result<ExtensionOutputValue> + Sync + Send + 'static,
        >,
        return_type: SchemaType,
        arg_types: (Option<SchemaType>, Option<SchemaType>),
    ) -> Self {
        Self::new(
            name.clone(),
            style,
            Box::new(move |args: &[Value]| match &args {
                &[first, second] => func(first.clone(), second.clone()),
                _ => Err(evaluator::EvaluationError::wrong_num_arguments(
                    name.clone(),
                    2,
                    args.len(),
                    None, // evaluator will add the source location later
                )),
            }),
            Some(return_type),
            vec![arg_types.0, arg_types.1],
        )
    }

    /// Create a new `ExtensionFunction` taking three arguments
    pub fn ternary(
        name: Name,
        style: CallStyle,
        func: Box<
            dyn Fn(Value, Value, Value) -> evaluator::Result<ExtensionOutputValue>
                + Sync
                + Send
                + 'static,
        >,
        return_type: SchemaType,
        arg_types: (Option<SchemaType>, Option<SchemaType>, Option<SchemaType>),
    ) -> Self {
        Self::new(
            name.clone(),
            style,
            Box::new(move |args: &[Value]| match &args {
                &[first, second, third] => func(first.clone(), second.clone(), third.clone()),
                _ => Err(evaluator::EvaluationError::wrong_num_arguments(
                    name.clone(),
                    3,
                    args.len(),
                    None, // evaluator will add the source location later
                )),
            }),
            Some(return_type),
            vec![arg_types.0, arg_types.1, arg_types.2],
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
    /// `None` represents the `Never` type.
    pub fn return_type(&self) -> Option<&SchemaType> {
        self.return_type.as_ref()
    }

    /// Get the argument types of the `ExtensionFunction`.
    ///
    /// If any given argument type is not constant (function works with multiple
    /// `SchemaType`s) then this will be `None` for that argument.
    pub fn arg_types(&self) -> &[Option<SchemaType>] {
        &self.arg_types
    }

    /// Returns `true` if this function is considered a "constructor".
    ///
    /// Currently, the only impact of this is that non-constructors are not
    /// accessible in the JSON format (entities/json.rs).
    pub fn is_constructor(&self) -> bool {
        // return type is an extension type
        matches!(self.return_type(), Some(SchemaType::Extension { .. }))
        // all arg types are `Some()`
        && self.arg_types().iter().all(Option::is_some)
        // no argument is an extension type
        && !self.arg_types().iter().any(|ty| matches!(ty, Some(SchemaType::Extension { .. })))
    }

    /// Call the `ExtensionFunction` with the given args
    pub fn call(&self, args: &[Value]) -> evaluator::Result<PartialValue> {
        match (self.func)(args)? {
            ExtensionOutputValue::Known(v) => Ok(PartialValue::Value(v)),
            ExtensionOutputValue::Unknown(u) => Ok(PartialValue::Residual(Expr::unknown(u))),
        }
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
pub trait ExtensionValue: Debug + Display + Send + Sync + UnwindSafe + RefUnwindSafe {
    /// Get the name of the type of this value.
    ///
    /// Cedar has nominal typing, so two values have the same type iff they
    /// return the same typename here.
    fn typename(&self) -> Name;
}

impl<V: ExtensionValue> StaticallyTyped for V {
    fn type_of(&self) -> Type {
        Type::Extension {
            name: self.typename(),
        }
    }
}

#[derive(Debug, Clone)]
/// Object container for extension values, also stores the constructor-and-args
/// that can reproduce the value (important for converting the value back to
/// `RestrictedExpr` for instance)
pub struct ExtensionValueWithArgs {
    value: Arc<dyn InternalExtensionValue>,
    pub(crate) constructor: Name,
    /// Args are stored in `RestrictedExpr` form, just because that's most
    /// convenient for reconstructing a `RestrictedExpr` that reproduces this
    /// extension value
    pub(crate) args: Vec<RestrictedExpr>,
}

impl ExtensionValueWithArgs {
    /// Create a new `ExtensionValueWithArgs`
    pub fn new(
        value: Arc<dyn InternalExtensionValue + Send + Sync>,
        constructor: Name,
        args: Vec<RestrictedExpr>,
    ) -> Self {
        Self {
            value,
            constructor,
            args,
        }
    }

    /// Get the internal value
    pub fn value(&self) -> &(dyn InternalExtensionValue) {
        self.value.as_ref()
    }

    /// Get the typename of this extension value
    pub fn typename(&self) -> Name {
        self.value.typename()
    }

    /// Get the constructor and args that can reproduce this value
    pub fn constructor_and_args(&self) -> (&Name, &[RestrictedExpr]) {
        (&self.constructor, &self.args)
    }
}

impl From<ExtensionValueWithArgs> for Expr {
    fn from(val: ExtensionValueWithArgs) -> Self {
        ExprBuilder::new().call_extension_fn(val.constructor, val.args.into_iter().map(Into::into))
    }
}

impl StaticallyTyped for ExtensionValueWithArgs {
    fn type_of(&self) -> Type {
        self.value.type_of()
    }
}

impl Display for ExtensionValueWithArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl PartialEq for ExtensionValueWithArgs {
    fn eq(&self, other: &Self) -> bool {
        // Values that are equal are equal regardless of which arguments made them
        self.value.as_ref() == other.value.as_ref()
    }
}

impl Eq for ExtensionValueWithArgs {}

impl PartialOrd for ExtensionValueWithArgs {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExtensionValueWithArgs {
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

impl<V: 'static + Eq + Ord + ExtensionValue + Send + Sync> InternalExtensionValue for V {
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
