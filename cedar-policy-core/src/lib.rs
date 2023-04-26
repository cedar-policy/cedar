//! Implementation of the Cedar parser and evaluation engine in Rust.
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]

#[macro_use]
extern crate lalrpop_util;

pub mod ast;
pub mod authorizer;
pub mod entities;
pub mod est;
pub mod evaluator;
pub mod extensions;
pub mod parser;
pub mod transitive_closure;
