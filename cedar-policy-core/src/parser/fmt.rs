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

use std::fmt::{self, Write};

use super::cst::*;
use super::node::ASTNode;

/// Helper struct to handle non-existent nodes
struct View<'a, T>(&'a ASTNode<Option<T>>);
impl<'a, T: fmt::Display> fmt::Display for View<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(n) = &self.0.as_inner() {
            if f.alternate() {
                write!(f, "{:#}", n)
            } else {
                write!(f, "{}", n)
            }
        } else {
            write!(f, "[error]")
        }
    }
}

impl fmt::Display for Policies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            let mut ps = self.0.iter();
            if let Some(p) = ps.next() {
                write!(f, "{:#}", View(p))?;
            }
            for p in ps {
                write!(f, "\n\n{:#}", View(p))?;
            }
        } else {
            let mut ps = self.0.iter();
            if let Some(p) = ps.next() {
                write!(f, "{}", View(p))?;
            }
            for p in ps {
                write!(f, " {}", View(p))?;
            }
        }
        Ok(())
    }
}
impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // start with annotations
        for anno in self.annotations.iter() {
            if f.alternate() {
                // each annotation on a new line
                writeln!(f, "{:#}", View(anno))?;
            } else {
                write!(f, "{} ", View(anno))?;
            }
        }
        // main policy body
        if f.alternate() {
            write!(f, "{:#}(", View(&self.effect))?;
            let mut vars = self.variables.iter();
            // if at least one var ...
            if let Some(v) = vars.next() {
                // write out the first one ...
                write!(f, "\n  {:#}", View(v))?;
                // ... and write out the others after commas
                for v in vars {
                    write!(f, ",\n  {:#}", View(v))?;
                }
                // close up the vars
                write!(f, "\n)")?;
            } else {
                // no vars: stay on the same line
                write!(f, ")")?;
            }
            // include conditions on their own lines
            for c in self.conds.iter() {
                write!(f, "\n{:#}", View(c))?;
            }
            write!(f, ";")?;
        } else {
            write!(f, "{}(", View(&self.effect))?;
            let mut vars = self.variables.iter();
            // if at least one var ...
            if let Some(v) = vars.next() {
                // write out the first one ...
                write!(f, "{}", View(v))?;
                // ... and write out the others after commas
                for v in vars {
                    write!(f, ",  {}", View(v))?;
                }
            }
            write!(f, ")")?;

            for c in self.conds.iter() {
                write!(f, " {}", View(c))?;
            }
            write!(f, ";")?;
        }
        Ok(())
    }
}

impl fmt::Display for Annotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}({})", View(&self.key), View(&self.value))
    }
}

impl fmt::Display for VariableDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", View(&self.variable))?;
        if let Some(name) = &self.name {
            write!(f, ": {}", View(name))?;
        }
        if let Some((op, expr)) = &self.ineq {
            write!(f, " {} {}", op, View(expr))?;
        }
        Ok(())
    }
}
impl fmt::Display for Cond {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.expr.as_ref() {
            Some(expr_ref) => {
                if f.alternate() {
                    write!(f, "{} {{\n  {:#}\n}}", View(&self.cond), View(expr_ref))
                } else {
                    write!(f, "{} {{{}}}", View(&self.cond), View(expr_ref))
                }
            }
            None => write!(f, "{} {{ }}", View(&self.cond)),
        }
    }
}
impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let expr = &*self.expr;
        match expr {
            ExprData::Or(or) => write!(f, "{}", View(or)),
            ExprData::If(ex1, ex2, ex3) => {
                write!(f, "if {} then {} else {}", View(ex1), View(ex2), View(ex3))
            }
        }
    }
}
impl fmt::Display for Or {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", View(&self.initial))?;
        for or in self.extended.iter() {
            write!(f, " || {}", View(or))?;
        }
        Ok(())
    }
}
impl fmt::Display for And {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", View(&self.initial))?;
        for and in self.extended.iter() {
            write!(f, " && {}", View(and))?;
        }
        Ok(())
    }
}
impl fmt::Display for Relation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Relation::Common { initial, extended } => {
                write!(f, "{}", View(initial))?;
                for (op, add) in extended.iter() {
                    write!(f, " {} {}", op, View(add))?;
                }
            }
            Relation::Has { target, field } => {
                write!(f, "{} has {}", View(target), View(field))?;
            }
            Relation::Like { target, pattern } => {
                write!(f, "{} like {}", View(target), View(pattern))?;
            }
        }
        Ok(())
    }
}
impl fmt::Display for RelOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelOp::Less => write!(f, "<"),
            RelOp::LessEq => write!(f, "<="),
            RelOp::GreaterEq => write!(f, ">="),
            RelOp::Greater => write!(f, ">"),
            RelOp::NotEq => write!(f, "!="),
            RelOp::Eq => write!(f, "=="),
            RelOp::In => write!(f, "in"),
        }
    }
}
impl fmt::Display for AddOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddOp::Plus => write!(f, "+"),
            AddOp::Minus => write!(f, "-"),
        }
    }
}
impl fmt::Display for MultOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MultOp::Times => write!(f, "*"),
            MultOp::Divide => write!(f, "/"),
            MultOp::Mod => write!(f, "%"),
        }
    }
}
impl fmt::Display for NegOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NegOp::Bang(cnt) => {
                for _ in 0..*cnt {
                    write!(f, "!")?;
                }
            }
            // represents too many, current parser accepts a max of 4
            NegOp::OverBang => write!(f, "!!!!!!!!!!")?,
            NegOp::Dash(cnt) => {
                for _ in 0..*cnt {
                    write!(f, "-")?;
                }
            }
            // represents too many, current parser accepts a max of 4
            NegOp::OverDash => write!(f, "----------")?,
        }
        Ok(())
    }
}
impl fmt::Display for Add {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", View(&self.initial))?;
        for (op, mult) in self.extended.iter() {
            write!(f, " {} {}", op, View(mult))?;
        }
        Ok(())
    }
}
impl fmt::Display for Mult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", View(&self.initial))?;
        for (op, un) in self.extended.iter() {
            write!(f, " {} {}", op, View(un))?;
        }
        Ok(())
    }
}
impl fmt::Display for Unary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(op) = &self.op {
            write!(f, "{}{}", op, View(&self.item))
        } else {
            write!(f, "{}", View(&self.item))
        }
    }
}
impl fmt::Display for Member {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", View(&self.item))?;
        for m in self.access.iter() {
            write!(f, "{}", View(m))?;
        }
        Ok(())
    }
}
impl fmt::Display for MemAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemAccess::Field(id) => write!(f, ".{}", View(id))?,
            MemAccess::Call(exprs) => {
                write!(f, "(")?;
                let mut es = exprs.iter();
                if let Some(ex) = es.next() {
                    write!(f, "{}", View(ex))?;
                }
                for e in es {
                    write!(f, ", {}", View(e))?;
                }
                write!(f, ")")?;
            }
            MemAccess::Index(e) => write!(f, "[{}]", View(e))?,
        }
        Ok(())
    }
}
impl fmt::Display for Primary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Primary::Literal(lit) => write!(f, "{}", View(lit)),
            Primary::Ref(rf) => write!(f, "{}", View(rf)),
            Primary::Name(nm) => write!(f, "{}", View(nm)),
            Primary::Expr(expr) => write!(f, "({})", View(expr)),
            Primary::EList(exs) => {
                write!(f, "[")?;
                let mut es = exs.iter();
                if let Some(ex) = es.next() {
                    write!(f, "{}", View(ex))?;
                }
                for e in es {
                    write!(f, ", {}", View(e))?;
                }
                write!(f, "]")
            }
            Primary::RInits(mis) => {
                write!(f, "{{")?;
                let mut ms = mis.iter();
                if let Some(i) = ms.next() {
                    write!(f, "{}", View(i))?;
                }
                for i in ms {
                    write!(f, ", {}", View(i))?;
                }
                write!(f, "}}")
            }
            Primary::Slot(s) => write!(f, "{}", View(s)),
        }
    }
}
impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for n in self.path.iter() {
            write!(f, "{}::", View(n))?;
        }
        write!(f, "{}", View(&self.name))?;
        Ok(())
    }
}
impl fmt::Display for Ref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ref::Uid { path, eid } => {
                write!(f, "{}::{}", View(path), View(eid))?;
            }
            Ref::Ref { path, rinits } => {
                write!(f, "{}::{{", View(path))?;
                let mut ris = rinits.iter();
                if let Some(r) = ris.next() {
                    write!(f, "{}", View(r))?;
                }
                for r in ris {
                    write!(f, ", {}", View(r))?;
                }
                write!(f, "}}")?;
            }
        }
        Ok(())
    }
}
impl fmt::Display for RefInit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", View(&self.0), View(&self.1))
    }
}
impl fmt::Display for RecInit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", View(&self.0), View(&self.1))
    }
}
impl fmt::Display for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ident::Principal => write!(f, "principal"),
            Ident::Action => write!(f, "action"),
            Ident::Resource => write!(f, "resource"),
            Ident::Context => write!(f, "context"),
            Ident::True => write!(f, "true"),
            Ident::False => write!(f, "false"),
            Ident::Permit => write!(f, "permit"),
            Ident::Forbid => write!(f, "forbid"),
            Ident::When => write!(f, "when"),
            Ident::Unless => write!(f, "unless"),
            Ident::In => write!(f, "in"),
            Ident::Has => write!(f, "has"),
            Ident::Like => write!(f, "like"),
            Ident::If => write!(f, "if"),
            Ident::Then => write!(f, "then"),
            Ident::Else => write!(f, "else"),
            Ident::Ident(s) => write!(f, "{}", s),
            Ident::Invalid(s) => write!(f, "{}", s),
        }
    }
}
impl fmt::Display for Literal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Literal::True => write!(f, "true"),
            Literal::False => write!(f, "false"),
            Literal::Num(n) => write!(f, "{}", n),
            Literal::Str(s) => write!(f, "{}", View(s)),
        }
    }
}
impl fmt::Display for Str {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Str::String(s) | Str::Invalid(s) => {
                write!(f, "\"{}\"", s)
            }
        }
    }
}

impl std::fmt::Display for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let src = match self {
            Slot::Principal => "principal",
            Slot::Resource => "resource",
        };
        write!(f, "?{src}")
    }
}

pub fn join_with_conjunction<T, W: Write>(
    f: &mut W,
    conjunction: &str,
    items: impl IntoIterator<Item = T>,
    fmt_item: impl Fn(&mut W, T) -> fmt::Result,
) -> fmt::Result {
    let mut iter = items.into_iter().peekable();

    if let Some(first_item) = iter.next() {
        fmt_item(f, first_item)?;

        if let Some(second_item) = iter.next() {
            match iter.peek() {
                Some(_) => write!(f, ", "),
                None => write!(f, " {conjunction} "),
            }?;

            fmt_item(f, second_item)?;

            while let Some(item) = iter.next() {
                match iter.peek() {
                    Some(_) => write!(f, ", "),
                    None => write!(f, ", {conjunction} "),
                }?;

                fmt_item(f, item)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::parser::*;

    // Currently, hese tests supplement the ones in the main test
    // directory, rather than testing everything themselves

    #[test]
    fn idempotent1() {
        // Note: the context field in the head is no longer supported and
        // will produce an error during CST -> AST conversion. But it is
        // still correctly parsed & displayed by the CST code.
        let cstnode1 = text_to_cst::parse_policies(
            r#"

        permit(principal,action,resource,context)
        when {
            -3 != !!2
        };

        "#,
        )
        .expect("parse fail");
        let cst1 = cstnode1.as_inner().expect("no data");
        let revert = format!("{}", cst1);
        let cstnode2 = text_to_cst::parse_policies(&revert).expect("parse fail");
        let cst2 = cstnode2.as_inner().expect("no data");
        println!("{:#}", cst2);
        assert!(cst1 == cst2);
    }
    #[test]
    fn idempotent2() {
        let cstnode1 = text_to_cst::parse_policies(
            r#"

        permit(principal,action,resource,context)
        when {
            context.contains(3,"four",five(6,7))
        };

        "#,
        )
        .expect("parse fail");
        let cst1 = cstnode1.as_inner().expect("no data");
        let revert = format!("{}", cst1);
        let cstnode2 = text_to_cst::parse_policies(&revert).expect("parse fail");
        let cst2 = cstnode2.as_inner().expect("no data");
        assert!(cst1 == cst2);
    }
    #[test]
    fn idempotent3() {
        let cstnode1 = text_to_cst::parse_policies(
            r#"

        permit(principal,action,resource,context)
        when {
            context == {3: 14, "true": false || true }
        };

        "#,
        )
        .expect("parse fail");
        let cst1 = cstnode1.as_inner().expect("no data");
        let revert = format!("{}", cst1);
        let cstnode2 = text_to_cst::parse_policies(&revert).expect("parse fail");
        let cst2 = cstnode2.as_inner().expect("no data");
        assert!(cst1 == cst2);
    }
    #[test]
    fn idempotent4() {
        let cstnode1 = text_to_cst::parse_policies(
            r#"

        permit(principal,action,resource,context)
        when {
            contains() ||
            containsAll() ||
            containsAny() ||
            "sometext" like "some*" ||
            Random::naming::of::foo()
        };

        "#,
        )
        .expect("parse fail");
        let cst1 = cstnode1.as_inner().expect("no data");
        let revert = format!("{}", cst1);
        println!("{:#}", cst1);
        let cstnode2 = text_to_cst::parse_policies(&revert).expect("parse fail");
        let cst2 = cstnode2.as_inner().expect("no data");
        assert!(cst1 == cst2);
    }

    #[test]
    fn idempotent5() {
        let cstnode1 = text_to_cst::parse_policies(
            r#"

        permit(principal,action,resource,context)
        when {
            principle == Group::{uid:"ajn34-3qg3-g5"}
        };

        "#,
        )
        .expect("parse fail");
        let cst1 = cstnode1.as_inner().expect("no data");
        let revert = format!("{}", cst1);
        let cstnode2 = text_to_cst::parse_policies(&revert).expect("parse fail");
        let cst2 = cstnode2.as_inner().expect("no data");
        assert!(cst1 == cst2);
    }
}
