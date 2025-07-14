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

use itertools::Itertools;
use tokio::io::AsyncWriteExt;

/// a helper function here, rather than a trait method, because we want it to be
/// private, and we can't make trait methods private
async fn emitln(
    w: &mut (impl tokio::io::AsyncWrite + Unpin + ?Sized),
    str: &str,
) -> tokio::io::Result<()> {
    w.write_all(str.as_bytes()).await?;
    w.write_all(b"\n").await?;
    Ok(())
}

/// Abstraction layer to write output in the SMTLib2 format
#[allow(async_fn_in_trait)]
pub trait SmtLibScript {
    async fn set_logic(&mut self, logic: &str) -> tokio::io::Result<()>;
    async fn set_option(&mut self, option: &str, value: &str) -> tokio::io::Result<()>;
    async fn comment(&mut self, comment: &str) -> tokio::io::Result<()>;
    async fn assert(&mut self, expr: &str) -> tokio::io::Result<()>;
    async fn define_fun<'a>(
        &mut self,
        id: &str,
        args: impl IntoIterator<Item = (&'a str, &'a str)>,
        ty: &str,
        expr: &str,
    ) -> tokio::io::Result<()>;
    async fn declare_const(&mut self, id: &str, ty: &str) -> tokio::io::Result<()>;
    async fn declare_fun(
        &mut self,
        id: &str,
        args: impl IntoIterator<Item = String>,
        ty: &str,
    ) -> tokio::io::Result<()>;
    async fn declare_datatype<'a>(
        &mut self,
        id: &str,
        params: impl IntoIterator<Item = &'a str>,
        constructors: impl IntoIterator<Item = String>,
    ) -> tokio::io::Result<()>;
    async fn check_sat(&mut self) -> tokio::io::Result<()>;
    async fn get_model(&mut self) -> tokio::io::Result<()>;
    async fn reset(&mut self) -> tokio::io::Result<()>;
    async fn exit(&mut self) -> tokio::io::Result<()>;
}

/// Blanket impl that provides an implementation of `SmtLibScript` for any type
/// that implements `AsyncWrite`. This means that you can use these methods to
/// write to any `AsyncWrite` as long as you bring this trait into scope.
impl<W: tokio::io::AsyncWrite + Unpin + ?Sized> SmtLibScript for W {
    async fn set_logic(&mut self, logic: &str) -> tokio::io::Result<()> {
        emitln(self, &format!("(set-logic {logic})")).await
    }

    async fn comment(&mut self, comment: &str) -> tokio::io::Result<()> {
        let inline = comment.replace("\n", " ");
        emitln(self, &format!("; {inline}")).await
    }

    async fn assert(&mut self, expr: &str) -> tokio::io::Result<()> {
        emitln(self, &format!("(assert {expr})")).await
    }

    async fn set_option(&mut self, option: &str, value: &str) -> tokio::io::Result<()> {
        emitln(self, &format!("(set-option :{option} {value})")).await
    }

    async fn define_fun<'a>(
        &mut self,
        id: &str,
        args: impl IntoIterator<Item = (&'a str, &'a str)>,
        ty: &str,
        expr: &str,
    ) -> tokio::io::Result<()> {
        let inline = args
            .into_iter()
            .map(|(pi, pt)| format!("({pi} {pt})"))
            .join(" ");
        emitln(self, &format!("(define-fun {id} ({inline}) {ty} {expr})")).await
    }

    async fn declare_const(&mut self, id: &str, ty: &str) -> tokio::io::Result<()> {
        emitln(self, &format!("(declare-const {id} {ty})")).await
    }

    async fn declare_fun(
        &mut self,
        id: &str,
        args: impl IntoIterator<Item = String>,
        ty: &str,
    ) -> tokio::io::Result<()> {
        let inline = args.into_iter().join(" ");
        emitln(self, &format!("(declare-fun {id} ({inline}) {ty})")).await
    }

    async fn declare_datatype<'a>(
        &mut self,
        id: &str,
        params: impl IntoIterator<Item = &'a str>,
        constructors: impl IntoIterator<Item = String>,
    ) -> tokio::io::Result<()> {
        let c_inline = "\n  ".to_string() + &constructors.into_iter().join("\n  ");
        let p_inline = params.into_iter().join(" ");
        if p_inline.is_empty() {
            emitln(self, &format!("(declare-datatype {id} ({c_inline}))")).await
        } else {
            emitln(
                self,
                &format!("(declare-datatype {id} (par ({p_inline}) ({c_inline})))"),
            )
            .await
        }
    }

    async fn check_sat(&mut self) -> tokio::io::Result<()> {
        emitln(self, "(check-sat)").await
    }

    async fn get_model(&mut self) -> tokio::io::Result<()> {
        emitln(self, "(get-model)").await
    }

    async fn reset(&mut self) -> tokio::io::Result<()> {
        emitln(self, "(reset)").await
    }

    async fn exit(&mut self) -> tokio::io::Result<()> {
        emitln(self, "(exit)").await
    }
}
