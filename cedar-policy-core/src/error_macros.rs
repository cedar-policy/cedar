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

/// Macro which implements the `.labels()` and `.source_code()` methods of
/// `miette::Diagnostic` by using the `self.source_loc` field (assumed to be an
/// `Option<Loc>`)
#[macro_export]
macro_rules! impl_diagnostic_from_source_loc_field {
    () => {
        fn source_code(&self) -> Option<&dyn miette::SourceCode> {
            self.source_loc
                .as_ref()
                .map(|loc| &loc.src as &dyn miette::SourceCode)
        }

        fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
            self.source_loc.as_ref().map(|loc| {
                Box::new(std::iter::once(miette::LabeledSpan::underline(loc.span)))
                    as Box<dyn Iterator<Item = _>>
            })
        }
    };
}

/// Macro which implements the `.labels()` and `.source_code()` methods of
/// `miette::Diagnostic` by using the parameter `$i` which must be an `Expr`
/// (or `Box<Expr>`) type field.
#[macro_export]
macro_rules! impl_diagnostic_from_expr_field {
    ( $i:ident ) => {
        fn source_code(&self) -> Option<&dyn miette::SourceCode> {
            self.$i
                .source_loc()
                .as_ref()
                .map(|loc| &loc.src as &dyn miette::SourceCode)
        }

        fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
            self.$i.source_loc().as_ref().map(|loc| {
                Box::new(std::iter::once(miette::LabeledSpan::underline(loc.span)))
                    as Box<dyn Iterator<Item = _>>
            })
        }
    };
}
