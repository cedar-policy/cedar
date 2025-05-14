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
/// `miette::Diagnostic` by using the parameter `$i` which must be the name
/// of a field of type `Loc`
#[macro_export]
macro_rules! impl_diagnostic_from_source_loc_field {
    ( $i:ident ) => {
        fn source_code(&self) -> Option<&dyn miette::SourceCode> {
            None
        }

        fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
            Some(Box::new(std::iter::once(miette::LabeledSpan::underline(
                self.$i.span,
            ))) as _)
        }
    };
}

/// Macro which implements the `.labels()` and `.source_code()` methods of
/// `miette::Diagnostic` by using the parameter `$i` which must be the name
/// of a field of type `Option<Loc>`
#[macro_export]
macro_rules! impl_diagnostic_from_source_loc_opt_field {
    ( $($id:ident).+ ) => {
        fn source_code(&self) -> Option<&dyn miette::SourceCode> {
            None
        }

        fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
            self.$($id).+
                .as_ref()
                .map(|loc| Box::new(std::iter::once(miette::LabeledSpan::underline(loc.span))) as _)
        }
    };
}

/// Macro which implements the `.labels()` and `.source_code()` methods of
/// `miette::Diagnostic` by using the parameters `$i` and `$j` which must be
/// names of fields of type `Loc`.
/// Both locations will be underlined. It is assumed they have the same `src`.
#[macro_export]
macro_rules! impl_diagnostic_from_two_source_loc_fields {
    ( $i:ident, $j:ident ) => {
        fn source_code(&self) -> Option<&dyn miette::SourceCode> {
            None
        }

        fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
            Some(Box::new(
                [
                    miette::LabeledSpan::underline(self.$i.span),
                    miette::LabeledSpan::underline(self.$j.span),
                ]
                .into_iter(),
            ) as _)
        }
    };
}

/// Macro which implements the `.labels()` and `.source_code()` methods of
/// `miette::Diagnostic` by using the parameters `$i` and `$j` which must be the
/// names of fields of type `Option<Loc>`.
/// Both locations will be underlined, if both locs are present.
/// It is assumed that both locs have the same `src`, if both locs are present.
#[macro_export]
macro_rules! impl_diagnostic_from_two_source_loc_opt_fields {
    ( $i:ident , $j:ident ) => {
        fn source_code(&self) -> Option<&dyn miette::SourceCode> {
            None
        }

        fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
            let x = self
                .$i
                .as_ref()
                .map(|loc| miette::LabeledSpan::underline(loc.span));
            let y = self
                .$j
                .as_ref()
                .map(|loc| miette::LabeledSpan::underline(loc.span));

            match (x, y) {
                (None, None) => None,
                (Some(span), None) | (None, Some(span)) => Some(Box::new(std::iter::once(span))),
                (Some(span_a), Some(span_b)) => Some(Box::new([span_a, span_b].into_iter()) as _),
            }
        }
    };
}

/// Macro which implements the `.labels()` and `.source_code()` methods of
/// `miette::Diagnostic` by using the parameter `$i` which must be a field
/// of some type for which the method `$m()` returns `Option<&Loc>`.
/// E.g., a field of type `Expr` or `Box<Expr>`, where `$m` is `source_loc`.
#[macro_export]
macro_rules! impl_diagnostic_from_method_on_field {
    ( $i:ident, $m:ident ) => {
        fn source_code(&self) -> Option<&dyn miette::SourceCode> {
            None
        }

        fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
            self.$i
                .$m()
                .as_ref()
                .map(|loc| Box::new(std::iter::once(miette::LabeledSpan::underline(loc.span))) as _)
        }
    };
}

/// Macro which implements the `.labels()` and `.source_code()` methods of
/// `miette::Diagnostic` by using the parameter `$i` which must be a field
/// of type `NonEmpty<T>` where `T` has a method `$m()` which returns `Option<&Loc>`.
/// E.g., a field of type `NonEmpty<EntityUID>`, where `$m` is `loc`.
/// Only the first item in the `NonEmpty` will be underlined.
#[macro_export]
macro_rules! impl_diagnostic_from_method_on_nonempty_field {
    ( $i:ident, $m:ident ) => {
        fn source_code(&self) -> Option<&dyn miette::SourceCode> {
            None
        }

        fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
            self.$i
                .first()
                .$m()
                .as_ref()
                .map(|loc| Box::new(std::iter::once(miette::LabeledSpan::underline(loc.span))) as _)
        }
    };
}
