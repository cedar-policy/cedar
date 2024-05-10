/// Macro which implements the `.labels()` and `.source_code()` methods of
/// `miette::Diagnostic` by using the `self.source_loc` field (assumed to be an
/// `Option<Loc>`)
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
