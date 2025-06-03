pub(crate) fn new_symbol(
    name: String,
    range: lsp_types::Range,
    kind: lsp_types::SymbolKind,
) -> lsp_types::DocumentSymbol {
    lsp_types::DocumentSymbol {
        name,
        detail: None,
        kind,
        tags: None,
        range,
        selection_range: range,
        children: None,
        #[allow(deprecated)]
        deprecated: None,
    }
}
