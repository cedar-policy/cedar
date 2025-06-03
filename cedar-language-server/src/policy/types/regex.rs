use std::sync::LazyLock;

use regex::Regex;

pub(crate) static PRINCIPAL_IS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"principal\s+is\s*").unwrap());

pub(crate) static ACTION_IN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"action\s+in\s*").unwrap());
pub(crate) static ACTION_EQ_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"action\s+==\s*").unwrap());
pub(crate) static ACTION_IN_ARRAY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"action\s+in\s+\[(?:\s*(?:[A-Za-z]+::)?Action::"[\w]+?"\s*,?)*\s*"#).unwrap()
});

pub(crate) static RESOURCE_IS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"resource\s+is\s*").unwrap());
