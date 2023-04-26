use super::token::WrappedToken;

/// Configuraton struct that specifies line width and indentation width
#[derive(Debug, Clone)]
pub struct Config {
    pub line_width: usize,
    pub indent_width: isize,
}

#[derive(Debug)]
pub struct Context<'a> {
    pub config: &'a Config,
    pub tokens: Vec<WrappedToken>,
}
