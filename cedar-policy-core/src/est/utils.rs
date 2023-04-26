use std::sync::Arc;

/// Arc::unwrap_or_clone() isn't stabilized as of this writing, but this is its implementation
pub fn unwrap_or_clone<T: Clone>(arc: Arc<T>) -> T {
    Arc::try_unwrap(arc).unwrap_or_else(|arc| (*arc).clone())
}
