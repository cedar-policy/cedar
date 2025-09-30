use std::sync::Arc;

use crate::ast::Id;

/// A path containing a list of identifiers
#[derive(Clone)]
pub enum Path {
    /// An owned list of identifiers
    Arc(Arc<[Id]>),
    /// A static list of identifiers
    Static(&'static [Id]),
}

impl From<Vec<Id>> for Path {
    fn from(value: Vec<Id>) -> Self {
        Self::Arc(value.into())
    }
}

impl From<Arc<[Id]>> for Path {
    fn from(value: Arc<[Id]>) -> Self {
        Self::Arc(value)
    }
}

impl From<&'static [Id]> for Path {
    fn from(value: &'static [Id]) -> Self {
        Self::Static(value)
    }
}

impl AsRef<[Id]> for Path {
    fn as_ref(&self) -> &[Id] {
        match self {
            Self::Arc(value) => value.as_ref(),
            Self::Static(value) => value,
        }
    }
}

impl<'a> IntoIterator for &'a Path {
    type Item = &'a Id;
    type IntoIter = std::slice::Iter<'a, Id>;
    fn into_iter(self) -> Self::IntoIter {
        self.as_ref().iter()
    }
}

impl FromIterator<Id> for Path {
    fn from_iter<T: IntoIterator<Item = Id>>(iter: T) -> Self {
        Self::Arc(iter.into_iter().collect())
    }
}

impl Path {
    /// Create a new [`Path`] from an iterator
    pub fn new(iter: impl IntoIterator<Item = Id>) -> Self {
        Self::from_iter(iter)
    }

    /// Create a new [`Path`] from a static slice
    pub const fn new_from_static(slice: &'static [Id]) -> Self {
        Self::Static(slice)
    }

    /// Create a new [`Path`] from an arc
    pub const fn new_from_arc(ptr: Arc<[Id]>) -> Self {
        Self::Arc(ptr)
    }

    /// Create a new [`Path`] with no elements
    pub const fn empty() -> Self {
        Self::Static(&[])
    }

    /// Convert a [`Path`] to a [`Vec<Id>`]
    pub fn to_vec(&self) -> Vec<Id> {
        self.as_ref().to_vec()
    }

    /// Borrowed iteration of the [`Path`]'s elements
    pub fn iter(&self) -> impl Iterator<Item = &Id> {
        self.into_iter()
    }

    /// Check if the [`Path`] is empty
    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }

    /// Convert a [`Path`] to a slice
    pub fn as_slice(&self) -> &[Id] {
        self.as_ref()
    }

    /// Check if the [`Path`] is static
    pub const fn is_static(&self) -> bool {
        matches!(self, Self::Static(_))
    }
}

impl std::fmt::Debug for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_slice().fmt(f)
    }
}

impl PartialEq<[Id]> for Path {
    fn eq(&self, other: &[Id]) -> bool {
        self.as_slice() == other
    }
}

impl PartialEq<Path> for [Id] {
    fn eq(&self, other: &Path) -> bool {
        other == self
    }
}

impl PartialEq<Path> for Path {
    fn eq(&self, other: &Path) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl std::hash::Hash for Path {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
    }
}

impl Eq for Path {}

impl PartialOrd<[Id]> for Path {
    fn partial_cmp(&self, other: &[Id]) -> Option<std::cmp::Ordering> {
        self.as_slice().partial_cmp(other)
    }
}

impl PartialOrd<Path> for [Id] {
    fn partial_cmp(&self, other: &Path) -> Option<std::cmp::Ordering> {
        other.partial_cmp(self)
    }
}

impl PartialOrd<Path> for Path {
    fn partial_cmp(&self, other: &Path) -> Option<std::cmp::Ordering> {
        self.as_slice().partial_cmp(other.as_slice())
    }
}

impl Ord for Path {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}
