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

//! [`ArcOrd`], an `Arc` whose ordering includes a fast-path for pointer equal values.

use std::cmp::Ordering;
use std::fmt::{self, Display};
use std::ops::Deref;
use std::sync::Arc;

/// An `Arc<T>` that compares `Equal` without recursing when both sides are the same
/// allocation.
///
/// Used to optimize Term memoization in the encoder.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArcOrd<T: ?Sized>(Arc<T>);

impl<T: ?Sized + Ord> Ord for ArcOrd<T> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        if Arc::ptr_eq(&self.0, &other.0) {
            Ordering::Equal
        } else {
            T::cmp(&self.0, &other.0)
        }
    }
}

impl<T: ?Sized + Ord> PartialOrd for ArcOrd<T> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> ArcOrd<T> {
    /// Mirrors `Arc::new`.
    #[inline]
    pub fn new(t: T) -> Self {
        Self(Arc::new(t))
    }
}

impl<T: Clone> ArcOrd<T> {
    /// Mirrors `Arc::unwrap_or_clone`.
    #[inline]
    pub fn unwrap_or_clone(this: Self) -> T {
        Arc::unwrap_or_clone(this.0)
    }
}

impl<T: ?Sized> Deref for ArcOrd<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> AsRef<T> for ArcOrd<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized + Display> Display for ArcOrd<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
