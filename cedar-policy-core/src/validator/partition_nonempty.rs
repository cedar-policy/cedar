use itertools::Itertools;
use nonempty::NonEmpty;

/// A trait for partitioning a collection of `Result`s into a collection of `Ok` values or a `NonEmpty` of `Err` values.
pub(crate) trait PartitionNonEmpty<T, E> {
    fn partition_nonempty<C>(self) -> std::result::Result<C, NonEmpty<E>>
    where
        C: Default + Extend<T>;
}

impl<I, T, E> PartitionNonEmpty<T, E> for I
where
    I: Iterator<Item = Result<T, E>>,
{
    fn partition_nonempty<C>(self) -> Result<C, NonEmpty<E>>
    where
        C: Default + Extend<T>,
    {
        let (oks, errs): (_, Vec<_>) = self.partition_result();

        if let Some(errs) = NonEmpty::from_vec(errs) {
            Err(errs)
        } else {
            Ok(oks)
        }
    }
}
