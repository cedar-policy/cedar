use itertools::Itertools;
use nonempty::NonEmpty;

/// A trait for partitioning a collection of `Result`s into a collection of `Ok` values and a collection of `Err` values.
pub(crate) trait PartitionNonempty<T, E> {
    fn partition_nonempty(self) -> std::result::Result<Vec<T>, NonEmpty<E>>;
}

impl<I, T, E> PartitionNonempty<T, E> for I
where
    I: Iterator<Item = Result<T, E>>,
{
    fn partition_nonempty(self) -> Result<Vec<T>, NonEmpty<E>> {
        let (oks, errs): (Vec<_>, Vec<_>) = self.partition_result();

        if let Some(errs) = NonEmpty::from_vec(errs) {
            Err(errs)
        } else {
            Ok(oks)
        }
    }
}
