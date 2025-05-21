
#[macro_export]
macro_rules! maybe_loc {
    ($flag:ident, $loc:expr) => {
        if $flag {
            None
        } else {
            Some(Box::new($loc))
        }
    }
}
