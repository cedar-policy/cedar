/// Return a `MaybeLoc` value that depends on the flag
#[macro_export]
macro_rules! maybe_loc {
    ($flag:ident, $loc:expr) => {
        if $flag {
            None
        } else {
            #[cfg(feature = "fast-parsing")]
            {
                Some(Box::new($loc))
            }
            #[cfg(not(feature = "fast-parsing"))]
            {
                Some($loc)
            }
        }
    };
}
