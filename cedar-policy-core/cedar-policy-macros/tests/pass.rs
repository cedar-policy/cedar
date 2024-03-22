use cedar_policy_core::ast::{Eid, EntityUID};
use cedar_policy_macros::euid;

fn main() {
    let e: EntityUID = euid!(Foo, "bar");
    assert_eq!(e.entity_type().to_string(), "Foo");
    assert_eq!(<Eid as AsRef<str>>::as_ref(e.eid()), "bar");
    let e: EntityUID = euid!(Foo::Bar, "baz");
    assert_eq!(e.entity_type().to_string(), "Foo::Bar");
    assert_eq!(<Eid as AsRef<str>>::as_ref(e.eid()), "baz");
    let e: EntityUID = euid!(Foo, "\n");
    assert_eq!(e.entity_type().to_string(), "Foo");
    assert_eq!(<Eid as AsRef<str>>::as_ref(e.eid()), "\n");
    let e: EntityUID = euid!(Foo, "\\n");
    assert_eq!(e.entity_type().to_string(), "Foo");
    assert_eq!(<Eid as AsRef<str>>::as_ref(e.eid()), r#"\n"#);
}
