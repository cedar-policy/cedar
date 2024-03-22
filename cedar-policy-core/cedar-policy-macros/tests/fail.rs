use cedar_policy_core::ast::EntityUID;
use cedar_policy_macros::euid;

fn main() {
    let _: EntityUID = euid!(f, "bar");
    let _: EntityUID = euid!(Foo::Bar, "baz");
    let _: EntityUID = euid!(Foo, "ha");
}
