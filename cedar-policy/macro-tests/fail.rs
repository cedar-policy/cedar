fn main() {
    use cedar_policy::euid;
    // no type name
    euid!(,"");
    // no eid
    euid!(a,);
    // single arg
    euid!(a);
    euid!("");
    // wrong type name arg type
    euid!("", "");
    // wrong eid type name
    euid!(a, a);
    // just colons
    euid!(::, "foo");
    // invalid id
    euid!(a::東京::b, "foo");
    // invalid escape sequences
    euid!(a, "\*");
}