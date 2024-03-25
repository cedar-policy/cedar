fn main() {
    use cedar_policy::euid;
    euid!(::, "foo");
    euid!(a::東京::b, "foo");
}