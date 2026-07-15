//! Each test snapshots the emitted Lean (via `insta`) and compiles it against
//! the `Cedar.Spec` stub, so output is checked both textually and for
//! type-correctness. After an intentional emitter change, run
//! `cargo insta review`. Requires `lean` on `PATH` — see `tests/common/mod.rs`.

mod common;

use cedar_lean_symc::Property;
use common::{cond_expr, lean, lean_two_with_properties, lean_with_properties};

// ----- whole-policy snapshots -----

#[test]
fn allow_all_static_policy() {
    insta::assert_snapshot!(lean("permit(principal, action, resource);"), @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .permit,
        .principalScope (.any),
        .actionScope .any,
        .resourceScope (.any),
        [] ⟩

    def policies : Policies := [policy0]
    "#);
}

#[test]
fn forbid_effect() {
    insta::assert_snapshot!(lean("forbid(principal, action, resource);"), @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .forbid,
        .principalScope (.any),
        .actionScope .any,
        .resourceScope (.any),
        [] ⟩

    def policies : Policies := [policy0]
    "#);
}

#[test]
fn scope_eq_in_is_ismem() {
    let out = lean(
        r#"permit(
            principal is User in Group::"g",
            action == Action::"a",
            resource in Folder::"f"
        );"#,
    );
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .permit,
        .principalScope (.isMem (⟨"User", []⟩) (⟨⟨"Group", []⟩, "g"⟩)),
        .actionScope (.eq (⟨⟨"Action", []⟩, "a"⟩)),
        .resourceScope (.mem (⟨⟨"Folder", []⟩, "f"⟩)),
        [] ⟩

    def policies : Policies := [policy0]
    "#);
}

#[test]
fn scope_is_only() {
    let out = lean("permit(principal is User, action, resource);");
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .permit,
        .principalScope (.is (⟨"User", []⟩)),
        .actionScope .any,
        .resourceScope (.any),
        [] ⟩

    def policies : Policies := [policy0]
    "#);
}

#[test]
fn namespaced_entity_type() {
    let out = lean(r#"permit(principal == PhotoApp::User::"a", action, resource);"#);
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .permit,
        .principalScope (.eq (⟨⟨"User", ["PhotoApp"]⟩, "a"⟩)),
        .actionScope .any,
        .resourceScope (.any),
        [] ⟩

    def policies : Policies := [policy0]
    "#);
}

#[test]
fn deeply_namespaced_entity_type() {
    let out = lean(r#"permit(principal == A::B::C::User::"a", action, resource);"#);
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .permit,
        .principalScope (.eq (⟨⟨"User", ["A", "B", "C"]⟩, "a"⟩)),
        .actionScope .any,
        .resourceScope (.any),
        [] ⟩

    def policies : Policies := [policy0]
    "#);
}

#[test]
fn action_in_list_becomes_action_in_any() {
    let out = lean(r#"permit(principal, action in [Action::"a", Action::"b"], resource);"#);
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .permit,
        .principalScope (.any),
        .actionInAny [⟨⟨"Action", []⟩, "a"⟩, ⟨⟨"Action", []⟩, "b"⟩],
        .resourceScope (.any),
        [] ⟩

    def policies : Policies := [policy0]
    "#);
}

#[test]
fn single_action_in_becomes_action_in_any() {
    // A single `action in X` is modeled the same as a list.
    let out = lean(r#"permit(principal, action in Action::"a", resource);"#);
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .permit,
        .principalScope (.any),
        .actionInAny [⟨⟨"Action", []⟩, "a"⟩],
        .resourceScope (.any),
        [] ⟩

    def policies : Policies := [policy0]
    "#);
}

#[test]
fn empty_action_in_list() {
    let out = lean(r#"permit(principal, action in [], resource);"#);
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .permit,
        .principalScope (.any),
        .actionInAny [],
        .resourceScope (.any),
        [] ⟩

    def policies : Policies := [policy0]
    "#);
}

#[test]
fn template_emits_template_with_slots() {
    let out = lean(r#"permit(principal == ?principal, action, resource in ?resource);"#);
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def template0 : Template :=
      ⟨ .permit,
        .principalScope (.eq (.slot "?principal")),
        .actionScope .any,
        .resourceScope (.mem (.slot "?resource")),
        [] ⟩

    def policies : Policies := []
    "#);
}

#[test]
fn template_is_in_slot() {
    let out = lean(r#"permit(principal is User in ?principal, action, resource);"#);
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def template0 : Template :=
      ⟨ .permit,
        .principalScope (.isMem (⟨"User", []⟩) (.slot "?principal")),
        .actionScope .any,
        .resourceScope (.any),
        [] ⟩

    def policies : Policies := []
    "#);
}

#[test]
fn multiple_policies_sorted_by_id() {
    let out = lean(
        "permit(principal, action, resource);\n\
         forbid(principal, action, resource);",
    );
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .permit,
        .principalScope (.any),
        .actionScope .any,
        .resourceScope (.any),
        [] ⟩

    def policy1 : Policy :=
      ⟨ "policy1",
        .forbid,
        .principalScope (.any),
        .actionScope .any,
        .resourceScope (.any),
        [] ⟩

    def policies : Policies := [policy0, policy1]
    "#);
}

#[test]
fn mixed_static_and_template() {
    // Static policies are emitted before templates.
    let out = lean(
        "permit(principal, action, resource);\n\
         permit(principal == ?principal, action, resource);",
    );
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .permit,
        .principalScope (.any),
        .actionScope .any,
        .resourceScope (.any),
        [] ⟩

    def template0 : Template :=
      ⟨ .permit,
        .principalScope (.eq (.slot "?principal")),
        .actionScope .any,
        .resourceScope (.any),
        [] ⟩

    def policies : Policies := [policy0]
    "#);
}

#[test]
fn empty_policyset() {
    insta::assert_snapshot!(lean(""), @"
    import Cedar.Spec

    open Cedar.Spec

    def policies : Policies := []
    ");
}

// ----- condition / expression snapshots -----

#[test]
fn when_condition_and_negative_int() {
    insta::assert_snapshot!(
      cond_expr("context.x == -5"),
      @r#".binaryApp (.eq) (.getAttr (.var .context) "x") (.lit (.int (-5)))"#
    );
}

#[test]
fn unless_condition_is_negated() {
    let out = lean("permit(principal, action, resource) unless { context.b };");
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .permit,
        .principalScope (.any),
        .actionScope .any,
        .resourceScope (.any),
        [⟨.when, .unaryApp (.not) (.getAttr (.var .context) "b")⟩] ⟩

    def policies : Policies := [policy0]
    "#);
}

#[test]
fn multiple_conditions_folded() {
    // Cedar folds multiple clauses into a single non-scope constraint, so we
    // emit a single `when` condition holding a conjunction.
    insta::assert_snapshot!(
      cond_expr("context.a } when { context.b"),
      @r#".and (.getAttr (.var .context) "a") (.getAttr (.var .context) "b")"#
    );
}

#[test]
fn when_then_unless_folds_to_conjunction() {
    insta::assert_snapshot!(
      cond_expr("context.a } unless { context.b"),
      @r#".and (.getAttr (.var .context) "a") (.unaryApp (.not) (.getAttr (.var .context) "b"))"#
    );
}

#[test]
fn boolean_literals() {
    insta::assert_snapshot!(
      cond_expr("true == false"),
      @".binaryApp (.eq) (.lit (.bool true)) (.lit (.bool false))"
    );
}

#[test]
fn comparison_operators() {
    insta::assert_snapshot!(
      cond_expr("context.a < 1"),
      @r#".binaryApp (.less) (.getAttr (.var .context) "a") (.lit (.int 1))"#
    );
    insta::assert_snapshot!(
      cond_expr("context.a <= 1"),
      @r#".binaryApp (.lessEq) (.getAttr (.var .context) "a") (.lit (.int 1))"#
    );
    // `>` desugars to `!(a <= b)`.
    insta::assert_snapshot!(
      cond_expr("context.a > 1"),
      @r#".unaryApp (.not) (.binaryApp (.lessEq) (.getAttr (.var .context) "a") (.lit (.int 1)))"#
    );
    // `>=` desugars to `!(a < b)`.
    insta::assert_snapshot!(
      cond_expr("context.a >= 1"),
      @r#".unaryApp (.not) (.binaryApp (.less) (.getAttr (.var .context) "a") (.lit (.int 1)))"#
    );
    // `!=` desugars to `!(a == b)`.
    insta::assert_snapshot!(
      cond_expr("context.a != 1"),
      @r#".unaryApp (.not) (.binaryApp (.eq) (.getAttr (.var .context) "a") (.lit (.int 1)))"#
    );
}

#[test]
fn arithmetic_operators() {
    insta::assert_snapshot!(
      cond_expr("context.a + context.b - context.c * 2 == 0"),
      @r#".binaryApp (.eq) (.binaryApp (.sub) (.binaryApp (.add) (.getAttr (.var .context) "a") (.getAttr (.var .context) "b")) (.binaryApp (.mul) (.getAttr (.var .context) "c") (.lit (.int 2)))) (.lit (.int 0))"#
    );
}

#[test]
fn negation_operator() {
    insta::assert_snapshot!(
      cond_expr("-context.n == 0"),
      @r#".binaryApp (.eq) (.unaryApp (.neg) (.getAttr (.var .context) "n")) (.lit (.int 0))"#
    );
}

#[test]
fn logical_and_or() {
    insta::assert_snapshot!(
      cond_expr("context.a || context.b && context.c"),
      @r#".or (.getAttr (.var .context) "a") (.and (.getAttr (.var .context) "b") (.getAttr (.var .context) "c"))"#
    );
}

#[test]
fn if_then_else() {
    insta::assert_snapshot!(
      cond_expr("(if context.a then 1 else 2) == 0"),
      @r#".binaryApp (.eq) (.ite (.getAttr (.var .context) "a") (.lit (.int 1)) (.lit (.int 2))) (.lit (.int 0))"#
    );
}

#[test]
fn has_attr() {
    insta::assert_snapshot!(
      cond_expr("principal has name"),
      @r#".hasAttr (.var .principal) "name""#
    );
}

#[test]
fn nested_get_attr() {
    insta::assert_snapshot!(
      cond_expr("context.a.b.c == 0"),
      @r#".binaryApp (.eq) (.getAttr (.getAttr (.getAttr (.var .context) "a") "b") "c") (.lit (.int 0))"#
    );
}

#[test]
fn all_four_vars() {
    insta::assert_snapshot!(
      cond_expr("principal == action && resource == context"),
      @".and (.binaryApp (.eq) (.var .principal) (.var .action)) (.binaryApp (.eq) (.var .resource) (.var .context))"
    );
}

#[test]
fn set_operations() {
    insta::assert_snapshot!(
      cond_expr("context.s.contains(3)"),
      @r#".binaryApp (.contains) (.getAttr (.var .context) "s") (.lit (.int 3))"#
    );
    insta::assert_snapshot!(
      cond_expr("context.s.containsAll([1])"),
      @r#".binaryApp (.containsAll) (.getAttr (.var .context) "s") (.set [.lit (.int 1)])"#
    );
    insta::assert_snapshot!(
      cond_expr("context.s.containsAny([2])"),
      @r#".binaryApp (.containsAny) (.getAttr (.var .context) "s") (.set [.lit (.int 2)])"#
    );
    insta::assert_snapshot!(
      cond_expr("context.s.isEmpty()"),
      @r#".unaryApp (.isEmpty) (.getAttr (.var .context) "s")"#
    );
}

#[test]
fn tag_operations() {
    insta::assert_snapshot!(
      cond_expr(r#"principal.hasTag("t")"#),
      @r#".binaryApp (.hasTag) (.var .principal) (.lit (.string "t"))"#
    );
    insta::assert_snapshot!(
      cond_expr(r#"principal.getTag("t") == "x""#),
      @r#".binaryApp (.eq) (.binaryApp (.getTag) (.var .principal) (.lit (.string "t"))) (.lit (.string "x"))"#
    );
}

#[test]
fn entity_membership_and_equality() {
    insta::assert_snapshot!(
      cond_expr(r#"principal in Group::"g""#),
      @r#".binaryApp (.mem) (.var .principal) (.lit (.entityUID (⟨⟨"Group", []⟩, "g"⟩)))"#
    );
    insta::assert_snapshot!(
      cond_expr(r#"principal == User::"u""#),
      @r#".binaryApp (.eq) (.var .principal) (.lit (.entityUID (⟨⟨"User", []⟩, "u"⟩)))"#
    );
}

#[test]
fn empty_set_and_record_literals() {
    insta::assert_snapshot!(
      cond_expr("[] == context.a"),
      @r#".binaryApp (.eq) (.set []) (.getAttr (.var .context) "a")"#
    );
    insta::assert_snapshot!(
      cond_expr("{} == context.a"),
      @r#".binaryApp (.eq) (.record []) (.getAttr (.var .context) "a")"#
    );
}

#[test]
fn set_literal() {
    insta::assert_snapshot!(
      cond_expr("[1, 2, 3] == context.s"),
      @r#".binaryApp (.eq) (.set [.lit (.int 1), .lit (.int 2), .lit (.int 3)]) (.getAttr (.var .context) "s")"#
    );
}

#[test]
fn record_literal_is_sorted_by_attr() {
    // Records are backed by a `BTreeMap`, so attributes come out sorted.
    insta::assert_snapshot!(
      cond_expr("{b: 1, a: true, c: [false]}.a"),
      @r#".getAttr (.record [("a", .lit (.bool true)), ("b", .lit (.int 1)), ("c", .set [.lit (.bool false)])]) "a""#
    );
}

#[test]
fn record_attr_with_special_chars() {
    insta::assert_snapshot!(
      cond_expr(r#"{"a b": 1, "": 2}.x"#),
      @r#".getAttr (.record [("", .lit (.int 2)), ("a b", .lit (.int 1))]) "x""#
    );
}

#[test]
fn is_expression() {
    insta::assert_snapshot!(
      cond_expr("principal is User"),
      @r#".unaryApp (.is (⟨"User", []⟩)) (.var .principal)"#
    );
    insta::assert_snapshot!(
      cond_expr(r#"principal is User in Group::"g""#),
      @r#".and (.unaryApp (.is (⟨"User", []⟩)) (.var .principal)) (.binaryApp (.mem) (.var .principal) (.lit (.entityUID (⟨⟨"Group", []⟩, "g"⟩))))"#
    );
}

#[test]
fn like_pattern() {
    insta::assert_snapshot!(
      cond_expr(r#"context.name like "a*b""#),
      @r#".unaryApp (.like [.justChar 'a', .star, .justChar 'b']) (.getAttr (.var .context) "name")"#
    );
}

#[test]
fn like_pattern_escaped_star() {
    // `\*` is a literal `*`, not a wildcard.
    insta::assert_snapshot!(
      cond_expr(r#"context.name like "a\*b""#),
      @r#".unaryApp (.like [.justChar 'a', .justChar '*', .justChar 'b']) (.getAttr (.var .context) "name")"#
    );
}

#[test]
fn like_pattern_leading_trailing_wildcards() {
    insta::assert_snapshot!(
      cond_expr(r#"context.name like "*mid*""#),
      @r#".unaryApp (.like [.star, .justChar 'm', .justChar 'i', .justChar 'd', .star]) (.getAttr (.var .context) "name")"#
    );
}

// ----- extension functions -----

#[test]
fn ext_ip_functions() {
    insta::assert_snapshot!(
      cond_expr(r#"context.ip.isInRange(ip("10.0.0.0/8"))"#),
      @r#".call (.isInRange) [.getAttr (.var .context) "ip", .call (.ip) [.lit (.string "10.0.0.0/8")]]"#
    );
    insta::assert_snapshot!(
      cond_expr(r#"ip("127.0.0.1").isLoopback()"#),
      @r#".call (.isLoopback) [.call (.ip) [.lit (.string "127.0.0.1")]]"#
    );
    insta::assert_snapshot!(
      cond_expr(r#"ip("::1").isIpv6()"#),
      @r#".call (.isIpv6) [.call (.ip) [.lit (.string "::1")]]"#
    );
    insta::assert_snapshot!(
      cond_expr(r#"ip("1.2.3.4").isIpv4()"#),
      @r#".call (.isIpv4) [.call (.ip) [.lit (.string "1.2.3.4")]]"#
    );
    insta::assert_snapshot!(
      cond_expr(r#"ip("224.0.0.1").isMulticast()"#),
      @r#".call (.isMulticast) [.call (.ip) [.lit (.string "224.0.0.1")]]"#
    );
}

#[test]
fn ext_decimal_functions() {
    insta::assert_snapshot!(
      cond_expr(r#"context.d.lessThan(decimal("1.5"))"#),
      @r#".call (.lessThan) [.getAttr (.var .context) "d", .call (.decimal) [.lit (.string "1.5")]]"#
    );
    insta::assert_snapshot!(
      cond_expr(r#"context.d.greaterThanOrEqual(decimal("0.0"))"#),
      @r#".call (.greaterThanOrEqual) [.getAttr (.var .context) "d", .call (.decimal) [.lit (.string "0.0")]]"#
    );
}

#[test]
fn ext_datetime_functions() {
    insta::assert_snapshot!(
      cond_expr(r#"context.dt.offset(duration("1h"))"#),
      @r#".call (.offset) [.getAttr (.var .context) "dt", .call (.duration) [.lit (.string "1h")]]"#
    );
    insta::assert_snapshot!(
      cond_expr(r#"datetime("2020-01-01").toDate()"#),
      @r#".call (.toDate) [.call (.datetime) [.lit (.string "2020-01-01")]]"#
    );
    insta::assert_snapshot!(
      cond_expr(r#"duration("1h").toHours()"#),
      @r#".call (.toHours) [.call (.duration) [.lit (.string "1h")]]"#
    );
}

// ----- lexical edge cases -----

#[test]
fn string_escaping() {
    insta::assert_snapshot!(
      cond_expr(r#"context.x == "a\"b\n\t\r\\c""#),
      @r#".binaryApp (.eq) (.getAttr (.var .context) "x") (.lit (.string "a\"b\n\t\r\\c"))"#
    );
}

#[test]
fn string_control_char_escaping() {
    // `\u{7}` (BEL) is a non-printable control char and is emitted as ``.
    insta::assert_snapshot!(
      cond_expr(r#"context.x == "bell\u{7}""#),
      @r#".binaryApp (.eq) (.getAttr (.var .context) "x") (.lit (.string "bell\u0007"))"#
    );
}

#[test]
fn unicode_string_passthrough() {
    insta::assert_snapshot!(
      cond_expr(r#"context.x == "emoji😀""#),
      @r#".binaryApp (.eq) (.getAttr (.var .context) "x") (.lit (.string "emoji😀"))"#
    );
}

#[test]
fn int64_bounds() {
    insta::assert_snapshot!(
      cond_expr("context.x == 9223372036854775807"),
      @r#".binaryApp (.eq) (.getAttr (.var .context) "x") (.lit (.int 9223372036854775807))"#
    );
    insta::assert_snapshot!(
      cond_expr("context.x == -9223372036854775808"),
      @r#".binaryApp (.eq) (.getAttr (.var .context) "x") (.lit (.int (-9223372036854775808)))"#
    );
}

// ----- policy id / identifier handling -----
//
// `parse_policyset` always assigns ids `policy0`, `policy1`, ... in source
// order; `@id(...)` does not change them. Id sanitization/prefixing is instead
// covered by the unit tests in `src/emit.rs`, where custom ids are reachable.

#[test]
fn annotation_does_not_change_policy_id() {
    let out = lean(r#"@id("my_policy") permit(principal, action, resource);"#);
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .permit,
        .principalScope (.any),
        .actionScope .any,
        .resourceScope (.any),
        [] ⟩

    def policies : Policies := [policy0]
    "#);
}

// ----- property theorems -----

#[test]
fn always_allows_theorem_appended() {
    let out = lean_with_properties(
        "permit(principal, action, resource);",
        &[Property::AlwaysAllows],
    );
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .permit,
        .principalScope (.any),
        .actionScope .any,
        .resourceScope (.any),
        [] ⟩

    def policies : Policies := [policy0]

    theorem policies_always_allows :
        ∀ (req : Request) (es : Entities),
          (isAuthorized req es policies).decision = .allow := by
      sorry
    "#);
}

#[test]
fn always_allows_theorem_on_empty_policyset() {
    // The theorem statement is well-formed even when `policies` is empty.
    let out = lean_with_properties("", &[Property::AlwaysAllows]);
    insta::assert_snapshot!(out, @"
    import Cedar.Spec

    open Cedar.Spec

    def policies : Policies := []

    theorem policies_always_allows :
        ∀ (req : Request) (es : Entities),
          (isAuthorized req es policies).decision = .allow := by
      sorry
    ");
}

#[test]
fn equivalent_theorem_over_two_sets() {
    let out = lean_two_with_properties(
        "permit(principal, action, resource);",
        "forbid(principal, action, resource);\n\
         permit(principal, action, resource) when { context.x };",
        &[Property::Equivalent],
    );
    insta::assert_snapshot!(out, @r#"
    import Cedar.Spec

    open Cedar.Spec

    def policy0 : Policy :=
      ⟨ "policy0",
        .permit,
        .principalScope (.any),
        .actionScope .any,
        .resourceScope (.any),
        [] ⟩

    def policies : Policies := [policy0]

    def policyB0 : Policy :=
      ⟨ "policy0",
        .forbid,
        .principalScope (.any),
        .actionScope .any,
        .resourceScope (.any),
        [] ⟩

    def policyB1 : Policy :=
      ⟨ "policy1",
        .permit,
        .principalScope (.any),
        .actionScope .any,
        .resourceScope (.any),
        [⟨.when, .getAttr (.var .context) "x"⟩] ⟩

    def policiesB : Policies := [policyB0, policyB1]

    theorem policies_equivalent :
        ∀ (req : Request) (es : Entities),
          (isAuthorized req es policies).decision
            = (isAuthorized req es policiesB).decision := by
      sorry
    "#);
}

#[test]
fn binary_property_without_second_set_errors() {
    let err = cedar_lean_symc::policyset_to_lean_with_properties(
        "permit(principal, action, resource);",
        &[Property::Equivalent],
    )
    .unwrap_err();
    assert!(matches!(err, cedar_lean_symc::Error::Unsupported(_)));
}

#[test]
fn no_properties_matches_plain_emission() {
    assert_eq!(
        cedar_lean_symc::policyset_to_lean_with_properties(
            "permit(principal, action, resource);",
            &[],
        )
        .unwrap(),
        cedar_lean_symc::policyset_to_lean("permit(principal, action, resource);").unwrap(),
    );
}

#[test]
fn property_parse_round_trips() {
    assert_eq!(Property::parse("always-allows"), Some(Property::AlwaysAllows));
    assert_eq!(Property::parse("equivalent"), Some(Property::Equivalent));
    assert_eq!(Property::parse("nonsense"), None);
}

// ----- error handling -----

#[test]
fn parse_error_is_reported() {
    let err = cedar_lean_symc::policyset_to_lean("this is not a policy").unwrap_err();
    assert!(matches!(err, cedar_lean_symc::Error::Parse(_)));
}
