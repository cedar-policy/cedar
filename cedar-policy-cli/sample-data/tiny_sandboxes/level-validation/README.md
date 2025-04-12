# Policy Level Validation

By passing the `--level` flag to the `validate` command, you can
additionally validate that a policy does not contain any operations that need to
access entity data above the specified level.

## Level Zero Policy

Level zero policies can perform basic operations on entity data without
accessing their attributes. They can compare entity identifiers (e.g.,
`principal == User::"alice"`) and check entity types (e.g., `principal is User`).
Any access to an entity's attributes is not allowed. Other operations that don't
deal with entities are not limited at all even at level zero - for example, we
can access any attributes in the context such as `context.token.is_secure`. This
may look the same as an access to entity attributes, but the context is a record
that is part of the authorization request and not data for an entity.

Try this out by running

```bash
cargo run validate \
    --level 0 \
    --policies policy-level-0.cedar \
    --schema schema.cedarschema
```

## Level One Policy

Level one policies can do everything level zero policies can, plus access
attributes of entities directly referenced in the request (principal, action,
resource, and any entities in the context). For example, `principal.jobLevel` in
`policy-level-1.cedar` is allowed.

Try this out by running

```bash
cargo run validate \
    --level 1 \
    --policies policy-level-1.cedar \
    --schema schema.cedarschema
```

We can also _try_ to validate this policy at level zero, but we'll get an error
pointing out where we've accessed an attribute

```
  × policy set validation failed
  ╰─▶ for policy `policy0`, the maximum allowed level 0 is violated. Actual level is 1
   ╭─[2:3]
 1 │ permit(principal, action, resource) when {
 2 │   principal.jobLevel > 5
   ·   ──────────────────
 3 │ };
   ╰────
  help: Consider increasing the level
```

## Level Two Policy

More complicated policies might require higher levels.  Level two policies can
do everything level one policies can, plus access entity data for entities
referenced by level one entities.  For example, in `policy-level-2.cedar`, we
want to access an attribute and then ask if it is in a group (`principal.manager
in Group::"admins"`). The `in` operation also requires access to entity data, so
this is a level two operation. We need the entity data for `principal` to get its
attribute, and then we need the entity data for that attribute to decide if it
is in the group.

Try this out by running

```bash
cargo run validate \
    --level 2 \
    --policies policy-level-2.cedar \
    --schema schema.cedarschema
```

Again, we can try to validate this at level one or zero, but this would only
return a level validation error.
