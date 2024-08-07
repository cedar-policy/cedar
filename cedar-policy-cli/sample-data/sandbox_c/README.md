# Sandbox C

This sandbox builds on `sandbox_a` and `sandbox_b` to demonstrate the use of policy templates.

## Entity store

Our store has three `User`s:

- `alice`
- `bob` (with the attribute `department` set to `research`)
- `jane`

One `Album`:

- `jane`

And two `Photo`s, both in the `Album::"jane"`:

- `VacationPhoto94.jpg`

Let's see if `alice` can view `VacationPhoto94.jpg`:

```shell
cargo run authorize \
    --principal 'User::"alice"' \
    --action 'Action::"view"' \
    --resource 'Photo::"VacationPhoto94.jpg"' \
    --policies policies.cedar \
    --entities entities.json
```

We should get `DENY`, as there is no policy that allows this.

## Linking a template

Our policy store contains a policy template that we can use to grant `alice` access:

```cedar
@id("AccessVacation")
permit(
    principal in ?principal,
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
```

This looks like a regular policy, but it has `?principal` instead of a concrete Entity UID on the left hand side of `==`.
`?principal` is a *Slot*, which can be filled in later.
Let's link this template to give `alice` access:

```shell
cargo run link \
    --policies policies.cedar \
    --template-linked ./linked \
    --template-id "AccessVacation" \
    --new-id "AliceAccess" \
    --arguments '{ "?principal" : "User::\"alice\"" }'
```

This will fill the Slot `?principal` with `User::\"alice\"` in the template with ID "AccessVacation".
This template-linked policiy will have the ID "AliceAccess".
It will save this template-linked policy in the file `./linked`.
We can re-run the request with our linked file:

```shell
cargo run authorize \
    --principal 'User::"alice"' \
    --action 'Action::"view"' \
    --resource 'Photo::"VacationPhoto94.jpg"' \
    --policies policies.cedar \
    --entities entities.json \
    --template-linked ./linked
```

And we should now get `ALLOW`.

Let's also give `bob` access:

```shell
cargo run link \
    --policies policies.cedar \
    --template-linked ./linked \
    --template-id "AccessVacation" \
    --new-id "BobAccess" \
    --arguments '{ "?principal" : "User::\"bob\"" }'
```

And now both `bob` and `alice` have access.

## Updating a template

Templates can be updated, and past policies linked to that template will reflect the new template.
Let's take our previous template, and update it to also have an ABAC rule.
Edit the template to add a when clause so it looks like the following:

```cedar
@id("AccessVacation")
permit(
    principal in ?principal,
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
) when {
    principal has department && principal.department == "research"
};
```

Now we can re-run our requests:

```shell
cargo run authorize \
    --principal 'User::"bob"' \
    --action 'Action::"view"' \
    --resource 'Photo::"VacationPhoto94.jpg"' \
    --policies policies_edited.cedar \
    --entities entities.json \
    --template-linked ./linked
```

Bob should still have access, as his entity has the attribute set.

```shell
cargo run authorize \
    --principal 'User::"alice"' \
    --action 'Action::"view"' \
    --resource 'Photo::"VacationPhoto94.jpg"' \
    --policies policies_edited.cedar \
    --entities entities.json \
    --template-linked ./linked
```

But Alice should now be denied.

## What's next?

Try even more authorization requests. Change the data in the policies or entities
files and see how Cedar responds. Maybe even write your own entities and
policies.
