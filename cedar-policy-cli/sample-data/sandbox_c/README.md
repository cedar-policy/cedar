# sandbox_c

This sandbox demonstrates the use of policy templates.

## Entity Store

Our store has 3 `User`s:
- `alice`
- `bob` (with the attribute `department` set to `research`)
- `jane`

1 `Album`:
- `jane`

2 `Photo`s, both in the `Album::"jane"`:
- `VacationPhoto94.jpg`

Let's see if `alice` can view `VacationPhoto94.jpg`:
```
cargo run authorize \
	--principal 'User::"alice"' \
	--action 'Action::"view"' \
	--resource 'Photo::"VacationPhoto94.jpg"' \
	--policies policies.cedar \
	--entities entities.json
```

We should get `DENY`, as there is no policy that allows this.

## Instantiating a template
Our policy store contains a Policy Template that we can use to grant `alice` access:
```
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
```
cargo run link \
	--policies-file policies.cedar \
	--template-linked-file ./linked \
	--template-id "AccessVacation" \
	--new-id "AliceAccess" \
	--arguments '{ "?principal" : "User::\"alice\"" }'
```

This will fill the Slot `?principal` with `User::\"alice\"` in the template with ID "AccessVacation".
This template-linked policiy will have the ID "AliceAccess".
It will save this template-linked policy in the file `./linked`.
We can re-run the request with our linked file:
```
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
```
cargo run link \
	--policies-file policies.cedar \
	--template-linked-file ./linked \
	--template-id "AccessVacation" \
	--new-id "BobAccess" \
	--arguments '{ "?principal" : "User::\"bob\"" }'
```

And now both `bob` and `alice` have access.


## Updating Templates

Templates can be updated, and past policies linked to that template will reflect the new template.
Let's take our previous template, and update it to also have an ABAC rule.
Edit the template to add a when clause so it looks like the following:
```
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


```
cargo run authorize \
	--principal 'User::"bob"' \
	--action 'Action::"view"' \
	--resource 'Photo::"VacationPhoto94.jpg"' \
	--policies policies.cedar \
	--entities entities.json \
	--template-linked ./linked
```
Bob should still have access, as his entity has the attribute set.

```
cargo run authorize \
	--principal 'User::"alice"' \
	--action 'Action::"view"' \
	--resource 'Photo::"VacationPhoto94.jpg"' \
	--policies policies.cedar \
	--entities entities.json \
	--template-linked ./linked
```
But Alice should now be denied.
