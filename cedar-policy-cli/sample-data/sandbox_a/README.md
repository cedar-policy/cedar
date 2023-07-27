## sandbox_a

This sandbox contains some simple policies and entities for the example
Photoflash application described in the Cedar language overview-and-spec
document.

None of the entities in this sandbox have attributes, so all the policies
are purely RBAC policies: they are based on the entity hierarchy itself.

### policies_1.cedar

With this policy set, everyone in `UserGroup::"jane_friends"` can view a
specific photo (`Photo::"VacationPhoto94.jpg"`), but one specific user
(`User::"tim"`) is explicitly forbidden from any action on that photo via a
`forbid` policy which overrides the `permit` policy.

All operations on any other resources are implicitly forbidden, because
Cedar's default is always to deny access unless some policy specifically
allows it.

Try the following authorization request:
```
cargo run authorize \
    --principal 'User::"alice"' \
    --action 'Action::"view"' \
    --resource 'Photo::"VacationPhoto94.jpg"' \
    --policies policies_1.cedar \
    --entities entities.json
```
This should be allowed, because `alice` is in the group `jane_friends`.

On the other hand, if you replace `User::"alice"` with `User::"tim"`, this request
should be denied, due to the `forbid` policy.

If you try `User::"bob"`, the request should still be denied, but this time it's
because `bob` is not in the group `jane_friends`.

### policies_2.cedar

This policy set demonstrates how one policy can apply to a explicit list of
actions on a resource or group of resources.

Try the following authorization request:
```
cargo run authorize \
    --principal 'User::"alice"' \
    --action 'Action::"view"' \
    --resource 'Photo::"VacationPhoto94.jpg"' \
    --policies policies_2.cedar \
    --entities entities.json
```
By adjusting the `--action`, you should see that `alice` is allowed to `view`,
`edit`, or `delete` the photo.  (Or, any other resources `in` the
`jane_vacation` album.)  However, she's not allowed to `comment`, because
`Action::"comment"` isn't explicitly listed in the policy.

With this policy set, you should also see that `bob` is allowed to `view`
resources in the `jane_vacation` album, but unlike `alice`, `bob` can only
`view`, he cannot `edit` or `delete`.

### policies_3.cedar

This policy set allows public (`view`) access to the resources in the
`jane_vacation` album, and also to take the `listPhotos` action on the album
itself.

Try this request, with any `--principal`, to see that `view` access is allowed to
everyone:
```
cargo run authorize \
    --principal 'User::"alice"' \
    --action 'Action::"view"' \
    --resource 'Photo::"VacationPhoto94.jpg"' \
    --policies policies_3.cedar \
    --entities entities.json
```

And, see that anyone is also allowed the `listPhotos` action on the album
itself:
```
cargo run authorize \
    --principal 'User::"tim"' \
    --action 'Action::"listPhotos"' \
    --resource 'Album::"jane_vacation"' \
    --policies policies_3.cedar \
    --entities entities.json
```

### Policy validation

You can validate if a policy conforms with the schema. Try the following:
```
cargo run validate \
  --policies policies_1.cedar \
  --schema schema.cedarschema.json
```
Validation should pass. If you look at the `schema.cedarschema.json` file, you will see it has two sections: the `entityTypes` section, first, and the `actions` section. The first section describes the legal entity types, including member relationships. For example, we see that entities of type `Photo` can be members of entities of type `Album` or `Account` -- membership is tantamount to a parent-child relationship in the entity hierarchy.

The second section of the schema defines all of the legal actions (each of which has entity type `Action`, not shown), and the principal and resource types of entities that are allowed in authorization requests for that action. We can see that there are four legal actions, and each one has the same assumptions: only `User` entities can be passed in as principals in requests, and either `Photo`, `Album`, or `Video` entities can be passed in as resources.

Now try validation on `policies_1_bad.cedar`. You will see that validation fails, indicating that entity type `UsrGroup` is unrecognized; this is because it is not listed in the `entityTypes` section (it was meant to be `UserGroup` but there was a typo).

### Evaluation

You can evaluate a Cedar expression using the `evaluate` command. Try the
following:
```
cargo run evaluate \
    --principal 'User::"alice"' \
    --action 'Action::"listPhotos"' \
    --resource 'Album::"jane_vacation"' \
    --entities entities.json \
   "resource in Account::\"jane\""
```
Now, continue on to `sandbox_b`, where we'll consider ABAC policies, that
examine the attributes of various entities.
