## sample 9

This sample demonstrates using `is` operation to write a policy specific to a
particular entity type.

We want to write a policy allowing the owner of any photo to view that photo.
As a first attempt we could write a policy testing `principal == resource.owner`.

```cedar
permit (
  principal,
  action == Action::"view",
  resource
)
when { principal == resource.owner };
```

This doesn't quite work because because `Action::"view"` applies to both `Photo`
and `ScreenTime` entities, but only `Photo` entities have an owner. Policy
validation detects this issue.

```console
sample9$ cedar validate --policies policy_bad.cedar --schema schema.cedarschema
Validation Results:
validation error on policy `policy0` at offset 83-97: attribute `owner` for entity type ScreenTime not found
```

We can use the `is` operator to ensure that the policy can only apply to `Photo` entities.

```cedar
permit (
  principal,
  action == Action::"view",
  resource is Photo
)
when { principal == resource.owner };
```

```console
sample9$ cedar validate --policies policy.cedar --schema schema.cedarschema
Validation Passed
```

The policy using `is` will authorize owners to view their photos. We use the
file `request.json` to ask if `User::"Bob"` can view `Photo::"VacationPhoto94.jpg"`.

```console
sample9$ cargo run authorize --policies policy.cedar --entities entity.json --request-json request.json
ALLOW
```

This request is allowed because the resource is a photo and `Bob` is the owner of
that photo.
