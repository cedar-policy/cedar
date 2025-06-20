# is *(entity type test)*

## Usage:
```cedar
<entity> is <entity-type>
<entity> is <entity-type> in <entity>
<entity> is <entity-type> in set(<entity>)
```

Boolean operator that tests whether an entity has a specific type. It evaluates to true
if the left operand is an entity of the specified type, and false if it's an entity of
a different type. Both evaluation and validation will result in an error if the left
operand is not an entity or if the right operand is not a known entity type from the schema.
