# has *(presence of attribute test)*

## Usage:
```cedar
<entity or record> has <attribute>
<entity or record> has <accessor.path>
```

Boolean operator that tests whether an entity or record has a specified attribute or
attribute path defined. It evaluates to true if the attribute exists, false if it
doesn't. Both evaluation and validation will result in an error if the left operand
is not an entity or record type.
