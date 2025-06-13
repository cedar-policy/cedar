# != *(inequality)*

## Usage:
```cedar
<value> != <value>
```

Binary operator that compares two operands of any type and evaluates to true if the
operands have different values or are of different types. You can use != only in when
and unless clauses. As with the == operator, the validator only accepts policies that
use != on two expressions of (possibly differing) entity type, or the same non-entity type.
