# containsAny() *(any element set membership test)*

## Usage:
```cedar
<set>.containsAny(<set>)
```

Function that evaluates to true if any one or more members of the operand
set is a member of the receiver set. Both the receiver and the operand must
be of type set or evaluation produces an error. To be accepted by the policy
validator, calls to containsAny must be on homogeneous sets of the same type.
