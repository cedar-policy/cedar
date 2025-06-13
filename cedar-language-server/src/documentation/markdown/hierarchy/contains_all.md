# containsAll() *(all element set membership test)*

## Usage:
```cedar
<set>.containsAll(<set>)
```

Function that evaluates to true if every member of the operand set is a member
of the receiver set. Both the receiver and the operand must be of type set or
evaluation results in an error. To be accepted by the validator, the receiver
and argument to containsAll must be homogeneous sets of the same type.
