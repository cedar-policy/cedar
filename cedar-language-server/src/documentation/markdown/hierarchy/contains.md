# contains() *(single element set membership test)*

## Usage:
```cedar
<set>.contains(<value>)
```

Function that evaluates to true if the operand is a member of the receiver
on the left side of the function. The receiver must be of type Set or
evaluation produces an error. To be accepted by the policy validator,
contains must be called on a receiver that is a Set of some type T,
with an argument that also has type T.
