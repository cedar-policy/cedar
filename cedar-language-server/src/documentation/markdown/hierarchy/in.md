# in *(hierarchy membership)*

## Usage:
```cedar
<entity> in <entity>
```

Binary operator that evaluates to true if the entity in the left operand is a
descendant in the hierarchy under the entity in the right operand. Evaluation
(and validation) produces an error if the first (lhs) operand of in is not an
entity, or the (rhs) is not an entity or a set thereof.
