# - *(numeric subtraction or negation)*

## Usage:
```cedar
<long> - <long>    // binary subtraction
-<long>           // unary negation
```

Operator that can function as either binary subtraction or unary negation. As a binary
operator, it subtracts the second long integer from the first. As a unary operator, it
negates a single long integer. Both forms require long integer operands or evaluation
and validation will result in an error. Subtraction operations that result in overflow
(or underflow) will fail at evaluation time, but will pass validation.
