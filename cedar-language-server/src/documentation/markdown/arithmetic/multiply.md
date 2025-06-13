# * *(numeric multiplication)*

## Usage:
```cedar
<long> * <long>
```

Binary operator that multiplies two long integer operands and returns their product.
Both operands must be long integers or evaluation and validation will result in an
error. Multiplication operations that result in overflow will fail at evaluation time,
but will pass validation.

Note: Cedar does not provide an operator for arithmetic division.
