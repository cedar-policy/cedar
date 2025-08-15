# isInRange() *(test for inclusion in IP address range)*

## Usage:
```cedar
<ipaddr>.isInRange(<ipaddr>)
```

Function that evaluates to true if the receiver is an IP address or a range
of addresses that fall completely within the range specified by the operands.
This function evaluates (and validates) to an error if either operand does
not have ipaddr type.
