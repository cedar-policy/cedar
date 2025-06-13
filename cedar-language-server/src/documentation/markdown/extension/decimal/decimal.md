# decimal() *(parse string and convert to decimal)*

## Usage:
```cedar
decimal(<string>)
```

Function that parses the string and tries to convert it to type decimal. If the string doesn't represent
a valid decimal value, it generates an error.

To be interpreted successfully as a decimal value, the string must contain a decimal separator (.)
and at least one digit before and at least one digit after the separator. There can be no more than
4 digits after the separator. The value must be within the valid range of the decimal type, from
-922337203685477.5808 to 922337203685477.5807.
