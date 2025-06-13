# like *(string matching with wildcard)*

## Usage:
```cedar
<string> like <string possibly with wildcards>
```

Binary operator that evaluates to true if the string in the left operand matches the pattern string
in the right operand. The pattern string can include one or more asterisks (*) as wildcard characters
that match 0 or more of any character.

To match a literal asterisk character, use the escaped \* sequence in the pattern string.
