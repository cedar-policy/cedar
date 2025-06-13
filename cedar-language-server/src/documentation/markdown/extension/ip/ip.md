# ip() *(parse string and convert to ipaddr)*

## Usage:
```cedar
ip(<string>)
```

Function that parses the string and attempts to convert it to type ipaddr.
If the string doesn't represent a valid IP address or range, then the ip()
expression generates an error when evaluated.
