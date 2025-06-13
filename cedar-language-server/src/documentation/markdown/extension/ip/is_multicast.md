# isMulticast() *(test for multicast address)*

## Usage:
```cedar
<ipaddr>.isMulticast()
```

Function that evaluates to true if the receiver is a multicast address
for its IP version type; evaluates (and validates) to an error if receiver
does not have ipaddr type. This function takes no operand.

## Examples:
In the examples that follow, those labeled //error both evaluate and validate to an error.
```cedar
ip("127.0.0.1").isMulticast()  //false
ip("ff00::2").isMulticast()    //true
context.foo.isMulticast()      //error if `context.foo` is not an `ipaddr`
