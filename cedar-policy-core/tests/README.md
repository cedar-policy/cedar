To run the test in this file, do the following from the parent directory:
```
cargo bolero test --engine libfuzzer check_rbac
```

Note that this test is not really doing the RBAC test, since the invocation
of the definitional engine is commented out. Adding back in would be the
next step for comparison against cargo fuzz.
