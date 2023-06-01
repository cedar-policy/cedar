To run the test in this file, do the following from the parent directory:
```
cargo bolero test --engine libfuzzer check_rbac
```

Note that this test is not really doing the RBAC test, since the invocation
of the definitional engine is commented out. Adding back in would be the
next step for comparison against cargo fuzz.

To run the test using Kani rather than libfuzzer, do:
```
cargo bolero test --engine kani check_rbac
```

This doesn't actually work at present, I don't think. You'll see lots of diagnostics. I had to add annotation `#[cfg_attr(kani, kani::unwind(5))]` on the test so that it didn't get stuck in the same spot forever.
