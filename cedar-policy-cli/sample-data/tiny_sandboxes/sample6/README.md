## sample 6

### Authorize

 Can User::alice  view ScreenTime::activity

 Decision: Deny

 Reason: alice's age is not greater than 18

```
cargo run  authorize \
    --policies policy.txt \
    --entities entity.json \
    --request-json request.json
```


### Validation

Is policy.txt valid based on the schema schema.json

```
cargo run  validate \
    --policies policy.txt \
    --schema schema.json
```

### Evaluate

Evaluate a Cedar expression

```
cargo run  evaluate  \
    --request-json request.json \
    --entities entity.json \
     "principal.account.age >= 17"
```