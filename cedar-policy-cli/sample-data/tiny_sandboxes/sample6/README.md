## sample 6

### Authorize

 Can User::alice  view ScreenTime::activity

 Decision: Deny

 Reason: alice's age is not greater than 18

```
cargo run  authorize \
    --policies policy.cedar \
    --entities entity.json \
    --request-json request.json
```


### Validation

Is policy.cedar valid based on the schema schema.cedarschema.json

```
cargo run  validate \
    --policies policy.cedar \
    --schema schema.cedarschema.json
```

### Evaluate

Evaluate a Cedar expression

```
cargo run  evaluate  \
    --request-json request.json \
    --entities entity.json \
     "principal.account.age >= 17"
```