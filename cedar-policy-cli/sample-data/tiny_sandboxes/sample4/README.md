## sample 4

### Authorize

 Can User::bob view Photo:VacationPhoto94.jpg

 Decision: Allow

 Reason: request action is in the allowed action list
```
cargo run  authorize \
    --policies policy.cedar \
    --entities entity.json \
    --request-json request.json
```




# Validation

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
    "resource.owner == User::\"bob\""
```