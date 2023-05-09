## sample 4

### Authorize

 Can User::bob view Photo:VacationPhoto94.jpg

 Decision: Allow

 Reason: request action is in the allowed action list
```
cargo run  authorize \
    --policies policy.txt \
    --entities entity.json \
    --request-json request.json
```




# Validation

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
    "resource.owner == User::\"bob\""
```