
## sample 3
### Authorize


 Can User::bob view Photo:VacationPhoto94.jpg

 Decision: Deny

 Reason: Bob can access resources in Album::"jane_vacation",
 but Photo::"VacationPhoto94.jpg" does not belong to the album


```
cargo run  authorize \
    --policies policy.txt \
    --entities entity.json \
    --request-json request.json
```

### Validation:

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
    "if 10 > 5 then \"good\" else \"bad\""
```