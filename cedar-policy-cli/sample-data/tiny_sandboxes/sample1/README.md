
## sample 1

### Authorization

 Can User::alice view Photo:VacationPhoto94.jpg

 Decision: Allow

```
cargo run  authorize \
    --policies policy.cedar \
    --entities entity.json \
    --request-json request.json
```
or, provide the principal, action, and resources separately
```
cargo run  authorize \
    --policies policy.cedar \
    --entities entity.json \
    --principal 'User::"alice"' \
    --action 'Action::"view"' \
    --resource 'Photo::"VacationPhoto94.jpg"'
```

### Validation:

Is policy.cedar valid based on the schema schema.cedarschema.json

```
cargo run  validate \
    --policies policy.cedar \
    --schema schema.cedarschema.json
```


### Evaluate:
Evaluate a Cedar expression

```
cargo run  evaluate  \
    --request-json request.json \
    --entities entity.json \
    "principal in UserGroup::\"jane_friends\""
```
```
cargo run  evaluate  \
    --principal 'User::"alice"' \
    --action 'Action::"view"' \
    --resource 'Photo::"VacationPhoto94.jpg"' \
    --entities entity.json \
    "principal in UserGroup::\"jane_friends\""
```
```
cargo run  evaluate  \
    --request-json request.json \
    "[\"a\",true,10].contains(10)"
```