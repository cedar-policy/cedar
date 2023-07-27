## sample 2

### Authorize

 Can `User::bob` view `Photo:VacationPhoto94.jpg`

 Decision: Allow

 Reason: Bob is the owner of the resource

```
cargo run  authorize \
    --policies policy.cedar \
    --entities entity.json \
    --request-json request.json
```


### Validation:

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
    "resource.owner"
```
```
cargo run  evaluate  \
    --principal 'User::"alice"' \
    --action 'Action::"view"' \
    --resource 'Photo::"VacationPhoto94.jpg"' \
    --entities entity.json \
    "resource.owner"
```
```
cargo run  evaluate  \
    --request-json request.json \
    "if 10 > 5 then \"good\" else \"bad\""
```