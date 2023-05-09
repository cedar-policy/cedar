## sample 5

### Authorize 

 Can User::bob  view Photo:VacationPhoto94.jpg

 Decision: Allow

```
cargo run  authorize \
    --policies policy.txt \
    --entities entity.json \
    --request-json request.json
```


### Validation

Is `policy.txt` valid based on the schema `schema.json`

```
cargo run  validate \
    --policies policy.txt \
    --schema schema.json
```

### Evaluate:

Evaluate a Cedar expression

```
cargo run  evaluate  \
    --request-json request.json \
    --entities entity.json \
     "principal.addr.isLoopback()"
```