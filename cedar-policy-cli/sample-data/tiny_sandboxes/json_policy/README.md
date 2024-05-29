# JSON formatted policies

The Cedar policy CLI also supports using reading policies in the JSON policy format.
See the [Cedar language reference](https://docs.cedarpolicy.com/policies/json-format.html) for a detailed description of this format.

In general, you can select between the human-readable and JSON format using `--policy-format`.
For example, we can check if a JSON format policy parses:

```bash
cedar --check-parse --policy-format json --policies policy.cedar.json
```

We can also use a JSON format policy in an authorization request

```bash
cedar authorize --policy-format json\
    --policies policy.cedar.json\
    --entities entity.json\
    --principal 'User::"bob"'\
    --action 'Action::"view"'\
    --resource 'Photo::"VacationPhoto94.jpg"'`
```
