# JSON formatted policies

The Cedar policy CLI also supports using policies in the JSON policy format.
See the [Cedar language reference](https://docs.cedarpolicy.com/policies/json-format.html) for a detailed description of this format.

In general, you can select between the Cedar and JSON formats using `--policy-format`.
For example, we can use a JSON format policy in an authorization request

```bash
cedar authorize --policy-format json \
    --policies policy.cedar.json \
    --entities entity.json \
    --principal 'User::"bob"' \
    --action 'Action::"view"' \
    --resource 'Photo::"VacationPhoto94.jpg"'`
```
