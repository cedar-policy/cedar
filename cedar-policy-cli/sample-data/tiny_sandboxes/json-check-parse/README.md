# JSON formatted policies

The Cedar policy CLI also supports using policies in the JSON policy format.
See the [Cedar language reference](https://docs.cedarpolicy.com/policies/json-format.html) for a detailed description of this format.

In general, you can select between the human-readable and JSON format using `--policy-format`.
For example, we can check if a JSON format policy parses:

```bash
cedar check-parse --policy-format json \
    --policies policy.cedar.json
```
