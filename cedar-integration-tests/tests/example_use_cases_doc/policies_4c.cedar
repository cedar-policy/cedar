// Scenario 4C: Alice is allowed to perform any action that is `readOnly` and
// which applies to Photos or Albums. Note that this policy uses attributes on
// `action` which is not permitted by the validator.
permit (
  principal == User::"alice",
  action,
  resource
)
when { action.readOnly && ["Photo", "Album"].contains(action.appliesTo) };
