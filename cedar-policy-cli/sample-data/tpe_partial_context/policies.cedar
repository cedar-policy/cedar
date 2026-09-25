@id("has-mfa")
permit (
  principal,
  action == Action::"read",
  resource
)
when { context has mfa };
