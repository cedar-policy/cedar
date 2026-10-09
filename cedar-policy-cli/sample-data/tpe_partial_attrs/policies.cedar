@id("has-nickname")
permit (
  principal,
  action == Action::"View",
  resource
)
when { principal has nickname };
