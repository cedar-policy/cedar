permit (
  principal == User::"bob",
  action in [Action::"view", Action::"edit"],
  resource
)
when { resource.owner == principal };
