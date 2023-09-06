permit (
  principal == User::"bob",
  action == Action::"view",
  resource
)
when { action == Action::"view" };
