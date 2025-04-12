permit (
  principal == User::"alice",
  action == Action::"view",
  resource
)
when { context.token.is_secure };
