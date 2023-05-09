permit (
  principal == User::"bob",
  action in [Action::"view", Action::"edit"],
  resource in Album::"jane_vacation"
);
