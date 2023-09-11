// Scenario 2C: Alice can view, edit, or comment on any photo in Jane's "Vacation" album
permit (
  principal == User::"alice",
  action in [Action::"view", Action::"edit", Action::"comment"],
  resource in Album::"jane_vacation"
);
