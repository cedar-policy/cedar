// Scenario 2B: Alice can view any photo in Jane's "Vacation" album
permit (
  principal == User::"alice",
  action == Action::"view",
  resource in Album::"jane_vacation"
);
