// Scenario 3C: Alice can perform any action on resources in jane's "Vacation" album
permit (
  principal == User::"alice",
  action,
  resource in Album::"jane_vacation"
);
