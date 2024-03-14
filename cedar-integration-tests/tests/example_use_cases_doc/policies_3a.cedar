// Scenario 3A: Any Principal can view jane's "Vacation" album
permit (
  principal,
  action == Action::"view",
  resource in Album::"jane_vacation"
);
