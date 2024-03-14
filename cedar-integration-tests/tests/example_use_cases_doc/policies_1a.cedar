// Scenario 1A: One Principal, One Action, One Resource
permit (
  principal == User::"alice",
  action == Action::"view",
  resource == Photo::"VacationPhoto94.jpg"
);
