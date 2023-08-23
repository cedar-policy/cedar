// Scenario 2A: Anyone in a given group can view a given photo
permit (
  principal in UserGroup::"jane_friends",
  action == Action::"view",
  resource == Photo::"VacationPhoto94.jpg"
);
