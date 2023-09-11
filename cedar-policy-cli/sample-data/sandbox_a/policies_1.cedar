// Everyone in the group UserGroup::"jane_friends" can view this specific photo
@id("jane's friends view-permission policy")
permit (
  principal in UserGroup::"jane_friends",
  action == Action::"view",
  resource == Photo::"VacationPhoto94.jpg"
);

// but Tim is disallowed from viewing the photo
@id("disallow tim policy")
forbid (
  principal == User::"tim",
  action,
  resource == Photo::"VacationPhoto94.jpg"
);
