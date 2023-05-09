permit(
  principal == User::"alice",
  action == Action::"view",
  resource == Photo::"VacationPhoto94.jpg"
);

permit(
  principal in Group::"jane_friends",
  action == Action::"view",
  resource == Photo::"VacationPhoto94.jpg"
);

permit(
  principal == User::"alice",
  action == Action::"view",
  resource in Album::"jane_vacation"
);

permit(
  principal == User::"alice",
  action in [Action::"view", Action::"edit", Action::"delete"],
  resource in Album::"jane_vacation"
);

// Alice has "admin" permissions on the album
permit(
  principal == User::"alice",
  action in Action::"admin",
  resource in Album::"jane_vacation"
);

// Solution #1: Using multiple policies
permit(
  principal == User::"alice",
  action in Action::"admin",
  resource in Album::"jane_vacation"
);

permit(
  principal == User::"alice",
  action == Action::"edit",
  resource in Album::"jane_vacation"
);

// Solution #2: Using conditions in a single policy.
// Note - depending on the implementation of a backend datastore,
// shifting rules into the conditions may result in changes to
// performance or search/lookup capabilities, as the condition clauses
// can be less amenable to indexing.
permit(
  principal == User::"alice",
  action,
  resource in Album::"jane_vacation"
)
when {
  action in PhotoflashRole::"viewer" ||
  action == Action::"edit"
};

permit(
  principal,
  action == Action::"view",
  resource in Album::"jane_vacation"
);

permit(
  principal,
  action == Action::"view",
  resource in Album::"jane_vacation"
);

permit(
  principal == User::"alice",
  action in [Action::"listAlbums", Action::"listPhotos", Action::"view"],
  resource in Account::"jane"
);

permit(
  principal == User::"alice",
  action,
  resource in Account::"jane"
);

permit (
    principal,
    action in
        [Action::"UpdateList",
         Action::"CreateTask",
         Action::"UpdateTask",
         Action::"DeleteTask"],
    resource
)
when
{
    principal in resource.editors
};

// Policy 4: Admins can perform any action on any resource
