// Scenario 3B: Alice can perform specified actions on any resource in Jane's account
permit (
  principal == User::"alice",
  action in [Action::"listAlbums", Action::"listPhotos", Action::"view"],
  resource in Account::"jane"
);
