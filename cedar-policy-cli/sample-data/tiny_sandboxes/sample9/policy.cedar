permit (
  principal,
  action == Action::"view",
  resource is Photo
)
when { principal == resource.owner };
