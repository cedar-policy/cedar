permit (
  principal,
  action == Action::"view",
  resource
)
when { principal == resource.owner };
