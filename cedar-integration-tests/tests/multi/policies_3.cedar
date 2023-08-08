// This test has a slightly more complicated forbid policy partially overriding
// a permit policy
// Alice's friends can view all of her photos
permit (
  principal in UserGroup::"alice_friends",
  action == Action::"view",
  resource in Account::"alice"
);

// but, as a general rule, anything marked private can only be viewed by the
// account owner
forbid (principal, action, resource)
when { resource.private }
unless { resource has account && resource.account.owner == principal };
