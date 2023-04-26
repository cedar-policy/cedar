// Alice's friends can view all of her photos
@id("alice's friends view policy")
permit (
  principal in UserGroup::"alice_friends",
  action == Action::"view",
  resource in Account::"alice"
);

// but, as a general rule, anything marked private can only be viewed by the
// account owner
@id("privacy rule")
forbid (principal, action, resource)
when { resource.private }
unless { resource.account.owner == principal };
