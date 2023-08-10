// Multiple permit and multiple forbid policies, which could apply in various
// combinations
// Alice's friends can view all of her photos
permit (
  principal in UserGroup::"alice_friends",
  action == Action::"view",
  resource in Account::"alice"
);

// Anyone in the Sales department can view Alice's vacation photos
permit (
  principal,
  action,
  resource in Album::"alice_vacation"
)
when { principal.department == "Sales" };

// anything marked private can only be viewed by the account owner
forbid (principal, action, resource)
when { resource.private }
unless { resource has account && resource.account.owner == principal };

// deny all requests that have context.authenticated set to false
forbid (principal, action, resource)
when { !context.authenticated };
