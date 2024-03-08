// Anyone in the Sales department can perform any action on Alice's vacation photos
permit (
  principal,
  action,
  resource in Album::"alice_vacation"
)
when { principal.department == "Sales" };

// Deny all requests that have context.authenticated set to false
forbid (principal, action, resource)
unless { context.authenticated };

// Users with job level >= 7 can view any resource
permit (
  principal,
  action == Action::"view",
  resource
)
when { principal.jobLevel >= 7 };
