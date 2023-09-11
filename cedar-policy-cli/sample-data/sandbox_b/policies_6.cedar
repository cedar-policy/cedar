// Alice's friends can view all of her photos
@id("alice's friends view policy")
permit (
  principal in UserGroup::"alice_friends",
  action == Action::"view",
  resource in Account::"alice"
);

// but forbid all requests coming from this IP range
@id("ip_denylist")
forbid (principal, action, resource)
when { context.source_ip.isInRange(ip("222.222.222.0/24")) };
