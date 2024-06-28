permit(principal, action, resource) when {
  principal["is_admin"]
};

permit(principal, action, resource) when {
  principal["roles"]["admin"]
};

permit(principal, action, resource) when {
  principal // principal
    ["roles"] // get roles
    ["admin"] // get the admin role
};
