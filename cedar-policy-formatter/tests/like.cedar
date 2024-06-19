permit(principal, action, resource) when {
  resource.path like "/home/*"
};

permit(principal, action, resource) when {
  resource.path // Checking path
  like
  // is `home`
  "/home/*"
};
