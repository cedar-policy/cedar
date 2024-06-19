permit(principal, action, resource) when {
  (principal.widgets + principal.gadgets) < resource.limit
};

permit(principal, action, resource) when {
  (principal.widgets - principal.gadgets) == principal.fidgets
};

permit(principal, action, resource) when {
  (principal.widgets * 2) < resource.limit
};

permit(principal, action, resource) when {
  - principal.negative_age > resource.min_age
};
