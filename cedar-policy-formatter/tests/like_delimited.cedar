// Delimiter-aware `like(pattern, delim)` from RFC #115.
permit(principal, action, resource) when {
  context.host like("*.example.com", ".")
};

// Path pattern with `/` delimiter.
permit(principal, action, resource) when {
  context.path like("/repos/*/pulls/*/reviews", "/")
};

// `**` (multi-wildcard) crosses the delimiter.
permit(principal, action, resource) when {
  context.host like("**.example.com", ".")
};
