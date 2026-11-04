// Delimiter-aware `like(pattern, delim)`.
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

// Comments on every token of `like(pattern, delim)`.
permit(principal, action, resource) when {
  context.host like //A
  ( //B
  "*.a" //C
  , //D
  "." //E
  ) //F
};
