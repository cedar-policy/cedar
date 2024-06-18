forbid(principal, action, resource) when {
  principal.tags == {}
};

forbid(principal, action, resource) when {
  principal.tags == { // This
    // is
    // empty
  }
};
