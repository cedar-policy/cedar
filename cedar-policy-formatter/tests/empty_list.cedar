permit(principal, action, resource) when {
  principal.things == []
};

permit(principal, action, resource) when {
  principal.things == [
    // This is empty
  ]
};
