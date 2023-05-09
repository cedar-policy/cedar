permit(
  principal,
  action in [Action::"action"],
  resource
) when {
  ((true && principal) && principal) && principal
};
