permit (
  principal == User::"bob",
  action == Action::"view",
  resource
)
when
{
  principal == resource.owner &&
  principal.score.greaterThanOrEqual(decimal("0.75"))
};
