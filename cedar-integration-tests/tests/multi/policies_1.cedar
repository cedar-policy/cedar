// This test has two Permit policies, and tests that we give the right Reason
// for each Allow
permit (
  principal == User::"alice",
  action == Action::"view",
  resource in Album::"jane_vacation"
);

permit (
  principal == User::"bob",
  action in [Action::"view", Action::"edit"],
  resource in Account::"bob"
);
