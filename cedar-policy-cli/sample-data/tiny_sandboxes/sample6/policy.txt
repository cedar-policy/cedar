permit (
  principal in UserGroup::"guardians",
  action in [Action::"view"],
  resource == ScreenTime::"activity"
)
when { principal.account.age >= 18 };
