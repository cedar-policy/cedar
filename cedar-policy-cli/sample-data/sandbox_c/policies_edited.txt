// Template for permitting vacation photo access
@id("AccessVacation")
permit (
  principal in ?principal,
  action == Action::"view",
  resource == Photo::"VacationPhoto94.jpg"
)
when { principal has department && principal.department == "research" };
