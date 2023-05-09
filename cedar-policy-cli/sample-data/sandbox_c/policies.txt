// Template for permitting vacation photo access
@id("AccessVacation")
permit (
  principal in ?principal,
  action == Action::"view",
  resource == Photo::"VacationPhoto94.jpg"
);
