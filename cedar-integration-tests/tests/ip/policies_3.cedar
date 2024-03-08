permit (
  principal,
  action == Action::"view",
  resource == Photo::"VacationPhoto94.jpg"
)
when { context.source_ip.isInRange(ip("222.222.222.0/24")) };
