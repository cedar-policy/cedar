permit(
    principal,
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
) when {
    context.source_ip == ip("222.222.222.222")
};
