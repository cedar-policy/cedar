permit(
    principal,
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
) when {
    !(context.source_ip.isLoopback()) && !(context.source_ip.isMulticast())
};
