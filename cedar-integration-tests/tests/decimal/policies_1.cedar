permit(
    principal,
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
) when {
    context.confidence_score.greaterThan(decimal("0.75"))
};
