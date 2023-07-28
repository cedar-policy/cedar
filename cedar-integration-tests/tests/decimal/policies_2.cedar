permit(
    principal,
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
) when {
    context.confidence_score.greaterThanOrEqual(decimal("0.4")) && context.confidence_score.lessThanOrEqual(decimal("0.5"))
};
