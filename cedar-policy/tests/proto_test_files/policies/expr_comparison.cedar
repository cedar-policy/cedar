permit(
    principal,
    action,
    resource
) when {
    context.age > 18 && context.age <= 65 && context.score >= 0 && context.score < 100
};
