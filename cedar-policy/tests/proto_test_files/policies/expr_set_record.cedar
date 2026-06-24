permit(
    principal,
    action,
    resource
) when {
    [1, 2, 3].contains(context.level) &&
    [10, 20, 30].containsAll(context.scores) &&
    ["a", "b"].containsAny(context.tags)
};
