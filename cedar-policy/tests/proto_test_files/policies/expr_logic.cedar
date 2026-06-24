permit(
    principal,
    action,
    resource
) when {
    (context.a || context.b) && !context.c
};
