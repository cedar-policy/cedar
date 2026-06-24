forbid(
    principal,
    action,
    resource
) unless {
    context.allowed
};
