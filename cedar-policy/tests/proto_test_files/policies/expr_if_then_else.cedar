permit(
    principal,
    action,
    resource
) when {
    (if context.admin then true else resource.public)
};
