permit(
    principal,
    action,
    resource
) when {
    principal in resource.owner && resource has visibility && resource.visibility == "public"
};
