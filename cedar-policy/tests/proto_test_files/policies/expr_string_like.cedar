permit(
    principal,
    action,
    resource
) when {
    resource.name like "photo_*.jpg" && resource.path like "*/public/*"
};
