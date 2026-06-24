permit(
    principal,
    action,
    resource
) when {
    principal is User && resource is Folder in Account::"main"
};
