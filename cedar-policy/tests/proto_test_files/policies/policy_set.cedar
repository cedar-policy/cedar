@id("ip-restrict")
@advice("check source IP")
forbid(
    principal is App::Org::User,
    action in [Action::"read", Action::"write"],
    resource
) when {
    !context.src_ip.isInRange(ip("10.0.0.0/8"))
};

@id("owner-edit")
permit(
    principal,
    action == Action::"write",
    resource in App::Org::Folder::"root"
) when {
    resource.owner == principal && context.authenticated
} unless {
    principal.suspended
};

@id("public-read")
permit(
    principal,
    action == Action::"read",
    resource
) when {
    resource.public
};
