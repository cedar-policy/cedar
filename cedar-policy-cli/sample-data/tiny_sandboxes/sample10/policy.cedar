@id("too-hungry")
permit(principal, action == Action::"eat", resource)
when {
    principal.hungry_level >= resource.min_hungry_level
};

@id("not-too-hungry")
forbid(principal, action == Action::"eat", resource)
when {
    principal.hungry_level < 0 ||
    resource.min_hungry_level < 0 ||
    principal.hungry_level + resource.min_hungry_level >= 100
};
