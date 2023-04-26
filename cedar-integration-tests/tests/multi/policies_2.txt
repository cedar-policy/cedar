// This test has a Permit, and a Forbid that partially overrides it

// Anyone can view photos in jane's "Vacation" album
permit(
    principal,
    action == Action::"view",
    resource in Album::"jane_vacation"
);

// except bob
forbid(
    principal == User::"bob",
    action == Action::"view",
    resource in Album::"jane_vacation"
);
