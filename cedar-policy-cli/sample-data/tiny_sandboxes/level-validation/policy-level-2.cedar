@id("attr-access")
permit (principal, action, resource)
when { principal.manager in Group::"admins" };
