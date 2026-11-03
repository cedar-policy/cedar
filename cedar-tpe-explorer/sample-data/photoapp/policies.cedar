@id("admin_override")
permit (
  principal in PhotoApp::UserGroup::"admins",
  action == PhotoApp::Action::"view",
  resource
);

@id("allow same dept")
permit (principal, action == PhotoApp::Action::"view", resource)
when { principal.meta.dept == resource.owner_dept };

@id("private requires mfa")
forbid (principal, action == PhotoApp::Action::"view", resource)
when { resource.private && !(context.authn_method == "mfa") };
