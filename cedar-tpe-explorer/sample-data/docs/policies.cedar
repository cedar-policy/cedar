@id("owner can do anything")
permit (principal, action, resource)
when { resource.owner == principal };

@id("team folder")
permit (principal in Docs::Team::"eng", action == Docs::Action::"read", resource in Docs::Folder::"eng-shared");

@id("senior verified editors")
permit (principal, action == Docs::Action::"edit", resource)
when { principal.level >= 5 && principal has profile && principal.profile has verified && principal.profile.verified }
unless { resource.labels.contains("locked") };

@id("drafts by title")
permit (principal, action == Docs::Action::"read", resource)
when { resource.title like "draft-*" && principal.hasTag("reviewer") && principal.getTag("reviewer") == "yes" };

@id("corp network only")
forbid (principal, action, resource)
unless { context.ip.isInRange(ip("10.0.0.0/8")) || (context has mfa && context.mfa) };
