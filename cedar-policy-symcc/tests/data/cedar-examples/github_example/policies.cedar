//Actions for readers
permit (
  principal,
  action == Action::"pull",
  resource
)
when { principal in resource.readers };

permit (
  principal,
  action == Action::"fork",
  resource
)
when { principal in resource.readers };

permit (
  principal,
  action == Action::"delete_issue",
  resource
)
when { principal in resource.repo.readers && principal == resource.reporter };

permit (
  principal,
  action == Action::"edit_issue",
  resource
)
when { principal in resource.repo.readers && principal == resource.reporter };

//Actions for triagers
permit (
  principal,
  action == Action::"assign_issue",
  resource
)
when { principal in resource.repo.triagers };

//Actions for writers
permit (
  principal,
  action == Action::"push",
  resource
)
when { principal in resource.writers };

permit (
  principal,
  action == Action::"edit_issue",
  resource
)
when { principal in resource.repo.writers };

//Actions for maintainers
permit (
  principal,
  action == Action::"delete_issue",
  resource
)
when { principal in resource.repo.maintainers };

//Actions for admins
permit (
  principal,
  action in
    [Action::"add_reader",
     Action::"add_triager",
     Action::"add_writer",
     Action::"add_maintainer",
     Action::"add_admin"],
  resource
)
when { principal in resource.admins };
//We use the same permissions for org owners, and rely on placing them in the admins group for every repository in the org
//The other option is to duplicate all policies for the org base permissions (with a separate heirarchy for each org)
