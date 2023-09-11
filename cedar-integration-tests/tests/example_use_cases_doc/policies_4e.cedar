// Scenario 4E: Anyone can view a Photo if the department attribute on the
// Principal equals the department attribute of the owner of the Photo
//
// (slightly adapted from the doc: in our sandbox_b, resources don't have
// .owner, but they do have .account.owner)
permit (
  principal,
  action == Action::"view",
  resource
)
when { principal.department == resource.account.owner.department };
