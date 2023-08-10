// Scenario 4D: Owners can perform any action over their own resources
//
// (slightly adapted from the doc: in our sandbox_b, resources don't have
// .owner, but they do have .account.owner)
// (but some resources, like Account itself, don't have .account, so we
// also added a `has` check)
permit (principal, action, resource)
when { resource has account && principal == resource.account.owner };
