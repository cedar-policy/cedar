// Rule 1a: organization-level access
permit (
  principal,
  action == Taxpreparer::Action::"viewDocument",
  resource
)
when
{
  principal.assigned_orgs
    .contains
    (
      {organization
       :resource.owner.organization,
       serviceline
       :resource.serviceline,
       location
       :resource.location}
    )
};

// Rule 1b: ad hoc access (per linked template)
@id("adhoc-access")
permit (
  principal == ?principal,
  action == Taxpreparer::Action::"viewDocument",
  resource == ?resource
);

// Rule 2: consent must be given by a document's owner
forbid (
  principal,
  action == Taxpreparer::Action::"viewDocument",
  resource
)
unless
{
  context.consent.client == resource.owner &&
  context.consent.team_region_list.contains(principal.location)
};
