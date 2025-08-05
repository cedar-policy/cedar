// PRESENTATION POLICIES
@id("external-prez-view")
permit (
  principal,
  action in Action::"ExternalPrezViewActions",
  resource
)
when { principal in resource.viewers };

@id("internal-prez-view")
permit (
  principal,
  action in Action::"InternalPrezViewActions",
  resource
)
when { principal.job == Job::"internal" && principal in resource.viewers };

// Authorizes edit actions generally, but these limited with forbid policies
@id("prez-edit")
permit (
  principal,
  action in Action::"PrezEditActions",
  resource
)
when { resource.owner == principal || principal in resource.editors };

// only permit sharing to non-customers
@id("limit-prez-view-customer")
forbid (
  principal,
  action == Action::"grantViewAccessToPresentation",
  resource
)
unless
{
  context.target.job != Job::"customer" ||
  (principal.job == Job::"distributor" &&
   principal.customerId == context.target.customerId)
};

// forbid sharing editor access to non-internal users
@id("limit-prez-edit-to-internal")
forbid (
  principal,
  action == Action::"grantEditAccessToPresentation",
  resource
)
when { context.target.job != Job::"internal" };

// TEMPLATE POLICIES
@id("market-template-view")
permit (
  principal,
  action in Action::"MarketTemplateViewActions",
  resource
)
when { principal in resource.viewerMarkets };

@id("internal-template-view")
permit (
  principal,
  action in Action::"InternalTemplateViewActions",
  resource
)
when { principal.job == Job::"internal" && principal in resource.viewers };

// Authorizes edit actions generally, but these limited with forbid policies
@id("template-edit")
permit (
  principal,
  action in Action::"TemplateEditActions",
  resource
)
when
{
  resource.owner == principal ||
  principal in resource.editors ||
  principal in resource.editorMarkets
};

// only permit sharing by internal users to non-customers
@id("limit-template-grant-view")
forbid (
  principal,
  action == Action::"grantViewAccessToTemplate",
  resource
)
when
{
  context has targetUser &&
  context.targetUser.job == Job::"customer" &&
  (principal.job != Job::"distributor" ||
   principal.customerId != context.targetUser.customerId)
};

// forbid sharing editor access to non-internal users
@id("limit-template-grant-edit-internal")
forbid (
  principal,
  action == Action::"grantEditAccessToTemplate",
  resource
)
when
{
  context has targetUser && context.targetUser.job != Job::"internal"
// context.targetMarket always Ok, no matter the market
};
