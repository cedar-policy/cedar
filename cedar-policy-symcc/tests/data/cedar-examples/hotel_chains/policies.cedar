// ==========================================
// Policies for particular property resource types
permit (
  principal,
  action in [Action::"viewReservation"],
  resource
)
when
{
  resource in principal.viewPermissions.hotelReservations ||
  resource in principal.viewPermissions.propertyReservations
};

// ... three similar policies but for Inventory, PaymentDetails, Rates
permit (
  principal,
  action in
    [Action::"viewReservation",
     Action::"updateReservation",
     Action::"createReservation"],
  resource
)
when
{
  resource in principal.memberPermissions.hotelReservations ||
  resource in principal.memberPermissions.propertyReservations
};

// ... three similar policies but for Inventory, PaymentDetails, Rates
permit (
  principal,
  action in
    [Action::"viewReservation",
     Action::"updateReservation",
     Action::"createReservation",
     Action::"grantAccessReservation"
    // ... other actions for all resource types
    ],
  resource
)
when
{
  resource in principal.hotelAdminPermissions ||
  resource in principal.propertyAdminPermissions
};

// ==========================================
// Policies for properties and hotels
permit (
  principal,
  action in [Action::"viewProperty", Action::"viewHotel"],
  resource
)
when
{
  resource in principal.viewPermissions.hotelReservations ||
  resource is Property &&
  resource in principal.viewPermissions.propertyReservations
// || resource in principal.viewPermissions.inventory ... for other resource types
};

permit (
  principal,
  action in
    [Action::"viewProperty",
     Action::"updateProperty",
     Action::"createProperty",
     Action::"viewHotel",
     Action::"updateHotel",
     Action::"createHotel"],
  resource
)
when
{
  resource in principal.memberPermissions.hotelReservations ||
  resource is Property &&
  resource in principal.memberPermissions.propertyReservations
// || resource in principal.memberPermissions.inventory ... for other resource types
};

permit (
  principal,
  action in
    [Action::"viewProperty",
     Action::"updateProperty",
     Action::"createProperty",
     Action::"grantAccessProperty",
     Action::"viewHotel",
     Action::"updateHotel",
     Action::"createHotel",
     Action::"grantAccessHotel"],
  resource
)
when
{
  resource in principal.hotelAdminPermissions ||
  resource is Property &&
  resource in principal.propertyAdminPermissions
};
