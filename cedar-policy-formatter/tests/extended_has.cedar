// An example from RFC
permit(
  principal is User,
  action == Action::"preview",
  resource == Movie::"Blockbuster"
) when {
    // extended has
  principal has 
  // contactInfo
  contactInfo.
  // address
  address.
  // zip
  zip &&
  // we are safe to access all attributes
  principal.contactInfo.address.zip == "90210"
};