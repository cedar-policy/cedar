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

// Same example without comments
permit(
  principal is User,
  action == Action::"preview",
  resource == Movie::"Blockbuster"
) when {
  principal has 
  contactInfo.
  address.
  zip &&
  principal.contactInfo.address.zip == "90210"
};

// Same example with long attributes
permit(
  principal is User,
  action == Action::"preview",
  resource == Movie::"Blockbuster"
) when {
  principal has 
  contactInfooooooooooooooooooooooooooooooooooooooooooooooo.
  addressssssssssssssssssssss.
  zipppppppppppp &&
  principal.contactInfo.address.zip == "90210"
};