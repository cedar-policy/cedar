@id("Role-A policy")
permit (
  principal in Role::"Role-A",
  action in [Action::"Role-A Actions"],
  resource
)
when
{
  // match the production_status tag if present for this role
  principal.allowedTagsForRole has "Role-A" &&
  (if
     principal.allowedTagsForRole["Role-A"] has production_status
   then
     if
       resource.tags has production_status
     then
       principal.allowedTagsForRole
         [
         "Role-A"
         ]
         .production_status
         .contains
         (
           "ALL"
         ) ||
       resource.tags.production_status.contains("ALL") ||
       principal.allowedTagsForRole
         [
         "Role-A"
         ]
         .production_status
         .containsAll
         (
           resource.tags["production_status"]
         )
     else
       true
   else
     true)
}
when
{
  // match the country tag if present for this role
  principal.allowedTagsForRole has "Role-A" &&
  (if
     principal.allowedTagsForRole["Role-A"] has country
   then
     if
       resource.tags has country
     then
       principal.allowedTagsForRole["Role-A"].country.contains("ALL") ||
       resource.tags.country.contains("ALL") ||
       principal.allowedTagsForRole
         [
         "Role-A"
         ]
         .country
         .containsAll
         (
           resource.tags["country"]
         )
     else
       true
   else
     true)
}
when
{
  // match the stage tag if present for this role
  principal.allowedTagsForRole has "Role-A" &&
  (if
     principal.allowedTagsForRole["Role-A"] has stage
   then
     if
       resource.tags has stage
     then
       principal.allowedTagsForRole["Role-A"].stage.contains("ALL") ||
       resource.tags.stage.contains("ALL") ||
       principal.allowedTagsForRole
         [
         "Role-A"
         ]
         .stage
         .containsAll
         (
           resource.tags["stage"]
         )
     else
       true
   else
     true)
};

// Similar to the above policy, but for Role B
@id("Role-B policy")
permit (
  principal in Role::"Role-B",
  action in [Action::"Role-B Actions"],
  resource
)
when
{
  principal.allowedTagsForRole has "Role-B" &&
  (if
     principal.allowedTagsForRole["Role-B"] has production_status
   then
     if
       resource.tags has production_status
     then
       principal.allowedTagsForRole
         [
         "Role-B"
         ]
         .production_status
         .contains
         (
           "ALL"
         ) ||
       resource.tags.production_status.contains("ALL") ||
       principal.allowedTagsForRole
         [
         "Role-B"
         ]
         .production_status
         .containsAll
         (
           resource.tags["production_status"]
         )
     else
       true
   else
     true)
}
when
{
  principal.allowedTagsForRole has "Role-B" &&
  (if
     principal.allowedTagsForRole["Role-B"] has country
   then
     if
       resource.tags has country
     then
       principal.allowedTagsForRole["Role-B"].country.contains("ALL") ||
       resource.tags.country.contains("ALL") ||
       principal.allowedTagsForRole
         [
         "Role-B"
         ]
         .country
         .containsAll
         (
           resource.tags["country"]
         )
     else
       true
   else
     true)
}
when
{
  principal.allowedTagsForRole has "Role-B" &&
  (if
     principal.allowedTagsForRole["Role-B"] has stage
   then
     if
       resource.tags has stage
     then
       principal.allowedTagsForRole["Role-B"].stage.contains("ALL") ||
       resource.tags.stage.contains("ALL") ||
       principal.allowedTagsForRole
         [
         "Role-B"
         ]
         .stage
         .containsAll
         (
           resource.tags["stage"]
         )
     else
       true
   else
     true)
};
