permit (
  principal == PhotoFlash::Data::User::"alice",
  action == PhotoFlash::Data::Action::"view",
  resource in PhotoFlash::Data::Album::"jane_vacation"
)
when
{
  context.role.contains("admin") &&
  context.person.age > 17 &&
  context.addr.city == "DC" ||
  context.addr == {city:"DC", street:"main"}
};
