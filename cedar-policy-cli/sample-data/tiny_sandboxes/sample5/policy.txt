permit (
  principal == User::"bob",
  action == Action::"view",
  resource
)
when
{
  principal == resource.owner &&
  ip("127.0.0.1") == ip("127.0.0.1") &&
  principal.addr.isLoopback() &&
  ip("192.168.0.1").isInRange(ip("192.168.0.1/24")) &&
  [ip("127.0.0.1"), ip("127.0.0.2")].containsAny([principal.addr]) &&
  principal.addr == ip("127.0.0.1") &&
  principal.addr.isInRange(ip("127.0.0.1/28")) &&
  principal.addr.isIpv4() &&
  ip("224.0.0.0").isMulticast()
};
