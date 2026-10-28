// Method names must stay attached to their argument lists (#2119)
permit(principal,action,resource) when {
  principal.loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong.toTime()
};

permit(principal,action,resource) when {
  context.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.contains(resource.cccccccccccccccccccccccccccccc)
};

permit(principal,action,resource) when {
  context.ip.isInRange(ip("10.0.0.0/8")).foooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo.isLoopback()
};

permit(principal,action,resource) when {
  context.loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong.lessThan // c1
  (decimal("1.0"))
};
