forbid(
    principal,
    action,
    resource
) when {
    !context.src_ip.isIpv4() ||
    context.src_ip.isIpv6() ||
    context.src_ip.isLoopback() ||
    context.src_ip.isMulticast() ||
    context.src_ip.isInRange(ip("10.0.0.0/8"))
};
