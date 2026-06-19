permit(
    principal,
    action,
    resource
) when {
    decimal("1.23").lessThan(decimal("4.56")) &&
    decimal("1.23").lessThanOrEqual(decimal("1.23")) &&
    decimal("9.99").greaterThan(decimal("0.01")) &&
    decimal("5.00").greaterThanOrEqual(decimal("5.00"))
};
