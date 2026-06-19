permit(
    principal,
    action,
    resource
) when {
    datetime("2024-01-01").offset(duration("1d")).durationSince(datetime("2024-01-01")).toMilliseconds() > 0 &&
    datetime("2024-06-15T12:00:00Z").toDate() == datetime("2024-06-15") &&
    datetime("2024-06-15T12:30:00Z").toTime() == duration("12h30m")
};
