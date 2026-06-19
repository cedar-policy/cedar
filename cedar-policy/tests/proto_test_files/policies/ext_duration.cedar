permit(
    principal,
    action,
    resource
) when {
    duration("1d2h3m4s5ms").toMilliseconds() > 0 &&
    duration("1d2h3m4s5ms").toSeconds() > 0 &&
    duration("1d2h3m4s5ms").toMinutes() > 0 &&
    duration("1d2h3m4s5ms").toHours() > 0 &&
    duration("1d2h3m4s5ms").toDays() > 0
};
